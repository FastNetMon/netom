//! Immutable insert units. Each independently compressed frame ends on a row
//! boundary. Only unattempted `.open` tails may be truncated during recovery.
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
};

const MAGIC: &[u8; 8] = b"NETOMCH1";
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
const FRAME_HEADER: usize = 44;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

pub struct Spool {
    pub dir: PathBuf,
    pub stream: [u8; 16],
    _lock: File,
}

impl Spool {
    /// Bind a spool permanently to a destination/schema. Never silently replay
    /// old observations into a newly configured database or table.
    pub fn open(dir: &Path, destination: &str) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join("lock"))?;
        lock.try_lock_exclusive()?;
        let manifest = dir.join("manifest");
        let stream = if manifest.exists() {
            let bytes = fs::read(&manifest)?;
            if bytes.len() < 48
                || bytes[16..bytes.len() - 32] != *destination.as_bytes()
                || Sha256::digest(&bytes[..bytes.len() - 32])[..]
                    != bytes[bytes.len() - 32..]
            {
                return Err(invalid("spool destination/schema differs; use its original configuration"));
            }
            bytes[..16].try_into().unwrap()
        } else {
            // A crash before manifest rename may leave this uncommitted file.
            let mut file = File::create(dir.join("manifest.tmp"))?;
            let stream = *uuid::Uuid::new_v4().as_bytes();
            file.write_all(&stream)?;
            file.write_all(destination.as_bytes())?;
            let mut checksum = Sha256::new();
            checksum.update(stream);
            checksum.update(destination.as_bytes());
            file.write_all(&checksum.finalize())?;
            file.sync_all()?;
            fs::rename(dir.join("manifest.tmp"), &manifest)?;
            sync_dir(dir)?;
            stream
        };
        let spool = Self {
            dir: dir.to_owned(),
            stream,
            _lock: lock,
        };
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|v| v == "open") {
                recover(&path)?;
            }
        }
        Ok(spool)
    }
}

pub fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

pub fn pending(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for e in fs::read_dir(dir)? {
        let path = e?.path();
        if path.extension().is_some_and(|v| v == "ready") {
            files.push(path);
        }
        if files.len() > 100_000 {
            return Err(invalid("too many spool segments (limit 100000)"));
        }
    }
    files.sort_unstable();
    Ok(files)
}

pub fn usage(dir: &Path) -> io::Result<u64> {
    let mut bytes = 0u64;
    for e in fs::read_dir(dir)? {
        match e?.metadata() {
            Ok(m) => bytes = bytes.saturating_add(m.len()),
            // Concurrent uploader unlink or writer rename.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(bytes)
}

pub struct Segment {
    path: PathBuf,
    file: File,
    hash: Sha256,
    pub rows: u32,
    pub raw_bytes: u64,
}
impl Segment {
    pub fn create(dir: &Path) -> io::Result<Self> {
        let id = uuid::Uuid::new_v4();
        let name = format!(
            "{:020}-{}.open",
            chrono::Utc::now().timestamp_micros(),
            id.simple()
        );
        let path = dir.join(name);
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        file.write_all(MAGIC)?;
        file.write_all(id.as_bytes())?;
        file.sync_all()?;
        sync_dir(dir)?;
        let mut hash = Sha256::new();
        hash.update(MAGIC);
        hash.update(id.as_bytes());
        Ok(Self {
            path,
            file,
            hash,
            rows: 0,
            raw_bytes: 0,
        })
    }

    pub fn append(&mut self, bytes: &[u8], rows: u32) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME || rows == 0 {
            return Err(invalid("invalid spool frame size/row count"));
        }
        let compressed = lz4_flex::block::compress(bytes);
        let mut frame = Vec::with_capacity(FRAME_HEADER + compressed.len());
        frame.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        frame.extend_from_slice(&rows.to_le_bytes());
        let checksum = Sha256::digest(bytes);
        frame.extend_from_slice(&checksum);
        frame.extend_from_slice(&compressed);
        let offset = self.file.stream_position()?;
        if let Err(err) = self.file.write_all(&frame) {
            // No attempt was sent. Roll back partial writes before retrying.
            self.file.set_len(offset)?;
            self.file.seek(io::SeekFrom::Start(offset))?;
            return Err(err);
        }
        self.hash.update(&frame[..FRAME_HEADER]);
        self.rows = self
            .rows
            .checked_add(rows)
            .ok_or_else(|| invalid("segment row count overflow"))?;
        self.raw_bytes += bytes.len() as u64;
        Ok(())
    }
    pub fn sync(&self) -> io::Result<()> {
        self.file.sync_data()
    }

    pub fn seal(mut self) -> io::Result<PathBuf> {
        let mut footer = [0u8; FRAME_HEADER];
        footer[8..12].copy_from_slice(&self.rows.to_le_bytes());
        footer[12..].copy_from_slice(&self.hash.finalize());
        self.file.write_all(&footer)?;
        self.file.sync_all()?;
        let ready = self.path.with_extension("ready");
        fs::rename(&self.path, &ready)?;
        sync_dir(self.path.parent().unwrap())?;
        Ok(ready)
    }
}

/// Returns token, complete rows, last complete offset and whether a footer was
/// present. In recovery mode, only an incomplete final header/body is tolerated.
fn scan(
    path: &Path,
    recovery: bool,
    mut emit: impl FnMut(Vec<u8>) -> io::Result<()>,
) -> io::Result<([u8; 16], u32, u64, Option<Sha256>)> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 24];
    file.read_exact(&mut header)?;
    if &header[..8] != MAGIC {
        return Err(invalid("unknown spool format"));
    }
    let token = header[8..].try_into().unwrap();
    let mut hash = Sha256::new();
    hash.update(header);
    let mut rows = 0u32;
    let mut offset = 24;
    loop {
        let mut h = [0u8; FRAME_HEADER];
        if let Err(e) = file.read_exact(&mut h) {
            if recovery && e.kind() == io::ErrorKind::UnexpectedEof {
                return Ok((token, rows, offset, Some(hash)));
            }
            return Err(e);
        }
        let compressed_len =
            u32::from_le_bytes(h[..4].try_into().unwrap()) as usize;
        let raw_len =
            u32::from_le_bytes(h[4..8].try_into().unwrap()) as usize;
        let n = u32::from_le_bytes(h[8..12].try_into().unwrap());
        if compressed_len == 0 && raw_len == 0 {
            if n != rows || h[12..] != hash.clone().finalize()[..] {
                return Err(invalid("spool footer checksum/count mismatch"));
            }
            let mut extra = [0];
            if file.read(&mut extra)? != 0 {
                return Err(invalid("bytes after spool footer"));
            }
            return Ok((token, rows, offset, None));
        }
        if raw_len == 0
            || raw_len > MAX_FRAME
            || compressed_len > MAX_FRAME + MAX_FRAME / 255 + 16
            || n == 0
        {
            return Err(invalid("invalid spool frame bounds"));
        }
        let mut compressed = vec![0u8; compressed_len];
        if let Err(e) = file.read_exact(&mut compressed) {
            if recovery && e.kind() == io::ErrorKind::UnexpectedEof {
                return Ok((token, rows, offset, Some(hash)));
            }
            return Err(e);
        }
        let raw = lz4_flex::block::decompress(&compressed, raw_len)
            .map_err(|_| invalid("invalid LZ4 frame"))?;
        if raw.len() != raw_len || Sha256::digest(&raw)[..] != h[12..] {
            return Err(invalid("spool payload checksum mismatch"));
        }
        hash.update(h);
        rows = rows
            .checked_add(n)
            .ok_or_else(|| invalid("spool row count overflow"))?;
        offset += (FRAME_HEADER + compressed_len) as u64;
        emit(raw)?;
    }
}

pub fn validate(path: &Path) -> io::Result<(String, u32)> {
    let (token, rows, _, _) = scan(path, false, |_| Ok(()))?;
    Ok((uuid::Uuid::from_bytes(token).simple().to_string(), rows))
}
pub fn replay(
    path: &Path,
    emit: impl FnMut(Vec<u8>) -> io::Result<()>,
) -> io::Result<()> {
    scan(path, false, emit).map(|_| ())
}

fn recover(path: &Path) -> io::Result<()> {
    // A crash while initially creating a segment cannot lose any accepted rows.
    if fs::metadata(path)?.len() < 24 {
        fs::remove_file(path)?;
        return sync_dir(path.parent().unwrap());
    }
    let (_, rows, offset, hash) = scan(path, true, |_| Ok(()))?;
    if let Some(hash) = hash {
        let mut file =
            OpenOptions::new().read(true).write(true).open(path)?;
        file.set_len(offset)?;
        file.seek(io::SeekFrom::Start(offset))?;
        let segment = Segment {
            path: path.to_owned(),
            file,
            hash,
            rows,
            raw_bytes: 0,
        };
        segment.seal()?;
    } else {
        fs::rename(path, path.with_extension("ready"))?;
        sync_dir(path.parent().unwrap())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dir() -> PathBuf {
        let p = std::env::temp_dir()
            .join(format!("netom-ch-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&p).unwrap();
        p
    }
    #[test]
    fn crash_recovery_and_replay_preserve_bytes_and_token() {
        let dir = dir();
        let spool = Spool::open(&dir, "test").unwrap();
        let stream = spool.stream;
        assert!(Spool::open(&dir, "test").is_err(), "exclusive process lock");
        let mut s = Segment::create(&dir).unwrap();
        s.append(&[42; 1000], 3).unwrap();
        s.sync().unwrap();
        s.file.write_all(&[20, 0, 0]).unwrap();
        drop(s);
        drop(spool);
        let spool = Spool::open(&dir, "test").unwrap();
        assert_eq!(stream, spool.stream);
        let paths = pending(&dir).unwrap();
        assert_eq!(paths.len(), 1);
        let first = validate(&paths[0]).unwrap();
        assert_eq!(first.1, 3);
        let mut bytes = Vec::new();
        replay(&paths[0], |b| {
            bytes.extend(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(bytes, [42; 1000]);
        drop(spool);
        assert!(Spool::open(&dir, "other destination").is_err());
        let _spool = Spool::open(&dir, "test").unwrap();
        assert_eq!(validate(&paths[0]).unwrap(), first);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn corruption_of_attemptable_segment_is_never_repaired() {
        let dir = dir();
        let mut s = Segment::create(&dir).unwrap();
        s.append(b"binary\0\xff", 1).unwrap();
        let p = s.seal().unwrap();
        let mut bytes = fs::read(&p).unwrap();
        bytes[36] ^= 1;
        fs::write(&p, &bytes).unwrap();
        assert!(validate(&p).is_err());
        let _spool = Spool::open(&dir, "test").unwrap();
        assert_eq!(fs::read(p).unwrap(), bytes);
        fs::remove_dir_all(dir).unwrap();
    }
}
