use anyhow::{Result, bail, ensure};
use std::collections::HashMap;

const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const MAX_BUFFER: usize = 8 * 1024 * 1024;

fn delta(seq: u32, reference: u32) -> i64 {
    i64::from(seq.wrapping_sub(reference) as i32)
}

pub struct Stream {
    next_seq: Option<u32>,
    pending: HashMap<u32, Vec<u8>>,
    buffer: Vec<u8>,
    synchronized: bool,
    pub skipped: usize,
    pub syn_seq: Option<u32>,
}

impl Stream {
    pub fn new(initial_seq: Option<u32>) -> Self {
        Self {
            next_seq: initial_seq,
            pending: HashMap::new(),
            buffer: Vec::new(),
            synchronized: initial_seq.is_some(),
            skipped: 0,
            syn_seq: None,
        }
    }
    pub fn buffered(&self) -> usize {
        self.buffer.len() + self.pending.values().map(Vec::len).sum::<usize>()
    }
    pub fn feed(
        &mut self,
        mut seq: u32,
        mut payload: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        if payload.is_empty() {
            return Ok(vec![]);
        }
        let mut next = *self.next_seq.get_or_insert(seq);
        let offset = delta(seq, next);
        if offset < 0 {
            payload = &payload[(-offset as usize).min(payload.len())..];
            seq = next;
        }
        if payload.is_empty() {
            return Ok(vec![]);
        }
        if let Some(old) = self.pending.get(&seq) {
            let common = old.len().min(payload.len());
            ensure!(
                old[..common] == payload[..common],
                "conflicting TCP retransmission"
            );
            if old.len() >= payload.len() {
                return Ok(vec![]);
            }
        }
        self.pending.insert(seq, payload.to_vec());
        ensure!(
            self.buffered() <= MAX_BUFFER && self.pending.len() <= 8192,
            "TCP stream buffer limit exceeded (possibly a capture gap)"
        );
        while let Some(first) = self
            .pending
            .keys()
            .min_by_key(|n| delta(**n, next))
            .copied()
        {
            let offset = delta(first, next);
            if offset > 0 {
                break;
            }
            let chunk = self.pending.remove(&first).unwrap();
            let chunk = &chunk[(-offset as usize).min(chunk.len())..];
            self.buffer.extend_from_slice(chunk);
            next = next.wrapping_add(chunk.len() as u32);
        }
        self.next_seq = Some(next);
        let mut messages = Vec::new();
        let mut pos = 0;
        while self.buffer.len() - pos >= 6 {
            let version = self.buffer[pos];
            let length = u32::from_be_bytes(
                self.buffer[pos + 1..pos + 5].try_into().unwrap(),
            ) as usize;
            let kind = self.buffer[pos + 5];
            let minimum = match kind {
                0 => 67,
                1 => 52,
                2 => 49,
                3 => 126,
                6 => 48,
                _ => 6,
            };
            if version != 3 || !(minimum..=MAX_MESSAGE).contains(&length) {
                if self.synchronized {
                    bail!(
                        "invalid BMP header: version={version} length={length} type={kind}"
                    );
                }
                pos += 1;
                self.skipped += 1;
                continue;
            }
            if self.buffer.len() - pos < length {
                break;
            }
            self.synchronized = true;
            messages.push(self.buffer[pos..pos + length].to_vec());
            pos += length;
        }
        self.buffer.drain(..pos);
        Ok(messages)
    }
    pub fn unfinished(&self) -> Option<String> {
        if !self.pending.is_empty() {
            Some(format!(
                "TCP gap: {} bytes remain undecoded",
                self.buffered()
            ))
        } else if !self.buffer.is_empty() {
            Some(format!(
                "incomplete BMP message: {} trailing bytes",
                self.buffer.len()
            ))
        } else {
            None
        }
    }
}
