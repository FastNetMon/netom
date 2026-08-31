//! A minimal blocking HTTP/1.1 GET client.
//!
//! netom's API is deliberately narrow: GET only, plain HTTP, no auth, no
//! redirects, no cookies. That makes a purpose-built client smaller than the
//! configuration a general-purpose one would need, and it avoids pulling
//! hyper/tower into release builds of the daemon.
//!
//! It also buys something a general-purpose client cannot give us. Full-table
//! dumps are streamed as NDJSON, which has no terminator, and the daemon
//! aborts a dump whose client stalls for 60s. A truncated dump is therefore
//! indistinguishable from a complete one *unless* you can see that the
//! chunked stream ended without its terminal zero-length chunk. Owning the
//! framing lets [`Response::truncated`] report exactly that.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::error::CliError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Client {
    /// Addresses to try, in order.
    addrs: Vec<SocketAddr>,
    /// Where those addresses came from, for the error message. The single
    /// most common support question is "which endpoint did it even try?".
    provenance: String,
    read_timeout: Duration,
}

impl Client {
    pub fn new(
        addrs: Vec<SocketAddr>,
        provenance: String,
        read_timeout: Duration,
    ) -> Self {
        Self {
            addrs,
            provenance,
            read_timeout,
        }
    }

    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// GET `path`, returning the response with its body unread.
    pub fn get(&self, path: &str) -> Result<Response<TcpStream>, CliError> {
        let mut last_err = None;
        for addr in &self.addrs {
            match self.get_from(*addr, path) {
                Ok(resp) => return Ok(resp),
                Err(e) => last_err = Some(e),
            }
        }

        let list = self
            .addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let detail = last_err
            .map(|e| format!(": {e}"))
            .unwrap_or_else(|| " (no addresses to try)".into());
        Err(CliError::Transport(format!(
            "Unable to connect to netom at {list}{detail}\n%   ({})",
            self.provenance,
        )))
    }

    fn get_from(
        &self,
        addr: SocketAddr,
        path: &str,
    ) -> Result<Response<TcpStream>, io::Error> {
        let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
        stream.set_read_timeout(Some(self.read_timeout))?;
        stream.set_write_timeout(Some(self.read_timeout))?;
        let mut stream = stream;

        // `SocketAddr`'s Display brackets IPv6 literals, which is exactly
        // what a Host header needs.
        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {addr}\r\n\
             User-Agent: netom-cli/{}\r\n\
             Accept-Encoding: identity\r\n\
             Connection: close\r\n\
             \r\n",
            env!("CARGO_PKG_VERSION"),
        );
        stream.write_all(request.as_bytes())?;
        stream.flush()?;

        Response::read(BufReader::new(stream))
    }
}

/// How the body length is framed.
#[derive(Debug, PartialEq, Eq)]
enum Framing {
    Chunked,
    Length(usize),
    /// Read until EOF. Truncation is undetectable here, by definition.
    Eof,
}

/// A response with its body still unread.
///
/// Generic over the reader so the framing logic can be tested against an
/// in-memory buffer rather than a live socket.
pub struct Response<R: Read> {
    pub status: u16,
    pub content_type: String,
    reader: BufReader<R>,
    framing: Framing,
    /// Bytes still to read of the current chunk, or of the whole body.
    remaining: usize,
    /// Whether any chunk header has been consumed yet.
    seen_chunk: bool,
    done: bool,
    truncated: bool,
}

impl<R: Read> Response<R> {
    fn read(mut reader: BufReader<R>) -> Result<Self, io::Error> {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let status = parse_status_line(&line).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("malformed status line: {:?}", line.trim()),
            )
        })?;

        let mut content_type = String::new();
        let mut framing = Framing::Eof;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed in headers",
                ));
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            let Some((name, value)) = header.split_once(':') else {
                continue;
            };
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-type") {
                content_type = value.to_string();
            } else if name.eq_ignore_ascii_case("transfer-encoding")
                && value.eq_ignore_ascii_case("chunked")
            {
                framing = Framing::Chunked;
            } else if name.eq_ignore_ascii_case("content-length") {
                // Transfer-Encoding wins over Content-Length (RFC 9112 §6.3).
                if let (Ok(len), false) =
                    (value.parse(), framing == Framing::Chunked)
                {
                    framing = Framing::Length(len);
                }
            }
        }

        let remaining = match framing {
            Framing::Length(n) => n,
            _ => 0,
        };
        Ok(Response {
            status,
            content_type,
            reader,
            framing,
            remaining,
            seen_chunk: false,
            done: false,
            truncated: false,
        })
    }

    /// True once the body ended before its framing said it should — the
    /// signature of a dump the daemon abandoned.
    ///
    /// Only meaningful after the body has been read to completion, and only
    /// detectable for chunked and Content-Length responses.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn body_string(&mut self) -> Result<String, CliError> {
        let mut buf = String::new();
        self.read_to_string(&mut buf)?;
        Ok(buf)
    }

    fn read_chunked(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            // Between chunks: consume the CRLF closing the previous one,
            // then read the next chunk header.
            if self.seen_chunk {
                let mut crlf = String::new();
                if self.reader.read_line(&mut crlf)? == 0 {
                    self.done = true;
                    self.truncated = true;
                    return Ok(0);
                }
            }

            let mut header = String::new();
            if self.reader.read_line(&mut header)? == 0 {
                // Stream stopped without the terminating zero chunk: the
                // aborted-dump case this decoder exists to catch.
                self.done = true;
                self.truncated = true;
                return Ok(0);
            }
            self.seen_chunk = true;

            // A chunk header may carry `;ext=value` extensions.
            let size_hex =
                header.trim().split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_hex, 16).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("malformed chunk size: {size_hex:?}"),
                )
            })?;

            if size == 0 {
                // Terminal chunk: a clean, complete body.
                self.done = true;
                return Ok(0);
            }
            self.remaining = size;
        }

        let cap = out.len().min(self.remaining);
        let n = self.reader.read(&mut out[..cap])?;
        if n == 0 {
            self.done = true;
            self.truncated = true;
            return Ok(0);
        }
        self.remaining -= n;
        Ok(n)
    }
}

impl<R: Read> Read for Response<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.done || out.is_empty() {
            return Ok(0);
        }
        match self.framing {
            Framing::Eof => {
                let n = self.reader.read(out)?;
                if n == 0 {
                    self.done = true;
                }
                Ok(n)
            }
            Framing::Length(_) => {
                if self.remaining == 0 {
                    self.done = true;
                    return Ok(0);
                }
                let cap = out.len().min(self.remaining);
                let n = self.reader.read(&mut out[..cap])?;
                if n == 0 {
                    // Fewer bytes than Content-Length promised.
                    self.done = true;
                    self.truncated = true;
                    return Ok(0);
                }
                self.remaining -= n;
                Ok(n)
            }
            Framing::Chunked => self.read_chunked(out),
        }
    }
}

fn parse_status_line(line: &str) -> Option<u16> {
    let mut parts = line.split_whitespace();
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(raw: &str) -> Response<Cursor<Vec<u8>>> {
        Response::read(BufReader::new(Cursor::new(raw.as_bytes().to_vec())))
            .expect("response should parse")
    }

    #[test]
    fn parses_status_lines() {
        assert_eq!(parse_status_line("HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status_line("HTTP/1.0 503 \r\n"), Some(503));
        assert_eq!(parse_status_line("garbage"), None);
        assert_eq!(parse_status_line(""), None);
    }

    #[test]
    fn reads_a_content_length_body() {
        let mut r = parse(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 13\r\n\
             \r\n\
             {\"data\":null}",
        );
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type, "application/json");
        assert_eq!(r.body_string().unwrap(), "{\"data\":null}");
        assert!(!r.truncated());
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let mut r = parse(
            "HTTP/1.1 200 OK\r\n\
             CONTENT-TYPE: application/x-ndjson\r\n\
             content-length: 2\r\n\
             \r\n\
             hi",
        );
        assert_eq!(r.content_type, "application/x-ndjson");
        assert_eq!(r.body_string().unwrap(), "hi");
    }

    #[test]
    fn reads_a_chunked_body_across_several_chunks() {
        let mut r = parse(
            "HTTP/1.1 200 OK\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             5\r\nhello\r\n\
             6\r\n world\r\n\
             0\r\n\r\n",
        );
        assert_eq!(r.body_string().unwrap(), "hello world");
        assert!(!r.truncated());
    }

    #[test]
    fn honours_chunk_extensions() {
        let mut r = parse(
            "HTTP/1.1 200 OK\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             5;ext=value\r\nhello\r\n\
             0\r\n\r\n",
        );
        assert_eq!(r.body_string().unwrap(), "hello");
        assert!(!r.truncated());
    }

    /// The whole reason for owning the framing: an NDJSON dump the daemon
    /// abandoned must not look like a complete one.
    #[test]
    fn detects_a_dump_that_ended_without_its_terminal_chunk() {
        let mut r = parse(
            "HTTP/1.1 200 OK\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             5\r\nhello\r\n",
        );
        // The data that did arrive is still returned...
        assert_eq!(r.body_string().unwrap(), "hello");
        // ...but the caller can tell it is incomplete.
        assert!(r.truncated(), "premature EOF must be reported");
    }

    #[test]
    fn detects_a_chunk_cut_off_mid_body() {
        let mut r = parse(
            "HTTP/1.1 200 OK\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             20\r\nonly-a-few-bytes",
        );
        let _ = r.body_string().unwrap();
        assert!(r.truncated());
    }

    #[test]
    fn detects_a_short_content_length_body() {
        let mut r = parse(
            "HTTP/1.1 200 OK\r\n\
             Content-Length: 100\r\n\
             \r\n\
             short",
        );
        assert_eq!(r.body_string().unwrap(), "short");
        assert!(r.truncated());
    }

    #[test]
    fn transfer_encoding_wins_over_content_length() {
        let mut r = parse(
            "HTTP/1.1 200 OK\r\n\
             Content-Length: 999\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             2\r\nok\r\n\
             0\r\n\r\n",
        );
        assert_eq!(r.body_string().unwrap(), "ok");
        assert!(!r.truncated());
    }

    #[test]
    fn reads_bodies_that_end_at_eof() {
        let mut r = parse(
            "HTTP/1.1 200 OK\r\n\
             \r\n\
             body without framing",
        );
        assert_eq!(r.body_string().unwrap(), "body without framing");
    }

    #[test]
    fn surfaces_error_status_with_its_body() {
        let mut r = parse(
            "HTTP/1.1 503 Service Unavailable\r\n\
             Content-Length: 39\r\n\
             \r\n\
             {\"data\":null,\"error\":\"store unavail\"}\r\n",
        );
        assert_eq!(r.status, 503);
        assert!(r.body_string().unwrap().contains("store unavail"));
    }
}
