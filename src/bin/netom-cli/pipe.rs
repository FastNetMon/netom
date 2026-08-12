//! Cisco-style output filters (`| include`, `| exclude`, `| begin`,
//! `| count`).
//!
//! Implemented as a line-buffering [`Write`] wrapper so it composes with
//! every renderer and with raw `--json` passthrough alike, without any of
//! them knowing it exists.
//!
//! Matching is case-insensitive substring, not regex. That keeps `regex`
//! out of release builds, and covers what operators actually reach for.

use std::io::{self, Write};

use crate::lex::{Pipe, PipeOp};

pub struct LineFilter<W: Write> {
    inner: W,
    pipe: Pipe,
    pattern_lower: String,
    /// Partial trailing line not yet terminated by a newline.
    buf: Vec<u8>,
    /// `begin` has fired and everything from here on passes.
    begun: bool,
    count: u64,
}

impl<W: Write> LineFilter<W> {
    pub fn new(inner: W, pipe: Pipe) -> Self {
        let pattern_lower = pipe.pattern.to_lowercase();
        Self {
            inner,
            pipe,
            pattern_lower,
            buf: Vec::new(),
            begun: false,
            count: 0,
        }
    }

    fn keep(&mut self, line: &str) -> bool {
        let lower = line.to_lowercase();
        let hit = lower.contains(&self.pattern_lower);
        match self.pipe.op {
            PipeOp::Include => hit,
            PipeOp::Exclude => !hit,
            PipeOp::Begin => {
                if !self.begun && hit {
                    self.begun = true;
                }
                self.begun
            }
            PipeOp::Count => {
                self.count += 1;
                false
            }
        }
    }

    fn emit_line(&mut self, line: &[u8]) -> io::Result<()> {
        let text = String::from_utf8_lossy(line).to_string();
        if self.keep(&text) {
            self.inner.write_all(line)?;
            self.inner.write_all(b"\n")?;
        }
        Ok(())
    }

    /// Flush any partial line and, for `| count`, emit the tally.
    pub fn finish(mut self) -> io::Result<W> {
        if !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            self.emit_line(&line)?;
        }
        if self.pipe.op == PipeOp::Count {
            writeln!(self.inner, "Number of lines which match: {}", self.count)?;
        }
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for LineFilter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        for &byte in data {
            if byte == b'\n' {
                let line = std::mem::take(&mut self.buf);
                self.emit_line(&line)?;
            } else {
                self.buf.push(byte);
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(op: PipeOp, pattern: &str, input: &str) -> String {
        let pipe = Pipe {
            op,
            pattern: pattern.to_string(),
        };
        let mut f = LineFilter::new(Vec::new(), pipe);
        f.write_all(input.as_bytes()).unwrap();
        let out = f.finish().unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn include_keeps_only_matching_lines() {
        let out = run(PipeOp::Include, "bgp", "a bgp x\nbmp y\nBGP z\n");
        assert_eq!(out, "a bgp x\nBGP z\n");
    }

    #[test]
    fn exclude_drops_matching_lines() {
        let out = run(PipeOp::Exclude, "bmp", "a bgp x\nbmp y\n");
        assert_eq!(out, "a bgp x\n");
    }

    #[test]
    fn begin_passes_everything_from_the_first_hit() {
        let out = run(PipeOp::Begin, "two", "one\ntwo\nthree\n");
        assert_eq!(out, "two\nthree\n");
    }

    #[test]
    fn count_reports_the_total_and_suppresses_lines() {
        let out = run(PipeOp::Count, "", "one\ntwo\nthree\n");
        assert_eq!(out, "Number of lines which match: 3\n");
    }

    #[test]
    fn a_trailing_line_without_a_newline_is_not_lost() {
        let out = run(PipeOp::Include, "x", "ax\nbx");
        assert_eq!(out, "ax\nbx\n");
    }

    #[test]
    fn matching_ignores_case_both_ways() {
        let out = run(PipeOp::Include, "BGP", "a bgp x\n");
        assert_eq!(out, "a bgp x\n");
    }

    /// Renderers write in arbitrary chunks; line framing must not depend on
    /// how the writes happen to be split.
    #[test]
    fn works_across_arbitrary_write_boundaries() {
        let pipe = Pipe {
            op: PipeOp::Include,
            pattern: "bgp".into(),
        };
        let mut f = LineFilter::new(Vec::new(), pipe);
        f.write_all(b"a b").unwrap();
        f.write_all(b"gp x\nbmp").unwrap();
        f.write_all(b" y\n").unwrap();
        let out = String::from_utf8(f.finish().unwrap()).unwrap();
        assert_eq!(out, "a bgp x\n");
    }
}
