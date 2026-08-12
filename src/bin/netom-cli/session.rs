//! Per-invocation state: where the daemon is, and where output goes.

use std::io::{self, Write};
use std::time::Duration;

use crate::error::CliError;
use crate::http::{Client, Response};
use crate::lex::Pipe;
use crate::pipe::LineFilter;

pub struct Session {
    pub client: Client,
    /// Emit the raw API response instead of a rendered table.
    pub json: bool,
    /// Output filter for the command currently running.
    pub pipe: Option<Pipe>,
    /// Set by `exit`/`quit` in interactive mode.
    pub should_exit: bool,
}

impl Session {
    pub fn new(client: Client, json: bool) -> Self {
        Self {
            client,
            json,
            pipe: None,
            should_exit: false,
        }
    }

    /// GET a path, turning a non-2xx response into a `CliError`.
    pub fn get(
        &self,
        path: &str,
    ) -> Result<Response<std::net::TcpStream>, CliError> {
        let mut resp = self.client.get(path)?;
        if !(200..300).contains(&resp.status) {
            let body = resp.body_string().unwrap_or_default();
            return Err(CliError::from_http(resp.status, path, &body));
        }
        Ok(resp)
    }

    /// GET a path and parse the `{"data": ...}` envelope the API wraps
    /// every JSON response in.
    pub fn get_data(
        &self,
        path: &str,
    ) -> Result<serde_json::Value, CliError> {
        let body = self.get(path)?.body_string()?;
        let value: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| {
                CliError::transport(format!(
                    "Malformed JSON from {path}: {e}",
                ))
            })?;
        value.get("data").cloned().ok_or_else(|| {
            CliError::transport(format!("No 'data' field in {path} response"))
        })
    }

    /// Stream a response body straight to stdout, for `--json`.
    ///
    /// Reports a dump the daemon abandoned rather than letting a truncated
    /// table pass for a complete one.
    pub fn passthrough(&mut self, path: &str) -> Result<(), CliError> {
        let mut resp = self.get(path)?;
        let truncated = {
            let mut out = self.writer();
            io::copy(&mut resp, &mut out)?;
            out.finish()?;
            resp.truncated()
        };
        if truncated {
            return Err(CliError::transport(
                "Output truncated: the daemon closed the connection before \
                 the response was complete.",
            ));
        }
        Ok(())
    }

    /// Stdout for this command, with any output filter applied.
    pub fn writer(&self) -> Out {
        match &self.pipe {
            Some(pipe) => Out::Filtered(Box::new(LineFilter::new(
                io::stdout(),
                pipe.clone(),
            ))),
            None => Out::Plain(io::stdout()),
        }
    }
}

/// Command output, optionally passed through a `| include`-style filter.
pub enum Out {
    Plain(io::Stdout),
    Filtered(Box<LineFilter<io::Stdout>>),
}

impl Out {
    /// Flush, emitting any tail the filter is holding (`| count`'s total,
    /// or a final line with no trailing newline).
    pub fn finish(self) -> io::Result<()> {
        match self {
            Out::Plain(mut out) => out.flush(),
            Out::Filtered(f) => f.finish().map(|_| ()),
        }
    }
}

impl Write for Out {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            Out::Plain(out) => out.write(data),
            Out::Filtered(f) => f.write(data),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Out::Plain(out) => out.flush(),
            Out::Filtered(f) => f.flush(),
        }
    }
}

/// Default read timeout. Generous, because a full-table dump on a busy
/// daemon can pause between chunks.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
