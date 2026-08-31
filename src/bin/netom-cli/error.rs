//! Errors and exit codes, rendered in the style of a router console.

use std::fmt;

/// Exit codes. Chosen so scripts can distinguish "you typed it wrong" from
/// "the daemon is not reachable" from "the daemon said no".
pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 1;
pub const EXIT_TRANSPORT: i32 = 2;
pub const EXIT_API: i32 = 3;

#[derive(Debug)]
pub enum CliError {
    /// A command that did not parse. Already rendered Cisco-style.
    Usage(String),

    /// Could not reach the daemon, or the connection broke mid-response.
    Transport(String),

    /// The daemon returned a non-2xx status.
    Api { status: u16, message: String },

    /// The reader on the other end of stdout went away — `| head`, a
    /// pager quit, `grep -q` matching early. Not a failure: the user got
    /// what they asked for. Reported separately so it exits cleanly and
    /// silently instead of printing "Broken pipe" on every such run.
    BrokenPipe,
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => EXIT_USAGE,
            CliError::Transport(_) => EXIT_TRANSPORT,
            CliError::Api { .. } => EXIT_API,
            CliError::BrokenPipe => EXIT_OK,
        }
    }

    /// Whether this should be printed to the user at all.
    pub fn is_silent(&self) -> bool {
        matches!(self, CliError::BrokenPipe)
    }

    pub fn transport(msg: impl fmt::Display) -> Self {
        CliError::Transport(msg.to_string())
    }

    pub fn usage(msg: impl fmt::Display) -> Self {
        CliError::Usage(msg.to_string())
    }

    /// Turn an HTTP failure into a message that says what an operator can do
    /// about it. The generic "% 503 Service Unavailable" is useless; the two
    /// cases below are the ones this API actually produces in practice.
    pub fn from_http(status: u16, path: &str, body: &str) -> Self {
        // The daemon's error envelope is {"data":null,"error":"..."}.
        let detail = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| {
                v.get("error").and_then(|e| e.as_str()).map(String::from)
            })
            .unwrap_or_else(|| body.trim().to_string());

        let message = match status {
            404 => format!(
                "Not supported by this netom (no endpoint {path}). \
                 The daemon is probably older than this CLI.",
            ),
            503 if detail.is_empty() => {
                "Service unavailable; the RIB may not be ready, or too many \
                 concurrent table dumps are already running. Retry shortly."
                    .to_string()
            }
            _ if detail.is_empty() => format!("HTTP {status} from {path}"),
            _ => detail,
        };
        CliError::Api { status, message }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Usage errors carry their own multi-line Cisco rendering
            // (caret markers, candidate lists), so they print verbatim.
            CliError::Usage(msg) => write!(f, "{msg}"),
            CliError::Transport(msg) => write!(f, "% {msg}"),
            CliError::Api { message, .. } => write!(f, "% {message}"),
            CliError::BrokenPipe => Ok(()),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::BrokenPipe {
            return CliError::BrokenPipe;
        }
        CliError::Transport(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_closed_reader_is_not_a_failure() {
        // `netom-cli show ip bgp | head -1` must exit 0 and say nothing.
        let err = CliError::from(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken pipe",
        ));
        assert!(matches!(err, CliError::BrokenPipe));
        assert_eq!(err.exit_code(), EXIT_OK);
        assert!(err.is_silent());
        assert_eq!(err.to_string(), "");
    }

    #[test]
    fn other_io_errors_are_transport_failures() {
        let err = CliError::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ));
        assert_eq!(err.exit_code(), EXIT_TRANSPORT);
        assert!(!err.is_silent());
    }

    #[test]
    fn a_404_points_at_version_skew() {
        let err = CliError::from_http(404, "/api/v1/status", "");
        assert_eq!(err.exit_code(), EXIT_API);
        assert!(err.to_string().contains("older than this CLI"));
    }

    #[test]
    fn the_daemon_error_envelope_is_unwrapped() {
        let err = CliError::from_http(
            500,
            "/api/v1/ribs/ipv4unicast/routes",
            r#"{"data":null,"error":"store unavailable"}"#,
        );
        assert_eq!(err.to_string(), "% store unavailable");
    }
}
