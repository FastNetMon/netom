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
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => EXIT_USAGE,
            CliError::Transport(_) => EXIT_TRANSPORT,
            CliError::Api { .. } => EXIT_API,
        }
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
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        CliError::Transport(err.to_string())
    }
}
