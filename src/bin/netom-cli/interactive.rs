//! The `netom>` prompt.

use std::borrow::Cow;
use std::path::PathBuf;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{
    Cmd, Context, Editor, EventHandler, Helper, KeyCode, KeyEvent, Modifiers,
};

use crate::error::EXIT_OK;
use crate::session::Session;
use crate::tree;

/// Completion driven by the command tree, so tab and `?` can never offer
/// something the parser would reject.
struct NetomHelper;

impl Completer for NetomHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let upto = &line[..pos];
        // Replace from the start of the word under the cursor.
        let start =
            upto.rfind(char::is_whitespace).map(|i| i + 1).unwrap_or(0);

        let pairs = tree::candidates(upto)
            .into_iter()
            // Argument placeholders describe a value to type; there is
            // nothing to insert for them.
            .filter(|c| !c.insert.is_empty())
            .map(|c| Pair {
                display: format!("{}  {}", c.display, c.help),
                replacement: format!("{} ", c.insert),
            })
            .collect();

        Ok((start, pairs))
    }
}

impl Hinter for NetomHelper {
    type Hint = String;
}
impl Highlighter for NetomHelper {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Cow::Borrowed(hint)
    }
}
impl Validator for NetomHelper {}
impl Helper for NetomHelper {}

/// Where to keep command history.
///
/// Falls back to in-memory when there is no writable home — the Docker
/// image runs as a uid with no home directory, and a CLI that refuses to
/// start over that would be worse than one that forgets.
fn history_path() -> Option<PathBuf> {
    let dir = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(".local/state"))
        })?
        .join("netom");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("cli_history"))
}

pub fn run(session: &mut Session) -> i32 {
    let mut editor = match Editor::<NetomHelper, _>::new() {
        Ok(editor) => editor,
        Err(err) => {
            eprintln!("% Cannot start interactive mode: {err}");
            return crate::error::EXIT_USAGE;
        }
    };
    editor.set_helper(Some(NetomHelper));

    // `?` lists the possible continuations, as on a router console.
    editor.bind_sequence(
        KeyEvent(KeyCode::Char('?'), Modifiers::NONE),
        EventHandler::Simple(Cmd::Complete),
    );

    let history = history_path();
    if let Some(path) = &history {
        let _ = editor.load_history(path);
    }

    let endpoint = session
        .client
        .addrs()
        .first()
        .map(|a| a.to_string())
        .unwrap_or_default();
    println!("netom-cli {}", env!("CARGO_PKG_VERSION"));
    println!("Connected to {endpoint}. Type ? for help, exit to quit.\n");

    let mut code = EXIT_OK;
    loop {
        match editor.readline("netom> ") {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = editor.add_history_entry(trimmed);
                if let Err(err) = crate::execute(session, trimmed) {
                    if !err.is_silent() {
                        eprintln!("{err}");
                        code = err.exit_code();
                    }
                }
                if session.should_exit {
                    break;
                }
            }
            // Ctrl-C abandons the line but keeps the session, as a shell
            // does.
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(err) => {
                eprintln!("% {err}");
                code = crate::error::EXIT_USAGE;
                break;
            }
        }
    }

    if let Some(path) = &history {
        let _ = editor.save_history(path);
    }
    code
}
