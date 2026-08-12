//! The `netom>` prompt.

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{
    Cmd, ConditionalEventHandler, Context, Editor, Event, EventContext,
    EventHandler, Helper, KeyCode, KeyEvent, Modifiers, RepeatCount,
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

/// The `?` key.
///
/// On a router console `?` always *lists* what may follow and leaves the
/// line alone, even when only one keyword matches. Rustyline has no command
/// for that — `Complete` would type the sole candidate in, which is why
/// `show ip ?` used to turn into `show ip bgp ` instead of showing the
/// choice. So the key stashes the line, accepts it to get out of the
/// editor, and [`run`] prints the listing and hands the line straight back.
#[derive(Clone, Default)]
struct HelpKey(Arc<Mutex<Option<(String, String)>>>);

impl HelpKey {
    /// The line the `?` was typed on, split at the cursor, if the last
    /// readline ended because of `?` rather than enter.
    fn take(&self) -> Option<(String, String)> {
        self.0.lock().ok()?.take()
    }
}

impl ConditionalEventHandler for HelpKey {
    fn handle(
        &self,
        _evt: &Event,
        _n: RepeatCount,
        _positive: bool,
        ctx: &EventContext,
    ) -> Option<Cmd> {
        // Help applies to what is left of the cursor, so `?` in the middle
        // of a line answers about the word being typed there.
        let (left, right) = ctx.line().split_at(ctx.pos());
        // Past a `|` the rest of the line is a filter pattern, not a
        // command, so a `?` there is just a character to match on.
        if left.contains('|') {
            return None;
        }
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some((left.to_string(), right.to_string()));
        }
        Some(Cmd::AcceptLine)
    }
}

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
    let help_key = HelpKey::default();
    editor.bind_sequence(
        KeyEvent(KeyCode::Char('?'), Modifiers::NONE),
        EventHandler::Conditional(Box::new(help_key.clone())),
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
    println!(
        "Connected to {endpoint}. Type help for all commands, ? for what \
         may follow, exit to quit.\n"
    );

    let mut code = EXIT_OK;
    // Restored after a `?`, so the line survives the listing.
    let (mut before, mut after) = (String::new(), String::new());
    loop {
        match editor.readline_with_initial("netom> ", (&before, &after)) {
            Ok(line) => {
                // `?` accepts the line without meaning to run it.
                if let Some((left, right)) = help_key.take() {
                    println!("{}", tree::help_text(&left));
                    (before, after) = (left, right);
                    continue;
                }
                (before, after) = (String::new(), String::new());

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
            Err(ReadlineError::Interrupted) => {
                let _ = help_key.take();
                (before, after) = (String::new(), String::new());
                continue;
            }
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
