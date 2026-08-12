//! `netom-cli` — a router-style operational CLI for the netom daemon.
//!
//! Speaks Cisco-style commands (`show ip bgp summary`) over netom's HTTP
//! API, in one-shot or interactive form.
//!
//! # Hermetic by design
//!
//! This binary must never `use netom::...`. Because the package has a lib
//! target, every bin in it gets an implicit dependency on that lib, and
//! referencing it would pull roto/cranelift, axum and rotonda-store into
//! the CLI's link graph for the sake of a helper or two. Keeping the CLI
//! standalone keeps it small and its startup instant. The rule is enforced
//! by `hermetic::does_not_link_the_daemon` below.

use std::io::{IsTerminal, Read, Write};

use clap::{crate_version, Arg, ArgAction, Command};

mod commands;
mod endpoint;
mod error;
mod http;
mod interactive;
mod lex;
mod pipe;
mod render;
mod session;
mod tree;

use error::{CliError, EXIT_OK};
use session::Session;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let matches = cli().get_matches();

    let endpoint = match endpoint::resolve(
        matches.get_one::<String>("url").map(String::as_str),
        matches.get_one::<String>("config").map(String::as_str),
    ) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            eprintln!("{err}");
            return err.exit_code();
        }
    };

    let timeout = matches
        .get_one::<String>("timeout")
        .and_then(|s| s.parse().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or(session::DEFAULT_TIMEOUT);

    let client = http::Client::new(
        endpoint.addrs,
        endpoint.provenance,
        timeout,
    );
    let mut session =
        Session::new(client, matches.get_flag("json"));

    // Explicit -e commands, then a bare trailing command, then stdin if it
    // is a pipe, then the interactive prompt.
    let executes: Vec<String> = matches
        .get_many::<String>("execute")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    let trailing: Vec<String> = matches
        .get_many::<String>("command")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();

    if !executes.is_empty() {
        return run_lines(&mut session, executes.into_iter());
    }
    if !trailing.is_empty() {
        return run_lines(&mut session, std::iter::once(trailing.join(" ")));
    }
    if !std::io::stdin().is_terminal() {
        let mut buf = String::new();
        if std::io::stdin().read_to_string(&mut buf).is_err() {
            eprintln!("% Could not read commands from stdin.");
            return error::EXIT_USAGE;
        }
        return run_lines(
            &mut session,
            buf.lines().map(str::to_string).collect::<Vec<_>>().into_iter(),
        );
    }

    interactive::run(&mut session)
}

fn cli() -> Command {
    Command::new("netom-cli")
        .version(crate_version!())
        .about("Operational CLI for the netom BGP/BMP engine")
        .arg(
            Arg::new("url")
                .short('u')
                .long("url")
                .value_name("URL")
                .help("API endpoint, e.g. http://127.0.0.1:8080"),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("PATH")
                .help("Read the endpoint from a netom config file"),
        )
        .arg(
            Arg::new("execute")
                .short('e')
                .long("execute")
                .value_name("COMMAND")
                .action(ArgAction::Append)
                .help("Run a command; repeatable"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Emit the raw API response instead of a table"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("SECS")
                .help("Read timeout in seconds"),
        )
        .arg(
            Arg::new("command")
                .num_args(0..)
                .trailing_var_arg(true)
                .allow_hyphen_values(true)
                .help("Command to run, e.g. show ip bgp summary"),
        )
}

/// Run a sequence of command lines, returning the process exit code.
fn run_lines(
    session: &mut Session,
    lines: impl Iterator<Item = String>,
) -> i32 {
    let mut code = EXIT_OK;
    for line in lines {
        let line = line.trim();
        // Blank lines and `#` comments make piped scripts readable.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Err(err) = execute(session, line) {
            eprintln!("{err}");
            code = err.exit_code();
        }
        if session.should_exit {
            break;
        }
    }
    code
}

/// Parse and run one command line.
pub fn execute(session: &mut Session, line: &str) -> Result<(), CliError> {
    let (command, output_filter) = lex::split_pipe(line);

    // `show ip ?` prints the possible continuations.
    if let Some(stem) = command.trim_end().strip_suffix('?') {
        let mut stdout = std::io::stdout();
        writeln!(stdout, "{}", tree::help_text(stem))?;
        return Ok(());
    }

    let (handler, captures) = tree::resolve(command).map_err(|err| {
        CliError::Usage(err.render(command))
    })?;

    session.pipe = output_filter;
    let result = handler(session, &captures);
    session.pipe = None;
    result
}

#[cfg(test)]
mod hermetic {
    /// The CLI must not link the daemon lib — see the module docs. A stray
    /// `use netom::...` compiles fine and silently drags cranelift, axum
    /// and rotonda-store into this binary, so nothing but a check like this
    /// will catch it.
    #[test]
    fn does_not_link_the_daemon() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/netom-cli");
        let mut offenders = Vec::new();
        // Built at runtime so this test's own source does not match it.
        let needle = format!("{}::", "netom");

        fn walk(
            dir: &std::path::Path,
            needle: &str,
            offenders: &mut Vec<String>,
        ) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, needle, offenders);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    for (n, line) in text.lines().enumerate() {
                        // Skip the prose in the module docs that names the
                        // very pattern being banned.
                        if line.trim_start().starts_with("//") {
                            continue;
                        }
                        if line.contains(needle) {
                            offenders.push(format!(
                                "{}:{}: {}",
                                path.display(),
                                n + 1,
                                line.trim(),
                            ));
                        }
                    }
                }
            }
        }
        walk(std::path::Path::new(dir), &needle, &mut offenders);

        assert!(
            offenders.is_empty(),
            "netom-cli must stay hermetic, but these lines reference the \
             daemon lib:\n{}",
            offenders.join("\n"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// clap panics on a malformed command definition; this catches it at
    /// test time rather than on a user's first run.
    #[test]
    fn arg_definition_is_valid() {
        cli().debug_assert();
    }
}
