//! Tokenizing a command line, and splitting off a trailing output filter.
//!
//! Tokens carry their byte offset so that an "invalid input" report can put
//! the `^` marker under the offending word, the way a router console does.

/// A word plus where it started in the original line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    pub offset: usize,
}

/// A Cisco-style output filter: `... | include bgp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pipe {
    pub op: PipeOp,
    pub pattern: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeOp {
    Include,
    Exclude,
    Begin,
    Count,
}

impl PipeOp {
    fn parse(word: &str) -> Option<Self> {
        // Accept unambiguous abbreviations here too: `| inc`, `| exc`.
        for (name, op) in [
            ("include", PipeOp::Include),
            ("exclude", PipeOp::Exclude),
            ("begin", PipeOp::Begin),
            ("count", PipeOp::Count),
        ] {
            if !word.is_empty() && name.starts_with(word) {
                return Some(op);
            }
        }
        None
    }
}

/// Split a line into `(command, output filter)`.
///
/// The filter is taken off before command matching so that the command tree
/// never has to know about `|`. A `|` with nothing usable after it is left
/// in the command text, where it will fail as an unknown token — better than
/// silently ignoring it.
pub fn split_pipe(line: &str) -> (&str, Option<Pipe>) {
    let Some(bar) = line.find('|') else {
        return (line, None);
    };
    let (cmd, rest) = line.split_at(bar);
    let rest = &rest[1..];

    let mut words = rest.split_whitespace();
    let Some(op_word) = words.next() else {
        return (line, None);
    };
    let Some(op) = PipeOp::parse(op_word) else {
        return (line, None);
    };

    let pattern = words.collect::<Vec<_>>().join(" ");
    if pattern.is_empty() && op != PipeOp::Count {
        // `| include` with no pattern filters nothing; treat as malformed.
        return (line, None);
    }
    (cmd, Some(Pipe { op, pattern }))
}

/// Split a command into whitespace-separated tokens with byte offsets.
pub fn tokenize(line: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut start = None;
    for (i, ch) in line.char_indices() {
        if ch.is_whitespace() {
            if let Some(s) = start.take() {
                tokens.push(Token {
                    text: line[s..i].to_string(),
                    offset: s,
                });
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        tokens.push(Token {
            text: line[s..].to_string(),
            offset: s,
        });
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizes_with_offsets() {
        let toks = tokenize("show ip bgp");
        assert_eq!(toks.len(), 3);
        assert_eq!(toks[0].text, "show");
        assert_eq!(toks[0].offset, 0);
        assert_eq!(toks[2].text, "bgp");
        assert_eq!(toks[2].offset, 8);
    }

    #[test]
    fn offsets_survive_irregular_spacing() {
        let toks = tokenize("   show    ip ");
        assert_eq!(toks[0].offset, 3);
        assert_eq!(toks[1].offset, 11);
    }

    #[test]
    fn empty_line_has_no_tokens() {
        assert!(tokenize("   ").is_empty());
    }

    #[test]
    fn splits_output_filter() {
        let (cmd, pipe) = split_pipe("show ingresses | include bgp");
        assert_eq!(cmd.trim(), "show ingresses");
        let pipe = pipe.unwrap();
        assert_eq!(pipe.op, PipeOp::Include);
        assert_eq!(pipe.pattern, "bgp");
    }

    #[test]
    fn accepts_abbreviated_filter_verbs() {
        let (_, pipe) = split_pipe("show ingresses | inc bgp");
        assert_eq!(pipe.unwrap().op, PipeOp::Include);
        let (_, pipe) = split_pipe("show ingresses | exc bmp");
        assert_eq!(pipe.unwrap().op, PipeOp::Exclude);
    }

    #[test]
    fn count_needs_no_pattern() {
        let (cmd, pipe) = split_pipe("show ingresses | count");
        assert_eq!(cmd.trim(), "show ingresses");
        assert_eq!(pipe.unwrap().op, PipeOp::Count);
    }

    #[test]
    fn multi_word_pattern_is_kept_whole() {
        let (_, pipe) = split_pipe("show status | include bgp tcp in");
        assert_eq!(pipe.unwrap().pattern, "bgp tcp in");
    }

    #[test]
    fn malformed_filter_stays_in_the_command() {
        // Better to fail as an unknown token than to silently drop it.
        let (cmd, pipe) = split_pipe("show status | frobnicate x");
        assert!(cmd.contains('|'));
        assert!(pipe.is_none());

        let (cmd, pipe) = split_pipe("show status |");
        assert!(cmd.contains('|'));
        assert!(pipe.is_none());
    }

    #[test]
    fn no_filter_is_the_common_case() {
        let (cmd, pipe) = split_pipe("show ip bgp summary");
        assert_eq!(cmd, "show ip bgp summary");
        assert!(pipe.is_none());
    }
}
