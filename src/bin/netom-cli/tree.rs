//! The command tree.
//!
//! One static tree drives four things that must never disagree: parsing,
//! unambiguous-prefix abbreviation, tab-completion, and `?` help. Adding a
//! command in one place therefore makes it typeable, abbreviatable,
//! completable and documented at once.

use std::net::IpAddr;

use crate::commands;
use crate::error::CliError;
use crate::lex::{tokenize, Token};
use crate::session::Session;

pub type Handler = fn(&mut Session, &Captures) -> Result<(), CliError>;

/// What a node matches: a fixed keyword, or a typed value.
#[derive(Clone, Copy, Debug)]
pub enum Kw {
    Lit(&'static str),
    Arg(ArgKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgKind {
    /// `10.0.0.0/24` or `2001:db8::/32`.
    Prefix,
    /// A bare address.
    Ip,
    /// An ingress id.
    IngressId,
    /// An AS number, with or without the `AS` prefix.
    Asn,
    /// A standard community: `65000:100`, `0x1a2b3c4d`, or a well-known name.
    Community,
}

impl ArgKind {
    /// The placeholder shown in help and completion listings.
    pub fn placeholder(self) -> &'static str {
        match self {
            ArgKind::Prefix => "<A.B.C.D/M>",
            ArgKind::Ip => "<A.B.C.D|X:X::X>",
            ArgKind::IngressId => "<0-4294967295>",
            ArgKind::Asn => "<1-4294967295>",
            ArgKind::Community => "<AA:NN>",
        }
    }

    fn parse(self, tok: &str) -> Option<Value> {
        match self {
            ArgKind::Prefix => {
                let (addr, len) = tok.split_once('/')?;
                let addr: IpAddr = addr.parse().ok()?;
                let len: u8 = len.parse().ok()?;
                let max = if addr.is_ipv4() { 32 } else { 128 };
                (len <= max).then_some(Value::Prefix(addr, len))
            }
            ArgKind::Ip => tok.parse().ok().map(Value::Ip),
            ArgKind::IngressId => tok.parse().ok().map(Value::IngressId),
            ArgKind::Asn => {
                // `AS65000` and `65000` both, as inetnum's own parser accepts.
                let digits =
                    if tok.len() > 2 && tok[..2].eq_ignore_ascii_case("as") {
                        &tok[2..]
                    } else {
                        tok
                    };
                digits.parse().ok().map(Value::Asn)
            }
            // Validated only for shape: the daemon owns the real grammar, and
            // duplicating routecore's parser here would be one more thing to
            // keep in step. This rejects the typos worth a caret -- a bare
            // word, a missing half -- and lets anything plausible through.
            ArgKind::Community => {
                let plausible = match tok.split_once(':') {
                    Some((asn, tag)) => {
                        !asn.is_empty()
                            && !tag.is_empty()
                            && tag.bytes().all(|b| b.is_ascii_digit())
                    }
                    None => {
                        tok.strip_prefix("0x").is_some_and(|hex| {
                            !hex.is_empty()
                                && hex.bytes().all(|b| b.is_ascii_hexdigit())
                        }) || tok.bytes().all(|b| {
                            b.is_ascii_alphabetic() || b == b'_' || b == b'-'
                        })
                    }
                };
                plausible.then(|| Value::Community(tok.to_string()))
            }
        }
    }
}

/// A parsed argument value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Prefix(IpAddr, u8),
    Ip(IpAddr),
    IngressId(u32),
    Asn(u32),
    Community(String),
}

/// Static context a node contributes when traversed, so that one subtree can
/// serve several address families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flag {
    Afi(Afi),
    Safi(Safi),
    Source(PeerSource),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Afi {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Safi {
    Unicast,
    FlowSpec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerSource {
    Bgp,
    Bmp,
    /// Replayed from an MRT file. Route queries can be narrowed to it;
    /// `show ip bgp summary` cannot, since an MRT peer has no session.
    Mrt,
}

impl PeerSource {
    /// The `filter[ingressType]` value this narrows routes to.
    pub fn ingress_type(self) -> &'static str {
        match self {
            PeerSource::Bgp => "bgp",
            // The daemon reads `bmp` as everything learned through BMP, i.e.
            // the `bgpViaBmp` peers under a monitored router.
            PeerSource::Bmp => "bmp",
            PeerSource::Mrt => "mrt",
        }
    }
}

pub struct Node {
    pub kw: Kw,
    pub help: &'static str,
    pub set: Option<Flag>,
    pub run: Option<Handler>,
    pub children: &'static [Node],
}

/// Everything a handler needs from the matched command line.
#[derive(Clone, Debug, Default)]
pub struct Captures {
    pub args: Vec<Value>,
    pub flags: Vec<Flag>,
}

impl Captures {
    pub fn prefix(&self) -> Option<(IpAddr, u8)> {
        self.args.iter().find_map(|v| match v {
            Value::Prefix(a, l) => Some((*a, *l)),
            _ => None,
        })
    }

    pub fn ip(&self) -> Option<IpAddr> {
        self.args.iter().find_map(|v| match v {
            Value::Ip(a) => Some(*a),
            _ => None,
        })
    }

    pub fn ingress_id(&self) -> Option<u32> {
        self.args.iter().find_map(|v| match v {
            Value::IngressId(a) => Some(*a),
            _ => None,
        })
    }

    pub fn asn(&self) -> Option<u32> {
        self.args.iter().find_map(|v| match v {
            Value::Asn(a) => Some(*a),
            _ => None,
        })
    }

    pub fn community(&self) -> Option<&str> {
        self.args.iter().find_map(|v| match v {
            Value::Community(c) => Some(c.as_str()),
            _ => None,
        })
    }

    /// The address family this command applies to, defaulting to IPv4 the
    /// way `show ip bgp` implies v4.
    pub fn afi(&self) -> Afi {
        self.flags
            .iter()
            .rev()
            .find_map(|f| match f {
                Flag::Afi(a) => Some(*a),
                _ => None,
            })
            .unwrap_or(Afi::V4)
    }

    pub fn safi(&self) -> Safi {
        self.flags
            .iter()
            .rev()
            .find_map(|f| match f {
                Flag::Safi(s) => Some(*s),
                _ => None,
            })
            .unwrap_or(Safi::Unicast)
    }

    pub fn source(&self) -> Option<PeerSource> {
        self.flags.iter().rev().find_map(|f| match f {
            Flag::Source(s) => Some(*s),
            _ => None,
        })
    }
}

//------------ Matching ------------------------------------------------------

#[derive(Debug)]
pub enum MatchErr {
    /// Several keywords share the typed prefix.
    Ambiguous {
        token: String,
        candidates: Vec<(&'static str, &'static str)>,
    },
    /// Nothing at this level matches.
    Invalid { offset: usize },
    /// A valid path, but not a complete command.
    Incomplete,
    /// The line was blank.
    Empty,
}

impl MatchErr {
    /// Render in the style of a router console, with the caret under the
    /// offending token.
    pub fn render(&self, line: &str) -> String {
        match self {
            MatchErr::Empty => String::new(),
            MatchErr::Incomplete => "% Incomplete command.".to_string(),
            MatchErr::Invalid { offset } => {
                // The caret is positioned by character count, not bytes, so
                // it stays under the token for non-ASCII input.
                let col = line[..*offset].chars().count();
                format!(
                    "{}^\n% Invalid input detected at '^' marker.",
                    " ".repeat(col),
                )
            }
            MatchErr::Ambiguous {
                token, candidates, ..
            } => {
                let mut out = format!("% Ambiguous command: \"{token}\"\n");
                let width = candidates
                    .iter()
                    .map(|(w, _)| w.len())
                    .max()
                    .unwrap_or(0);
                for (word, help) in candidates {
                    out.push_str(&format!("  {word:width$}  {help}\n"));
                }
                out.pop();
                out
            }
        }
    }
}

/// Resolve a command line against the tree.
pub fn resolve(line: &str) -> Result<(Handler, Captures), MatchErr> {
    let tokens = tokenize(line);
    if tokens.is_empty() {
        return Err(MatchErr::Empty);
    }
    resolve_tokens(&tokens)
}

fn resolve_tokens(tokens: &[Token]) -> Result<(Handler, Captures), MatchErr> {
    let mut level: &'static [Node] = ROOT;
    let mut captures = Captures::default();
    let mut run: Option<Handler> = None;

    for tok in tokens {
        let node = match_one(level, &tok.text, tok.offset)?;

        if let Some(flag) = node.set {
            captures.flags.push(flag);
        }
        if let Kw::Arg(kind) = node.kw {
            // `match_one` only returns an Arg node whose parse succeeded.
            if let Some(value) = kind.parse(&tok.text) {
                captures.args.push(value);
            }
        }

        run = node.run;
        level = node.children;
    }

    run.map(|handler| (handler, captures))
        .ok_or(MatchErr::Incomplete)
}

/// Match one token against one level of the tree, with Cisco semantics.
fn match_one(
    level: &'static [Node],
    tok: &str,
    offset: usize,
) -> Result<&'static Node, MatchErr> {
    // 1. An exact keyword match wins outright, even when it is also a
    //    prefix of a sibling. Without this rule `ip` would be ambiguous
    //    against `ipv6`, and `show ip bgp` could never be typed in full.
    if let Some(node) = level.iter().find(|n| match n.kw {
        Kw::Lit(word) => word.eq_ignore_ascii_case(tok),
        Kw::Arg(_) => false,
    }) {
        return Ok(node);
    }

    // 2. Otherwise, a unique prefix match.
    let prefix_matches: Vec<&'static Node> = level
        .iter()
        .filter(|n| match n.kw {
            Kw::Lit(word) => {
                word.len() >= tok.len()
                    && word[..tok.len()].eq_ignore_ascii_case(tok)
            }
            Kw::Arg(_) => false,
        })
        .collect();

    match prefix_matches.len() {
        1 => return Ok(prefix_matches[0]),
        0 => {}
        _ => {
            return Err(MatchErr::Ambiguous {
                token: tok.to_string(),
                candidates: prefix_matches
                    .iter()
                    .filter_map(|n| match n.kw {
                        Kw::Lit(word) => Some((word, n.help)),
                        Kw::Arg(_) => None,
                    })
                    .collect(),
            })
        }
    }

    // 3. No keyword matched, so try typed arguments in declaration order.
    //    Order matters: Prefix is declared before Ip so that `10.0.0.0/24`
    //    cannot be partially read as a bare address.
    for node in level {
        if let Kw::Arg(kind) = node.kw {
            if kind.parse(tok).is_some() {
                return Ok(node);
            }
        }
    }

    Err(MatchErr::Invalid { offset })
}

//------------ Completion and help -------------------------------------------

/// One possible continuation of a command line.
#[derive(Clone, Debug)]
pub struct Candidate {
    /// Text to insert on tab-completion. Empty for argument placeholders,
    /// which cannot be completed.
    pub insert: &'static str,
    /// How it is shown in a listing.
    pub display: &'static str,
    pub help: &'static str,
}

/// Candidate continuations for a (possibly partial) line.
///
/// This is the single source for both tab-completion and `?` help, so the
/// two can never drift apart.
pub fn candidates(line: &str) -> Vec<Candidate> {
    let ends_with_space =
        line.chars().last().is_some_and(|c| c.is_whitespace());
    let tokens = tokenize(line);

    // Walk the complete tokens; the last one is a partial word unless the
    // line ends in whitespace.
    let (complete, partial) = if ends_with_space || tokens.is_empty() {
        (&tokens[..], "")
    } else {
        let (last, rest) = tokens.split_last().unwrap();
        (rest, last.text.as_str())
    };

    let mut level: &'static [Node] = ROOT;
    for tok in complete {
        match match_one(level, &tok.text, tok.offset) {
            Ok(node) => level = node.children,
            // A line that does not parse has no meaningful continuations.
            Err(_) => return Vec::new(),
        }
    }

    level
        .iter()
        .filter_map(|node| match node.kw {
            Kw::Lit(word) => {
                let matches = word.len() >= partial.len()
                    && word[..partial.len()].eq_ignore_ascii_case(partial);
                matches.then_some(Candidate {
                    insert: word,
                    display: word,
                    help: node.help,
                })
            }
            // Placeholders are listed for `?` but never inserted by tab.
            Kw::Arg(kind) => partial.is_empty().then_some(Candidate {
                insert: "",
                display: kind.placeholder(),
                help: node.help,
            }),
        })
        .collect()
}

/// Render `?` help: the candidate continuations, aligned in two columns.
///
/// A line that is already a complete command ends with `<cr>`, the way a
/// router console says "and you may press enter here".
pub fn help_text(line: &str) -> String {
    let cands = candidates(line);
    let runnable = resolve(line).is_ok();
    if cands.is_empty() {
        return if runnable {
            "  <cr>".to_string()
        } else {
            "% No additional keywords at this point.".to_string()
        };
    }
    let width = cands.iter().map(|c| c.display.len()).max().unwrap_or(0);
    let mut out = String::new();
    for c in &cands {
        out.push_str(&format!(
            "  {:width$}  {}\n",
            c.display,
            c.help,
            width = width
        ));
    }
    if runnable {
        out.push_str("  <cr>");
    } else {
        out.pop();
    }
    out
}

/// Every complete command in the tree, as the words to type and the help of
/// the keyword that runs it.
///
/// Walking the same tree the parser uses means `help` can never list a
/// command that does not exist, nor miss one that does.
pub fn all_commands() -> Vec<(String, &'static str)> {
    fn walk(
        level: &'static [Node],
        path: &mut Vec<&'static str>,
        out: &mut Vec<(String, &'static str)>,
    ) {
        for node in level {
            path.push(match node.kw {
                Kw::Lit(word) => word,
                Kw::Arg(kind) => kind.placeholder(),
            });
            if node.run.is_some() {
                out.push((path.join(" "), node.help));
            }
            walk(node.children, path, out);
            path.pop();
        }
    }

    let mut out = Vec::new();
    walk(ROOT, &mut Vec::new(), &mut out);
    out
}

/// Render the full command list for `help`, aligned in two columns.
pub fn command_list() -> String {
    let commands = all_commands();
    let width = commands
        .iter()
        .map(|(path, _)| path.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (path, help) in &commands {
        out.push_str(&format!("  {path:width$}  {help}\n"));
    }
    out.pop();
    out
}

//------------ The tree itself -----------------------------------------------

macro_rules! lit {
    ($word:expr, $help:expr, $children:expr) => {
        Node {
            kw: Kw::Lit($word),
            help: $help,
            set: None,
            run: None,
            children: $children,
        }
    };
}

macro_rules! leaf {
    ($word:expr, $help:expr, $run:expr) => {
        Node {
            kw: Kw::Lit($word),
            help: $help,
            set: None,
            run: Some($run),
            children: &[],
        }
    };
}

/// A node that sets a flag, runs on its own, and delegates to a shared
/// subtree. `show ip bgp` dumps the table; `show ip bgp <prefix>` and the
/// other children narrow it.
macro_rules! flagged {
    ($word:expr, $help:expr, $flag:expr, $run:expr, $children:expr) => {
        Node {
            kw: Kw::Lit($word),
            help: $help,
            set: Some($flag),
            run: Some($run),
            children: $children,
        }
    };
}

//------------ Route filters -------------------------------------------------

// These narrow a route query the way the API's `filter[...]` parameters do.
// They are `const`, not `static`, so one definition can appear in several
// subtrees; the tree is a path, so only one applies per command -- stack
// `| include` on top when you need a second condition.

/// `source bgp|bmp|mrt` -- where a route was learned.
const FILTER_SOURCE: Node = Node {
    kw: Kw::Lit("source"),
    help: "Only routes learned over one kind of ingress",
    set: None,
    run: None,
    children: FILTER_SOURCE_KINDS,
};

static FILTER_SOURCE_KINDS: &[Node] = &[
    Node {
        kw: Kw::Lit("bgp"),
        help: "Sessions netom terminates itself",
        set: Some(Flag::Source(PeerSource::Bgp)),
        run: Some(commands::bgp::routes),
        children: &[],
    },
    Node {
        kw: Kw::Lit("bmp"),
        help: "Peers monitored through BMP",
        set: Some(Flag::Source(PeerSource::Bmp)),
        run: Some(commands::bgp::routes),
        children: &[],
    },
    Node {
        kw: Kw::Lit("mrt"),
        help: "Peers replayed from MRT files",
        set: Some(Flag::Source(PeerSource::Mrt)),
        run: Some(commands::bgp::routes),
        children: &[],
    },
];

/// `ingress <id>` -- one exact ingress, i.e. one path of an ADD-PATH peer.
const FILTER_INGRESS: Node = Node {
    kw: Kw::Lit("ingress"),
    help: "Only routes stored under one ingress id",
    set: None,
    run: None,
    children: FILTER_INGRESS_ARG,
};

static FILTER_INGRESS_ARG: &[Node] = &[Node {
    kw: Kw::Arg(ArgKind::IngressId),
    help: "Ingress id, from `show ingresses`",
    set: None,
    run: Some(commands::bgp::routes),
    children: &[],
}];

/// `origin-as <asn>` -- the last ASN of the AS_PATH.
const FILTER_ORIGIN_AS: Node = Node {
    kw: Kw::Lit("origin-as"),
    help: "Only routes originated by one AS",
    set: None,
    run: None,
    children: FILTER_ORIGIN_AS_ARG,
};

static FILTER_ORIGIN_AS_ARG: &[Node] = &[Node {
    kw: Kw::Arg(ArgKind::Asn),
    help: "Originating AS number",
    set: None,
    run: Some(commands::bgp::routes),
    children: &[],
}];

/// `community <value>` -- one standard community.
const FILTER_COMMUNITY: Node = Node {
    kw: Kw::Lit("community"),
    help: "Only routes carrying one community",
    set: None,
    run: None,
    children: FILTER_COMMUNITY_ARG,
};

static FILTER_COMMUNITY_ARG: &[Node] = &[Node {
    kw: Kw::Arg(ArgKind::Community),
    help: "Community, e.g. 65000:100 or NO_EXPORT",
    set: None,
    run: Some(commands::bgp::routes),
    children: &[],
}];

pub static ROOT: &[Node] = &[
    lit!("show", "Show running system information", SHOW),
    leaf!("help", "List every command", commands::system::help),
    leaf!("exit", "Exit the CLI", commands::system::exit),
    leaf!("quit", "Exit the CLI", commands::system::exit),
    leaf!("end", "Exit the CLI", commands::system::exit),
];

static SHOW: &[Node] = &[
    lit!("ip", "IPv4 information", SHOW_IP),
    lit!("ipv6", "IPv6 information", SHOW_IPV6),
    lit!("bmp", "BMP monitoring information", SHOW_BMP),
    leaf!(
        "ingresses",
        "Ingress and session registry",
        commands::bmp::ingresses
    ),
    leaf!("version", "Software version", commands::system::version),
    leaf!(
        "status",
        "Daemon status and resource usage",
        commands::system::status
    ),
    leaf!(
        "running-config",
        "Current operating configuration",
        commands::system::running_config
    ),
    leaf!(
        "filters",
        "Roto filter script and entrypoints",
        commands::system::filters
    ),
];

// `show ip ...` and `show ipv6 ...` share one BGP subtree, differing only
// in the address family they push into the captures.
static SHOW_IP: &[Node] = &[flagged!(
    "bgp",
    "BGP information",
    Flag::Afi(Afi::V4),
    commands::bgp::routes,
    BGP_BODY
)];

static SHOW_IPV6: &[Node] = &[flagged!(
    "bgp",
    "BGP information",
    Flag::Afi(Afi::V6),
    commands::bgp::routes,
    BGP_BODY
)];

static BGP_BODY: &[Node] = &[
    // Runnable *and* extendable: `show ip bgp summary` stands alone, and
    // `show ip bgp summary bmp` narrows it.
    Node {
        kw: Kw::Lit("summary"),
        help: "Summary of BGP neighbor status",
        set: None,
        run: Some(commands::bgp::summary),
        children: BGP_SUMMARY,
    },
    Node {
        kw: Kw::Lit("neighbors"),
        help: "Detailed neighbor information",
        set: None,
        run: Some(commands::bgp::neighbors),
        children: BGP_NEIGHBORS,
    },
    Node {
        kw: Kw::Lit("flowspec"),
        help: "FlowSpec rules",
        set: Some(Flag::Safi(Safi::FlowSpec)),
        run: Some(commands::bgp::routes),
        children: BGP_FLOWSPEC,
    },
    Node {
        kw: Kw::Arg(ArgKind::Prefix),
        help: "Network in the BGP routing table",
        set: None,
        run: Some(commands::bgp::routes),
        children: &[],
    },
    FILTER_SOURCE,
    FILTER_INGRESS,
    FILTER_ORIGIN_AS,
    FILTER_COMMUNITY,
];

static BGP_SUMMARY: &[Node] = &[
    Node {
        kw: Kw::Lit("bgp"),
        help: "Only sessions netom terminates itself",
        set: Some(Flag::Source(PeerSource::Bgp)),
        run: Some(commands::bgp::summary),
        children: &[],
    },
    Node {
        kw: Kw::Lit("bmp"),
        help: "Only sessions observed through BMP",
        set: Some(Flag::Source(PeerSource::Bmp)),
        run: Some(commands::bgp::summary),
        children: &[],
    },
];

static BGP_NEIGHBORS: &[Node] = &[Node {
    kw: Kw::Arg(ArgKind::Ip),
    help: "Neighbor address",
    set: None,
    run: Some(commands::bgp::neighbors),
    children: BGP_NEIGHBOR_BODY,
}];

static BGP_NEIGHBOR_BODY: &[Node] = &[leaf!(
    "routes",
    "Routes learned from this neighbor",
    commands::bgp::routes
)];

// The FlowSpec endpoint rejects every filter but these two with a 400, so
// only these two are typeable here.
static BGP_FLOWSPEC: &[Node] = &[
    Node {
        kw: Kw::Arg(ArgKind::Prefix),
        help: "Destination prefix of the rule",
        set: None,
        run: Some(commands::bgp::routes),
        children: &[],
    },
    FILTER_SOURCE,
    FILTER_INGRESS,
];

static SHOW_BMP: &[Node] = &[
    leaf!("routers", "Monitored routers", commands::bmp::routers),
    lit!("router", "One monitored router", SHOW_BMP_ROUTER),
];

static SHOW_BMP_ROUTER: &[Node] = &[Node {
    kw: Kw::Arg(ArgKind::IngressId),
    help: "Ingress id of the router",
    set: None,
    run: Some(commands::bmp::router),
    children: &[],
}];

#[cfg(test)]
mod tests {
    use super::*;

    /// Resolve and report which handler matched, by address, so tests can
    /// assert on the destination without naming private fns.
    fn resolves(line: &str) -> bool {
        resolve(line).is_ok()
    }

    #[test]
    fn resolves_full_commands() {
        assert!(resolves("show version"));
        assert!(resolves("show status"));
        assert!(resolves("show running-config"));
        assert!(resolves("show filters"));
    }

    #[test]
    fn resolves_unambiguous_abbreviations() {
        assert!(resolves("sh ver"));
        assert!(resolves("sh stat"));
        assert!(resolves("s v"));
    }

    #[test]
    fn is_case_insensitive() {
        assert!(resolves("SHOW VERSION"));
        assert!(resolves("Sh Ver"));
    }

    #[test]
    fn rejects_incomplete_commands() {
        assert!(matches!(resolve("show"), Err(MatchErr::Incomplete)));
    }

    #[test]
    fn rejects_unknown_words_with_the_right_caret_column() {
        match resolve("show bogus") {
            Err(MatchErr::Invalid { offset }) => assert_eq!(offset, 5),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn reports_trailing_junk_after_a_complete_command() {
        match resolve("show version extra") {
            Err(MatchErr::Invalid { offset }) => assert_eq!(offset, 13),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn blank_line_is_empty_not_an_error() {
        assert!(matches!(resolve("   "), Err(MatchErr::Empty)));
    }

    /// The rule that makes `show ip bgp` typeable at all: an exact match
    /// must beat a longer sibling that shares the prefix.
    #[test]
    fn exact_match_beats_longer_sibling() {
        static LEVEL: &[Node] = &[
            leaf!("ip", "IPv4", commands::system::version),
            leaf!("ipv6", "IPv6", commands::system::status),
        ];
        let node = match_one(LEVEL, "ip", 0).expect("exact match wins");
        assert!(matches!(node.kw, Kw::Lit("ip")));

        // The shared prefix alone is genuinely ambiguous.
        assert!(matches!(
            match_one(LEVEL, "i", 0),
            Err(MatchErr::Ambiguous { .. })
        ));
    }

    #[test]
    fn ambiguity_lists_the_candidates() {
        static LEVEL: &[Node] = &[
            leaf!("ingresses", "Ingress registry", commands::system::version),
            leaf!("interfaces", "Interfaces", commands::system::status),
        ];
        match match_one(LEVEL, "in", 0) {
            Err(MatchErr::Ambiguous { candidates, .. }) => {
                assert_eq!(candidates.len(), 2);
            }
            _ => panic!("expected ambiguity"),
        }
    }

    #[test]
    fn resolves_the_route_filters() {
        assert!(resolves("show ip bgp source bgp"));
        assert!(resolves("show ip bgp source bmp"));
        assert!(resolves("show ip bgp source mrt"));
        assert!(resolves("show ipv6 bgp source bmp"));
        assert!(resolves("show ip bgp ingress 5"));
        assert!(resolves("show ip bgp origin-as 65001"));
        assert!(resolves("show ip bgp origin-as AS65001"));
        assert!(resolves("show ip bgp community 65000:100"));
        assert!(resolves("show ip bgp community NO_EXPORT"));
        assert!(resolves("show ip bgp neighbors 10.0.0.1 routes"));
        assert!(resolves("show ipv6 bgp neighbors 2001:db8::1 routes"));

        // The neighbor detail command still stands on its own.
        assert!(resolves("show ip bgp neighbors 10.0.0.1"));

        // A filter keyword on its own is incomplete, not a full-table dump.
        assert!(matches!(
            resolve("show ip bgp source"),
            Err(MatchErr::Incomplete)
        ));
        assert!(matches!(
            resolve("show ip bgp ingress"),
            Err(MatchErr::Incomplete)
        ));
    }

    /// FlowSpec only takes the filters the daemon implements for it; the
    /// others would come back as a 400 from the API.
    #[test]
    fn flowspec_offers_only_the_filters_it_supports() {
        assert!(resolves("show ip bgp flowspec source bmp"));
        assert!(resolves("show ip bgp flowspec ingress 5"));
        assert!(matches!(
            resolve("show ip bgp flowspec origin-as 65001"),
            Err(MatchErr::Invalid { .. })
        ));
        assert!(matches!(
            resolve("show ip bgp flowspec community 65000:100"),
            Err(MatchErr::Invalid { .. })
        ));
    }

    /// `summary` and `source` share a first letter, so the abbreviation has
    /// to report the ambiguity rather than silently pick one.
    #[test]
    fn summary_and_source_are_ambiguous_at_one_letter() {
        assert!(matches!(
            resolve("show ip bgp s"),
            Err(MatchErr::Ambiguous { .. })
        ));
        assert!(resolves("show ip bgp sum"));
        assert!(resolves("show ip bgp sou bmp"));
    }

    #[test]
    fn arg_kinds_parse_what_they_claim() {
        assert_eq!(
            ArgKind::Prefix.parse("10.0.0.0/24"),
            Some(Value::Prefix("10.0.0.0".parse().unwrap(), 24))
        );
        assert_eq!(
            ArgKind::Prefix.parse("2001:db8::/32"),
            Some(Value::Prefix("2001:db8::".parse().unwrap(), 32))
        );
        // Prefix length must be legal for the family.
        assert_eq!(ArgKind::Prefix.parse("10.0.0.0/33"), None);
        assert_eq!(ArgKind::Prefix.parse("10.0.0.0"), None);

        assert_eq!(
            ArgKind::Ip.parse("192.0.2.1"),
            Some(Value::Ip("192.0.2.1".parse().unwrap()))
        );
        assert_eq!(ArgKind::Ip.parse("192.0.2.1/24"), None);

        assert_eq!(
            ArgKind::IngressId.parse("42"),
            Some(Value::IngressId(42))
        );
        assert_eq!(ArgKind::IngressId.parse("bogus"), None);

        assert_eq!(ArgKind::Asn.parse("65001"), Some(Value::Asn(65001)));
        assert_eq!(ArgKind::Asn.parse("AS65001"), Some(Value::Asn(65001)));
        assert_eq!(ArgKind::Asn.parse("as65001"), Some(Value::Asn(65001)));
        assert_eq!(ArgKind::Asn.parse("AS"), None);
        assert_eq!(ArgKind::Asn.parse("65001:1"), None);

        assert_eq!(
            ArgKind::Community.parse("65000:100"),
            Some(Value::Community("65000:100".into()))
        );
        assert_eq!(
            ArgKind::Community.parse("0x1a2b3c4d"),
            Some(Value::Community("0x1a2b3c4d".into()))
        );
        assert_eq!(
            ArgKind::Community.parse("NO_EXPORT"),
            Some(Value::Community("NO_EXPORT".into()))
        );
        // Shape checks only, but enough to catch the typos worth a caret.
        assert_eq!(ArgKind::Community.parse("65000:"), None);
        assert_eq!(ArgKind::Community.parse("65000:abc"), None);
        assert_eq!(ArgKind::Community.parse("0x"), None);
        assert_eq!(ArgKind::Community.parse("10.0.0.1"), None);
    }

    /// Declaration order decides which typed argument wins, so a prefix must
    /// never be readable as a bare address.
    #[test]
    fn prefix_is_tried_before_ip() {
        static LEVEL: &[Node] = &[
            Node {
                kw: Kw::Arg(ArgKind::Prefix),
                help: "prefix",
                set: None,
                run: Some(commands::system::version),
                children: &[],
            },
            Node {
                kw: Kw::Arg(ArgKind::Ip),
                help: "address",
                set: None,
                run: Some(commands::system::status),
                children: &[],
            },
        ];
        let node = match_one(LEVEL, "10.0.0.0/24", 0).unwrap();
        assert!(matches!(node.kw, Kw::Arg(ArgKind::Prefix)));
        let node = match_one(LEVEL, "10.0.0.1", 0).unwrap();
        assert!(matches!(node.kw, Kw::Arg(ArgKind::Ip)));
    }

    #[test]
    fn completion_offers_children_of_a_complete_path() {
        let cands = candidates("show ");
        let words: Vec<_> = cands.iter().map(|c| c.insert).collect();
        assert!(words.contains(&"version"));
        assert!(words.contains(&"status"));
    }

    #[test]
    fn completion_filters_on_the_partial_word() {
        let cands = candidates("show ver");
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].insert, "version");
    }

    #[test]
    fn completion_at_root_offers_top_level_commands() {
        let words: Vec<_> = candidates("").iter().map(|c| c.insert).collect();
        assert!(words.contains(&"show"));
        assert!(words.contains(&"exit"));
    }

    #[test]
    fn help_text_is_produced_for_internal_nodes() {
        let help = help_text("show ");
        assert!(help.contains("version"));
        assert!(help.contains("Software version"));
    }

    /// The complaint that started this: one candidate must still be listed,
    /// never silently completed.
    #[test]
    fn help_text_lists_a_lone_candidate() {
        let help = help_text("show ip ");
        assert!(help.contains("bgp"), "{help}");
        assert!(help.contains("BGP information"), "{help}");
    }

    #[test]
    fn help_text_marks_a_runnable_line_with_cr() {
        // Runnable and extendable: both halves must show.
        let help = help_text("show ip bgp ");
        assert!(help.contains("summary"), "{help}");
        assert!(help.ends_with("<cr>"), "{help}");

        // Runnable with nothing to add.
        assert_eq!(help_text("show version "), "  <cr>");

        // Not runnable and nothing to add.
        assert!(help_text("show version extra ").starts_with('%'));
    }

    #[test]
    fn help_lists_every_runnable_command() {
        let commands = all_commands();
        let paths: Vec<_> =
            commands.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"show ip bgp summary bmp"));
        assert!(paths.contains(&"show bmp router <0-4294967295>"));
        assert!(paths.contains(&"help"));
        assert!(paths.contains(&"exit"));
        // Internal-only nodes are not commands in their own right.
        assert!(!paths.contains(&"show"));
        assert!(!paths.contains(&"show ip"));

        // Every listed command made only of keywords must parse back; the
        // ones with a placeholder need a real value in its place.
        for (path, _) in &commands {
            if path.contains('<') {
                continue;
            }
            assert!(
                resolve(path).is_ok(),
                "help lists {path:?}, which does not resolve",
            );
        }
    }

    /// Every leaf must be reachable and every internal node must offer a
    /// continuation, so the tree can never contain a dead end.
    #[test]
    fn tree_has_no_dead_ends() {
        fn walk(level: &'static [Node], path: &mut Vec<&'static str>) {
            for node in level {
                let name = match node.kw {
                    Kw::Lit(w) => w,
                    Kw::Arg(k) => k.placeholder(),
                };
                path.push(name);
                assert!(
                    node.run.is_some() || !node.children.is_empty(),
                    "dead end at {:?}: neither runnable nor extendable",
                    path.join(" "),
                );
                assert!(
                    !node.help.is_empty(),
                    "missing help text at {:?}",
                    path.join(" "),
                );
                walk(node.children, path);
                path.pop();
            }
        }
        walk(ROOT, &mut Vec::new());
    }
}
