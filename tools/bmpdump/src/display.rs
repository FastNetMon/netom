use crate::cli::{Color, routes_of};
use crate::protocol::array;
use serde_json::Value;
use std::env;
use std::io::{self, IsTerminal};

#[derive(Clone, Copy, Default)]
pub struct Palette {
    pub enabled: bool,
}
impl Palette {
    pub fn new(mode: Color, stderr: bool) -> Self {
        let tty = if stderr {
            io::stderr().is_terminal()
        } else {
            io::stdout().is_terminal()
        };
        let term = env::var("TERM").unwrap_or_default().to_lowercase();
        // Conservative detection for ANSI terminals; unusual terminals can opt in.
        let ansi = [
            "xterm",
            "screen",
            "tmux",
            "rxvt",
            "linux",
            "ansi",
            "color",
            "cygwin",
            "konsole",
            "alacritty",
            "kitty",
            "foot",
            "wezterm",
        ]
        .iter()
        .any(|name| term.contains(name))
            || env::var_os("COLORTERM").is_some();
        Self {
            enabled: match mode {
                Color::Always => true,
                Color::Never => false,
                Color::Auto => {
                    tty && !term.is_empty()
                        && term != "dumb"
                        && env::var_os("NO_COLOR").is_none()
                        && ansi
                }
            },
        }
    }
    pub fn paint(self, text: &str, style: &str) -> String {
        let code = match style {
            "heading" => "1;36",
            "label" => "36",
            "announce" => "32",
            "withdraw" => "31",
            "error" => "1;31",
            "warning" => "33",
            "muted" => "2",
            _ => "",
        };
        if self.enabled && !code.is_empty() {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
}
pub fn safe(text: &str) -> String {
    let mut result = String::new();
    for c in text.chars() {
        if c.is_control()
            || matches!(c,'\u{2028}'|'\u{2029}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        {
            result.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            result.push(c);
        }
    }
    result
}
fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        _ => v.to_string(),
    }
}
fn strv(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}
fn join(v: &Value, sep: &str) -> String {
    array(v).iter().map(text).collect::<Vec<_>>().join(sep)
}
fn timestamp(ns: &Value) -> String {
    let Ok(ns) = ns.to_string().parse::<i128>() else {
        return "unknown-time".into();
    };
    let (seconds, nanos) =
        (ns.div_euclid(1_000_000_000), ns.rem_euclid(1_000_000_000));
    if !(-62_135_596_800..=253_402_300_799).contains(&seconds) {
        return format!("epoch:{seconds}.{nanos:09}");
    }
    let seconds = seconds.rem_euclid(86400);
    format!(
        "{:02}:{:02}:{:02}.{nanos:09}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}
fn endpoint(v: &Value) -> String {
    let addr = strv(&v["address"]);
    if addr.contains(':') {
        format!("[{addr}]:{}", v["port"])
    } else {
        format!("{addr}:{}", v["port"])
    }
}
fn family(afi: &Value, safi: &Value) -> String {
    match (afi.as_u64(), safi.as_u64()) {
        (Some(1), Some(1)) => "IPv4 unicast".into(),
        (Some(1), Some(2)) => "IPv4 multicast".into(),
        (Some(2), Some(1)) => "IPv6 unicast".into(),
        (Some(2), Some(2)) => "IPv6 multicast".into(),
        (Some(25), Some(70)) => "L2VPN EVPN".into(),
        _ => format!("AFI {afi}, SAFI {safi}"),
    }
}
fn label(key: &str) -> String {
    match key {
        "asn" => "ASN".into(),
        "router_id" => "Router ID".into(),
        "afi" => "AFI".into(),
        "safi" => "SAFI".into(),
        "vrf-table-name" => "VRF/table name".into(),
        _ => {
            let mut s = key.replace(['_', '-'], " ");
            if let Some(c) = s.get_mut(..1) {
                c.make_ascii_uppercase();
            }
            s
        }
    }
}

struct Block {
    out: String,
    width: usize,
    colors: Palette,
}
impl Block {
    fn new(colors: Palette) -> Self {
        let width = env::var("COLUMNS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|w| *w > 0)
            .or_else(|| {
                terminal_size::terminal_size().map(|(w, _)| usize::from(w.0))
            })
            .unwrap_or(100)
            .clamp(60, 120);
        Self {
            out: String::new(),
            width,
            colors,
        }
    }
    fn blank(&mut self) {
        self.out.push('\n');
    }
    fn wrap(&self, value: &str, first: &str, next: &str) -> String {
        let value = safe(value);
        let mut out = first.to_owned();
        let mut column = first.chars().count();
        let mut content = false;
        for word in value.split_whitespace() {
            let length = word.chars().count();
            if content && column + 1 + length > self.width {
                out.push('\n');
                out.push_str(next);
                column = next.chars().count();
                content = false;
            }
            if content {
                out.push(' ');
                column += 1;
            }
            for c in word.chars() {
                if column >= self.width {
                    out.push('\n');
                    out.push_str(next);
                    column = next.chars().count();
                }
                out.push(c);
                column += 1;
            }
            content = true;
        }
        out
    }
    fn line(&mut self, value: &str, indent: usize, style: &str) {
        let prefix = " ".repeat(indent);
        let line = self.wrap(value, &prefix, &prefix);
        self.out.push_str(&self.colors.paint(&line, style));
        self.out.push('\n');
    }
    fn field(&mut self, name: &str, value: &Value, indent: usize) {
        let value = match value {
            Value::Bool(b) => {
                if *b {
                    "yes".into()
                } else {
                    "no".into()
                }
            }
            Value::Array(a) if a.is_empty() => "(empty)".into(),
            Value::Array(_) => join(value, ", "),
            _ => text(value),
        };
        self.field_text(
            name,
            if value.is_empty() { "(empty)" } else { &value },
            indent,
        );
    }
    fn field_text(&mut self, name: &str, value: &str, indent: usize) {
        let prefix =
            format!("{}{:<18} ", " ".repeat(indent), format!("{name}:"));
        let line = self.wrap(value, &prefix, &" ".repeat(prefix.len()));
        if name == "ERROR" {
            self.out.push_str(&self.colors.paint(&line, "error"));
        } else {
            let style = if name.starts_with("Unknown")
                || name.starts_with("Undecoded")
            {
                "warning"
            } else {
                "label"
            };
            self.out
                .push_str(&self.colors.paint(&line[..prefix.len()], style));
            self.out.push_str(&line[prefix.len()..]);
        }
        self.out.push('\n');
    }
    fn tree(&mut self, value: &Value, indent: usize) {
        if let Some(obj) = value.as_object() {
            for (key, value) in obj {
                if value.is_object() {
                    self.line(&format!("{}:", label(key)), indent, "");
                    self.tree(value, indent + 2);
                } else if value.is_array()
                    && array(value).iter().any(Value::is_object)
                {
                    self.line(&format!("{}:", label(key)), indent, "");
                    for (index, entry) in array(value).iter().enumerate() {
                        self.line(
                            &format!("[{}]", index + 1),
                            indent + 2,
                            "",
                        );
                        if entry.is_object() {
                            self.tree(entry, indent + 4);
                        } else {
                            self.line(&text(entry), indent + 4, "");
                        }
                    }
                } else {
                    self.field(&label(key), value, indent);
                }
            }
        }
    }
}
fn community(b: &mut Block, entry: &Value) {
    let name = strv(&entry["name"]);
    match name {
        "arp-nd" => b.field_text(
            "ARP/ND",
            &format!(
                "Router={}, Override={}, Immutable={}",
                if entry["router"] == true { "yes" } else { "no" },
                if entry["override"] == true {
                    "yes"
                } else {
                    "no"
                },
                if entry["immutable"] == true {
                    "yes"
                } else {
                    "no"
                },
            ),
            4,
        ),
        "unknown" => b.field_text(
            "Unknown community",
            &format!(
                "type {}, subtype {}; hex {}",
                entry["type"],
                entry["subtype"],
                strv(&entry["raw"])
            ),
            4,
        ),
        "mac-mobility" => b.field_text(
            "MAC mobility",
            &format!(
                "sequence {}, sticky {}",
                entry["sequence"],
                if entry["sticky"] == true { "yes" } else { "no" }
            ),
            4,
        ),
        _ => {
            let name = match name {
                "route-target" => "Route target",
                "route-origin" => "Route origin",
                "encapsulation" => "Encapsulation",
                "default-gateway" => "Default gateway",
                "router-mac" => "Router MAC",
                _ => name,
            };
            b.field(name, &entry["value"], 4);
        }
    }
}
fn attribute(b: &mut Block, entry: &Value) {
    let name = strv(&entry["name"]);
    match name {
        "as-path" | "as4-path" => {
            let parts: Vec<_> = array(&entry["segments"])
                .iter()
                .map(|seg| {
                    let (left, right) = match seg["type"].as_u64() {
                        Some(1) => ("{", "}"),
                        Some(3) => ("(", ")"),
                        Some(4) => ("[", "]"),
                        _ => ("", ""),
                    };
                    format!("{left}{}{right}", join(&seg["asns"], " "))
                })
                .collect();
            let path = if parts.is_empty() {
                "(empty)".to_owned()
            } else {
                parts.join(" ")
            };
            b.field_text(
                if name == "as-path" {
                    "AS path"
                } else {
                    "AS4 path"
                },
                &path,
                4,
            );
        }
        "origin" => b.field_text(
            "Origin",
            match entry["value"].as_u64() {
                Some(0) => "IGP",
                Some(1) => "EGP",
                Some(2) => "Incomplete",
                _ => return b.field("Origin", &entry["value"], 4),
            },
            4,
        ),
        "extended-communities" => {
            for c in array(&entry["values"]) {
                community(b, c);
            }
        }
        "mp-reach" | "mp-unreach" => {
            if let Some(raw) = entry.get("next_hop_raw") {
                b.field("Next hop (hex)", raw, 4);
            }
        }
        "pmsi-tunnel" => {
            b.line("PMSI tunnel:", 4, "");
            if entry["tunnel_type"] == 6 {
                b.field_text("Type", "Ingress Replication (6)", 6);
            } else {
                b.field("Type", &entry["tunnel_type"], 6);
            }
            if let Some(endpoint) = entry.get("endpoint") {
                b.field("Endpoint", endpoint, 6);
            } else {
                b.field("Tunnel ID (hex)", &entry["tunnel_id"], 6);
            }
            if let Some(vni) = entry.get("vni") {
                b.field("VNI", vni, 6);
            } else if let Some(label) = entry.get("mpls_label") {
                b.field("MPLS label", label, 6);
            } else {
                b.field("Raw label field", &entry["label_raw"], 6);
            }
            b.field_text(
                "Flags",
                &format!(
                    "0x{:02x}",
                    entry["tunnel_flags"].as_u64().unwrap_or(0)
                ),
                6,
            );
        }
        _ => {
            if let Some(value) = entry.get("value") {
                let title = match name {
                    "next-hop" => "Next hop".into(),
                    "local-pref" => "Local preference".into(),
                    "med" => "MED".into(),
                    "originator-id" => "Originator ID".into(),
                    _ => label(name),
                };
                b.field(&title, value, 4);
            } else if let Some(values) = entry.get("values") {
                b.field(&label(name), values, 4);
            } else {
                b.line(
                    &format!(
                        "{} (attribute {}):",
                        label(name),
                        entry["type"]
                    ),
                    4,
                    "",
                );
                let mut extra = entry.clone();
                for key in ["type", "flags", "name"] {
                    extra.as_object_mut().unwrap().remove(key);
                }
                b.tree(&extra, 6);
            }
        }
    }
}
fn route(b: &mut Block, entry: &Value) {
    let action = strv(&entry["action"]);
    let title = if let Some(kind) = entry.get("route_type") {
        let name = match kind.as_u64() {
            Some(1) => "Ethernet Auto-Discovery",
            Some(2) => "MAC/IP Advertisement",
            Some(3) => "Inclusive Multicast",
            Some(4) => "Ethernet Segment",
            Some(5) => "IP Prefix",
            _ => "Unknown",
        };
        format!("{}  EVPN type {kind} - {name}", action.to_uppercase())
    } else {
        format!(
            "{}  {}",
            action.to_uppercase(),
            family(&entry["afi"], &entry["safi"])
        )
    };
    b.line(
        &title,
        4,
        if action == "announce" {
            "announce"
        } else {
            "withdraw"
        },
    );
    for (key, name) in [
        ("rd", "RD"),
        ("prefix", "Prefix"),
        ("mac", "MAC"),
        ("ip", "IP"),
        ("originator", "Originator"),
        ("gateway", "Gateway"),
        ("next_hop", "Next hop"),
        ("vni", "VNI"),
        ("mpls_labels", "MPLS labels"),
        ("ethernet_tag", "Ethernet tag"),
        ("esi", "ESI"),
        ("path_id", "Path ID"),
    ] {
        if let Some(value) = entry.get(key) {
            b.field(name, value, 6);
        }
    }
    if entry.get("vni").is_none()
        && let Some(raw) = entry.get("label_raw")
    {
        b.field("Raw label field", raw, 6);
    }
    if let Some(raw) = entry.get("raw") {
        b.field("Undecoded (hex)", raw, 6);
    }
}
fn open_message(b: &mut Block, entry: &Value) {
    for (key, name) in [
        ("version", "Version"),
        ("asn", "ASN"),
        ("hold_time", "Hold time"),
        ("router_id", "Router ID"),
    ] {
        if key == "hold_time" {
            b.field_text(name, &format!("{} seconds", entry[key]), 4);
        } else {
            b.field(name, &entry[key], 4);
        }
    }
    for cap in array(&entry["capabilities"]) {
        let mut detail = match cap["code"].as_u64() {
            Some(1) => "Multiprotocol".into(),
            Some(2) => "Route refresh".into(),
            Some(6) => "Extended message".into(),
            Some(64) => "Graceful restart".into(),
            Some(65) => "4-octet ASN".into(),
            Some(69) => "ADD-PATH".into(),
            Some(70) => "Enhanced route refresh".into(),
            Some(71) => "Long-lived graceful restart".into(),
            Some(73) => "FQDN".into(),
            Some(76) => "Paths limit".into(),
            _ => format!("Unknown code {}", cap["code"]),
        };
        if cap.get("afi").is_some() {
            detail += &format!(" - {}", family(&cap["afi"], &cap["safi"]));
        } else if let Some(asn) = cap.get("asn") {
            detail += &format!(" - AS{asn}");
        } else if let Some(families) = cap.get("families") {
            let parts: Vec<_> = array(families)
                .iter()
                .map(|f| {
                    let mode = match f["mode"].as_u64() {
                        Some(1) => "receive".into(),
                        Some(2) => "send".into(),
                        Some(3) => "send/receive".into(),
                        _ => text(&f["mode"]),
                    };
                    format!("{} ({mode})", family(&f["afi"], &f["safi"]))
                })
                .collect();
            detail += &format!(
                " - {}",
                if parts.is_empty() {
                    "no families".into()
                } else {
                    parts.join(", ")
                }
            );
        } else if !strv(&cap["raw"]).is_empty() {
            detail += &format!(" - hex {}", strv(&cap["raw"]));
        }
        b.field_text("Capability", &detail, 4);
    }
}
fn verbose(message: &Value, colors: Palette) -> String {
    let mut b = Block::new(colors);
    let title = strv(&message["name"])
        .split('-')
        .map(label)
        .collect::<Vec<_>>()
        .join(" ");
    b.line(
        &format!(
            "{}  Frame {}  BMP {title}",
            timestamp(&message["timestamp_ns"]),
            message["frame"]
        ),
        0,
        if message["type"] == 2 {
            "withdraw"
        } else {
            "heading"
        },
    );
    b.field_text("Exporter", &endpoint(&message["source"]), 2);
    b.field_text("Collector", &endpoint(&message["destination"]), 2);
    if let Some(peer) = message.get("peer") {
        b.field_text(
            "Peer",
            &format!("{}  AS{}", strv(&peer["address"]), peer["asn"]),
            2,
        );
        b.field("Router ID", &peer["router_id"], 2);
        let mut rib = match strv(&peer["rib"]) {
            "loc-rib" => "Loc-RIB",
            "adj-rib-in" => "Adj-RIB-In",
            "adj-rib-out" => "Adj-RIB-Out",
            other => other,
        }
        .to_owned();
        if let Some(policy) = peer.get("policy") {
            rib += &format!(" ({}-policy)", strv(policy));
        }
        if peer["filtered"] == true {
            rib += " (filtered)";
        }
        b.field_text("RIB", &rib, 2);
    }
    for info in array(&message["information"]) {
        let title = info
            .get("name")
            .map(text)
            .unwrap_or_else(|| format!("Information {}", info["type"]));
        b.field(&label(&title), &info["value"], 2);
    }
    for key in [
        "local_address",
        "local_port",
        "remote_port",
        "reason",
        "fsm_event",
    ] {
        if let Some(value) = message.get(key) {
            b.field(&label(key), value, 2);
        }
    }
    for error in array(&message["errors"]) {
        b.field("ERROR", error, 2);
    }
    for (index, bgp) in array(&message["bgp"]).iter().enumerate() {
        b.blank();
        let direction = if message["type"] == 3 {
            if index == 0 { " (sent)" } else { " (received)" }
        } else {
            ""
        };
        b.line(
            &format!("BGP {}{direction}", strv(&bgp["name"])),
            2,
            "heading",
        );
        if let Some(error) = bgp.get("error") {
            b.field("ERROR", error, 4);
        }
        if let Some(open) = bgp.get("open") {
            open_message(&mut b, open);
        }
        for entry in array(&bgp["attributes"]) {
            attribute(&mut b, entry);
        }
        for eor in array(&bgp["end_of_rib"]) {
            b.field_text("End of RIB", &family(&eor["afi"], &eor["safi"]), 4);
        }
        for entry in array(&bgp["routes"]) {
            b.blank();
            route(&mut b, entry);
        }
        let mut extra = bgp.clone();
        for key in [
            "type",
            "name",
            "length",
            "open",
            "error",
            "attributes",
            "routes",
            "end_of_rib",
        ] {
            extra.as_object_mut().unwrap().remove(key);
        }
        b.tree(&extra, 4);
    }
    for key in ["statistics", "mirroring"] {
        if let Some(value) = message.get(key) {
            b.tree(&serde_json::json!({key:value}), 2);
        }
    }
    if let Some(raw) = message.get("raw") {
        b.field("Undecoded (hex)", raw, 2);
    }
    b.blank();
    b.out
}
fn route_text(route: &Value) -> String {
    let mut parts = vec![
        if route["action"] == "announce" {
            "+"
        } else {
            "-"
        }
        .to_owned(),
    ];
    if let Some(kind) = route.get("route_type") {
        parts.push(format!("EVPN{kind}({})", strv(&route["route_name"])));
    } else if route["unsupported"] == true {
        parts.push(format!(
            "unsupported-AFI/SAFI={}/{} raw={}",
            route["afi"],
            route["safi"],
            strv(&route["raw"])
        ));
    }
    for key in [
        "rd",
        "prefix",
        "mac",
        "ip",
        "originator",
        "gateway",
        "ethernet_tag",
        "path_id",
    ] {
        if let Some(value) = route.get(key) {
            parts.push(format!("{key}={}", text(value)));
        }
    }
    for key in ["vni", "mpls_labels", "next_hop"] {
        if let Some(value) = route.get(key) {
            parts.push(format!("{key}={}", join(value, ",")));
        }
    }
    if route.get("vni").is_none()
        && let Some(raw) = route.get("label_raw")
    {
        parts.push(format!("label_raw={}", join(raw, ",")));
    }
    parts.join(" ")
}
pub fn display_message(
    message: &Value,
    verbosity: u8,
    colors: Palette,
) -> String {
    if verbosity != 0 {
        let mut rendered = verbose(message, colors);
        if verbosity >= 2 {
            rendered += &serde_json::to_string_pretty(message).unwrap();
            rendered.push('\n');
        }
        return rendered;
    }
    let name = strv(&message["name"]);
    let mut parts = vec![
        timestamp(&message["timestamp_ns"]),
        format!("#{}", message["frame"]),
        endpoint(&message["source"]),
        ">".into(),
        endpoint(&message["destination"]),
        "BMP".into(),
        name.into(),
    ];
    if let Some(p) = message.get("peer") {
        parts.extend([
            format!("peer={}", strv(&p["address"])),
            format!("AS{}", p["asn"]),
            text(&p["rib"]),
        ]);
        if let Some(policy) = p.get("policy") {
            parts.push(format!("{}-policy", strv(policy)));
        }
    }
    for info in array(&message["information"]) {
        parts.push(format!(
            "{}={}",
            info.get("name")
                .map(text)
                .unwrap_or_else(|| text(&info["type"])),
            info["value"]
        ));
    }
    if let Some(reason) = message.get("reason") {
        parts.push(format!("reason={reason}"));
    }
    for error in array(&message["errors"]) {
        parts.push(format!("[ERROR: {}]", strv(error)));
    }
    if let Some(stats) = message.get("statistics") {
        parts.push(format!("counters={}", array(stats).len()));
    }
    for bgp in array(&message["bgp"]) {
        parts.push(format!("BGP-{}", strv(&bgp["name"])));
        for eor in array(&bgp["end_of_rib"]) {
            parts.push(format!("EOR={}/{}", eor["afi"], eor["safi"]));
        }
    }
    let routes: Vec<_> = routes_of(message).collect();
    parts.extend(routes.iter().take(3).map(|r| route_text(r)));
    if routes.len() > 3 {
        parts.push(format!("... +{} routes (use -v)", routes.len() - 3));
    }
    let rendered: Vec<_> = parts
        .iter()
        .enumerate()
        .map(|(index, part)| {
            let style = if index < 2 {
                "muted"
            } else if part.starts_with("[ERROR:") {
                "error"
            } else if part.starts_with("+ ") {
                "announce"
            } else if part.starts_with("- ") || part == "peer-down" {
                "withdraw"
            } else if part.starts_with("BGP-")
                || part == "BMP"
                || part == name
            {
                "heading"
            } else {
                ""
            };
            colors.paint(&safe(part), style)
        })
        .collect();
    rendered.join(" ") + "\n"
}
