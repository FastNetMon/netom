//! EVPN route queries, independent of the daemon library.
use std::io::Write;

use crate::{
    error::CliError,
    render::{fmt, left, Col, Table},
    session::Session,
    tree::{Captures, Flag, Value},
};

/// Percent-encode a query value without adding an HTTP dependency to the CLI.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn query_path(c: &Captures) -> String {
    let mut params = Vec::new();
    for arg in &c.args {
        let (key, value) = match arg {
            Value::Rd(v) => ("rd", v.clone()),
            Value::RouteTarget(v) => ("route_target", v.clone()),
            Value::RouteType(v) => ("route_type", v.to_string()),
            Value::Vni(v) => ("vni", v.to_string()),
            Value::Prefix(ip, len) => ("prefix", format!("{ip}/{len}")),
            Value::IngressId(v) => ("ingress_id", v.to_string()),
            _ => continue,
        };
        params.push(format!("{key}={}", encode(&value)));
    }
    if c.flags.contains(&Flag::IncludeWithdrawn) {
        params.push("include_withdrawn=true".into());
    }
    let mut path = "/api/v1/ribs/l2vpnevpn/routes".to_string();
    if !params.is_empty() {
        path.push('?');
        path.push_str(&params.join("&"));
    }
    path
}

pub fn routes(session: &mut Session, c: &Captures) -> Result<(), CliError> {
    let path = query_path(c);
    if session.json {
        return session.passthrough(&path);
    }
    let body = session.get(&path)?.body_string()?;
    let mut out = session.writer();
    render(&mut out, &body, c.detail())?;
    out.finish()?;
    Ok(())
}

static COLS: &[Col] = &[
    left("Type", 4),
    left("RD", 10),
    left("MAC / Prefix", 18),
    left("VNI(s)", 6),
    left("Next hop", 15),
    left("Route targets", 13),
    left("Peer / Path", 11),
    left("State", 6),
];

fn scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "-".into(),
        serde_json::Value::String(s) => s.clone(),
        _ => v.to_string(),
    }
}
fn list(v: &serde_json::Value) -> String {
    v.as_array()
        .filter(|a| !a.is_empty())
        .map(|a| a.iter().map(scalar).collect::<Vec<_>>().join(", "))
        .unwrap_or_else(|| "-".into())
}

fn render<W: Write>(
    out: &mut W,
    body: &str,
    detail: bool,
) -> Result<(), CliError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| {
            CliError::Transport(format!("Invalid EVPN JSON: {e}"))
        })?;
    let rows = value["data"].as_array().ok_or_else(|| {
        CliError::Transport(
            "Invalid EVPN response: missing data array".into(),
        )
    })?;
    if detail {
        for row in rows {
            writeln!(out, "{}", serde_json::to_string_pretty(row).unwrap())?;
        }
    } else {
        let mut table = Table::fit(out, COLS);
        for row in rows {
            let route = &row["route"];
            let nlri = &route["nlri"];
            let overlay = &row["overlay"];
            let destination = [nlri["mac"].as_str(), nlri["prefix"].as_str()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" / ");
            let mut peer = scalar(&row["source_ingress_id"]);
            if let Some(pid) = row["path_id"].as_u64() {
                peer.push_str(&format!(" path {pid}"));
            }
            table.row(&[
                scalar(&nlri["route_type"]),
                scalar(&nlri["rd"]),
                if destination.is_empty() {
                    "-".into()
                } else {
                    destination
                },
                list(&nlri["labels"]),
                scalar(&overlay["next_hop"]),
                list(&overlay["route_targets"]),
                peer,
                match route["active"].as_bool() {
                    Some(true) => "active",
                    Some(false) => "withdrawn",
                    None => "-",
                }
                .into(),
            ])?;
        }
        table.finish()?;
    }
    writeln!(out, "\nTotal EVPN routes {}", fmt::count(rows.len() as u64))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree;
    const BODY: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-data/cli/evpn-routes.json"
    ));

    #[test]
    fn evpn_query_uses_api_names_and_encodes_ipv6() {
        let (_, captures) = tree::resolve("show evpn route-target 65000:10 route-type 5 prefix 2001:db8::/64 include-withdrawn detail").unwrap();
        let path = query_path(&captures);
        assert_eq!(path, "/api/v1/ribs/l2vpnevpn/routes?route_target=65000%3A10&route_type=5&prefix=2001%3Adb8%3A%3A%2F64&include_withdrawn=true");
        assert!(captures.detail());
        let (_, captures) =
            tree::resolve("show evpn rd 192.0.2.1:20 vni 50000").unwrap();
        assert_eq!(
            query_path(&captures),
            "/api/v1/ribs/l2vpnevpn/routes?rd=192.0.2.1%3A20&vni=50000"
        );
        let (_, captures) = tree::resolve("show evpn ingress 101").unwrap();
        assert_eq!(
            query_path(&captures),
            "/api/v1/ribs/l2vpnevpn/routes?ingress_id=101"
        );
        assert_eq!(
            query_path(&Captures::default()),
            "/api/v1/ribs/l2vpnevpn/routes"
        );
    }

    #[test]
    fn evpn_table_and_detail_preserve_overlay_information() {
        let mut out = Vec::new();
        render(&mut out, BODY, false).unwrap();
        let text = String::from_utf8(out).unwrap();
        for expected in [
            "65000:10",
            "00:11:22:33:44:55 / 10.0.0.1/32",
            "10010, 50000",
            "7 path 11",
            "2001:db8::/64",
            "withdrawn",
            "Total EVPN routes 3",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        let mut out = Vec::new();
        render(&mut out, BODY, true).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("aa:bb:cc:dd:ee:ff"));
        assert!(text.contains("\"ingress_id\": 101"));
        assert!(text.contains("\"gateway\": \"::\""));
        assert!(!text.contains("VNI(s)"));
    }

    #[test]
    fn evpn_empty_and_invalid_responses() {
        let mut out = Vec::new();
        render(&mut out, r#"{"data":[]}"#, false).unwrap();
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("Total EVPN routes 0"));
        assert!(render(&mut Vec::new(), "not json", false).is_err());
        assert!(render(&mut Vec::new(), r#"{"data":{}}"#, false).is_err());
    }

    #[test]
    fn evpn_completion_validation_and_abbreviation() {
        assert!(tree::resolve("sh ev rd 65000:1 route-ty 2 vni 100 detail")
            .is_ok());
        assert!(tree::candidates("show evpn ")
            .iter()
            .any(|c| c.insert == "route-target"));
        assert!(tree::candidates("show evpn rd 65000:1 ")
            .iter()
            .any(|c| c.insert == "vni"));
        for command in [
            "show evpn rd",
            "show evpn rd 65536:65536",
            "show evpn rd bad&x=y:1",
            "show evpn route-type 256",
            "show evpn route-type 0",
            "show evpn vni 16777216",
            "show evpn source bmp",
            "show evpn best",
        ] {
            assert!(tree::resolve(command).is_err(), "accepted {command}");
        }
        assert!(tree::all_commands().iter().any(|(c, _)| c == "show evpn"));
    }
}
