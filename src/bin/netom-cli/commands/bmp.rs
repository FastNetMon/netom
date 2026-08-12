//! `show bmp routers`, `show bmp router <id>`, `show ingresses`.

use std::io::Write;

use crate::error::CliError;
use crate::render::{fmt, left, right, Col, Table};
use crate::session::Session;
use crate::tree::Captures;

static ROUTER_COLS: &[Col] = &[
    right("Id", 4),
    left("Router", 15),
    left("Name", 20),
    left("State", 12),
    right("Peers", 6),
];

pub fn routers(session: &mut Session, _c: &Captures) -> Result<(), CliError> {
    let path = "/api/v1/ingresses?filter[type]=bmp";
    if session.json {
        return session.passthrough(path);
    }
    let routers = session.get(path)?.body_string()?;
    // Peer counts come from the full registry: a BMP router's sessions are
    // the ingresses whose parent is that router.
    let all = session.get("/api/v1/ingresses")?.body_string()?;

    let mut out = session.writer();
    render_routers(&mut out, &routers, &all)?;
    out.finish()?;
    Ok(())
}

pub fn render_routers<W: Write>(
    out: &mut W,
    routers: &str,
    all: &str,
) -> Result<(), CliError> {
    let routers = data_array(routers)?;
    let all = data_array(all)?;

    let mut table = Table::fit(out, ROUTER_COLS);
    for router in &routers {
        let id = router["id"].as_u64().unwrap_or(0);
        let peers = all
            .iter()
            .filter(|i| {
                i["parent_ingress"].as_u64() == Some(id)
                    && i["ingress_type"].as_str() == Some("bgpViaBmp")
            })
            .count();
        table.row(&[
            id.to_string(),
            router["remote_addr"].as_str().unwrap_or("-").to_string(),
            router["name"].as_str().unwrap_or("-").to_string(),
            router["state"].as_str().unwrap_or("-").to_string(),
            peers.to_string(),
        ])?;
    }
    table.finish()?;

    writeln!(out, "\nTotal routers {}", routers.len())?;
    Ok(())
}

static PEER_COLS: &[Col] = &[
    right("Id", 4),
    left("Neighbor", 15),
    right("AS", 6),
    left("State", 12),
    left("RibType", 8),
    right("Up/Down", 9),
];

pub fn router(session: &mut Session, c: &Captures) -> Result<(), CliError> {
    let Some(id) = c.ingress_id() else {
        return Err(CliError::usage("% Missing router ingress id."));
    };
    if session.json {
        return session.passthrough(&format!("/api/v1/ingresses/{id}"));
    }
    let router = session.get(&format!("/api/v1/ingresses/{id}"))?.body_string()?;
    let all = session.get("/api/v1/ingresses")?.body_string()?;

    let mut out = session.writer();
    render_router(&mut out, id, &router, &all)?;
    out.finish()?;
    Ok(())
}

pub fn render_router<W: Write>(
    out: &mut W,
    id: u32,
    router: &str,
    all: &str,
) -> Result<(), CliError> {
    let router = parse(router)?;
    let router = &router["data"];
    if router.is_null() {
        writeln!(out, "% No ingress with id {id}.")?;
        return Ok(());
    }
    if router["ingress_type"].as_str() != Some("bmp") {
        writeln!(
            out,
            "% Ingress {id} is a {}, not a BMP router.",
            router["ingress_type"].as_str().unwrap_or("unknown"),
        )?;
        return Ok(());
    }

    writeln!(
        out,
        "BMP router {} (ingress {id})",
        router["remote_addr"].as_str().unwrap_or("-"),
    )?;
    if let Some(name) = router["name"].as_str() {
        writeln!(out, "  Name: {name}")?;
    }
    if let Some(state) = router["state"].as_str() {
        writeln!(out, "  State: {state}")?;
    }
    writeln!(out)?;

    let all = data_array(all)?;
    let mut table = Table::fit(out, PEER_COLS);
    let mut count = 0;
    for peer in all.iter().filter(|i| {
        i["parent_ingress"].as_u64() == Some(id as u64)
            && i["ingress_type"].as_str() == Some("bgpViaBmp")
    }) {
        count += 1;
        table.row(&[
            peer["id"].as_u64().unwrap_or(0).to_string(),
            peer["remote_addr"].as_str().unwrap_or("-").to_string(),
            peer["remote_asn"]
                .as_u64()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "-".into()),
            peer["state"].as_str().unwrap_or("-").to_string(),
            peer["peer_rib_type"].as_str().unwrap_or("-").to_string(),
            uptime_from(&peer["session_up_time"]),
        ])?;
    }
    table.finish()?;
    writeln!(out, "\nTotal neighbors {count}")?;
    Ok(())
}

static INGRESS_COLS: &[Col] = &[
    right("Id", 4),
    left("Type", 11),
    right("Parent", 6),
    left("Address", 15),
    right("AS", 6),
    left("State", 12),
];

pub fn ingresses(
    session: &mut Session,
    _c: &Captures,
) -> Result<(), CliError> {
    let path = "/api/v1/ingresses";
    if session.json {
        return session.passthrough(path);
    }
    let body = session.get(path)?.body_string()?;
    let mut out = session.writer();
    render_ingresses(&mut out, &body)?;
    out.finish()?;
    Ok(())
}

pub fn render_ingresses<W: Write>(
    out: &mut W,
    body: &str,
) -> Result<(), CliError> {
    let all = data_array(body)?;
    let mut table = Table::fit(out, INGRESS_COLS);
    for i in &all {
        table.row(&[
            i["id"].as_u64().unwrap_or(0).to_string(),
            i["ingress_type"].as_str().unwrap_or("-").to_string(),
            i["parent_ingress"]
                .as_u64()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into()),
            i["remote_addr"].as_str().unwrap_or("-").to_string(),
            i["remote_asn"]
                .as_u64()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "-".into()),
            i["state"].as_str().unwrap_or("-").to_string(),
        ])?;
    }
    table.finish()?;
    writeln!(out, "\nTotal ingresses {}", all.len())?;
    Ok(())
}

//------------ helpers -------------------------------------------------------

/// Render an RFC 3339 timestamp as an elapsed time.
fn uptime_from(value: &serde_json::Value) -> String {
    let Some(text) = value.as_str() else {
        return "never".to_string();
    };
    match chrono::DateTime::parse_from_rfc3339(text) {
        Ok(when) => {
            let secs = (chrono::Utc::now()
                - when.with_timezone(&chrono::Utc))
            .num_seconds()
            .max(0) as u64;
            fmt::uptime(secs)
        }
        Err(_) => "-".to_string(),
    }
}

fn parse(body: &str) -> Result<serde_json::Value, CliError> {
    serde_json::from_str(body)
        .map_err(|e| CliError::transport(format!("Malformed JSON: {e}")))
}

fn data_array(body: &str) -> Result<Vec<serde_json::Value>, CliError> {
    let value = parse(body)?;
    Ok(value["data"].as_array().cloned().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INGRESSES: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-data/cli/ingresses.json"
    ));

    fn bmp_only() -> String {
        let all = data_array(INGRESSES).unwrap();
        let routers: Vec<_> = all
            .into_iter()
            .filter(|i| i["ingress_type"].as_str() == Some("bmp"))
            .collect();
        serde_json::json!({ "data": routers }).to_string()
    }

    #[test]
    fn routers_are_listed_with_their_peer_counts() {
        let mut buf = Vec::new();
        render_routers(&mut buf, &bmp_only(), INGRESSES).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let row = out.lines().find(|l| l.contains("10.99.0.1")).unwrap();
        // Two bgpViaBmp children hang off this router; the bgpPath
        // grandchildren must not be counted as peers.
        assert!(row.trim_end().ends_with('2'), "{row}");
        assert!(out.contains("Total routers 1"));
    }

    #[test]
    fn router_detail_lists_its_neighbors() {
        let mut buf = Vec::new();
        render_router(&mut buf, 2, &router_json(), INGRESSES).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("BMP router 10.99.0.1 (ingress 2)"));
        assert!(out.contains("192.0.2.7"));
        assert!(out.contains("Total neighbors 2"), "{out}");
    }

    fn router_json() -> String {
        let all = data_array(INGRESSES).unwrap();
        let router = all
            .into_iter()
            .find(|i| i["id"].as_u64() == Some(2))
            .unwrap();
        serde_json::json!({ "data": router }).to_string()
    }

    #[test]
    fn router_detail_rejects_a_non_bmp_ingress() {
        let all = data_array(INGRESSES).unwrap();
        let peer = all
            .into_iter()
            .find(|i| i["ingress_type"].as_str() == Some("bgpViaBmp"))
            .unwrap();
        let body = serde_json::json!({ "data": peer }).to_string();

        let mut buf = Vec::new();
        render_router(&mut buf, 3, &body, INGRESSES).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("not a BMP router"), "{out}");
    }

    #[test]
    fn router_detail_reports_an_unknown_id() {
        let mut buf = Vec::new();
        render_router(&mut buf, 99, r#"{"data":null}"#, INGRESSES).unwrap();
        assert!(String::from_utf8(buf)
            .unwrap()
            .contains("No ingress with id 99"));
    }

    #[test]
    fn ingresses_are_listed_with_their_parents() {
        let mut buf = Vec::new();
        render_ingresses(&mut buf, INGRESSES).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("bgpViaBmp"));
        assert!(out.contains("bgpPath"));
        assert!(out.contains("Total ingresses 5"), "{out}");
    }

    #[test]
    fn a_missing_timestamp_reads_as_never() {
        assert_eq!(uptime_from(&serde_json::Value::Null), "never");
    }
}
