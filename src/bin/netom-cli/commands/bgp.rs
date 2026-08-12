//! `show ip bgp summary`, `show ip bgp neighbors`, and route lookups.
//!
//! Every command splits fetching from rendering: `render_*` takes the
//! response body and a writer, so the tables can be tested against captured
//! JSON with no daemon running.

use std::io::{BufRead, BufReader, Write};

use crate::error::CliError;
use crate::render::{fmt, left, right, Col, Table};
use crate::session::Session;
use crate::tree::{Afi, Captures, PeerSource, Safi};

//------------ show ip bgp summary -------------------------------------------

static SUMMARY_COLS: &[Col] = &[
    left("Neighbor", 15),
    right("V", 1),
    right("AS", 6),
    left("Src", 3),
    right("UpdRcvd", 8),
    right("NotifRcvd", 9),
    right("Up/Down", 9),
    right("State/PfxRcd", 12),
];

pub fn summary(session: &mut Session, c: &Captures) -> Result<(), CliError> {
    if session.json {
        return session.passthrough("/api/v1/bgp/neighbors");
    }
    let body = session.get("/api/v1/bgp/neighbors")?.body_string()?;
    let mut out = session.writer();
    render_summary(&mut out, &body, c.source())?;
    out.finish()?;
    Ok(())
}

pub fn render_summary<W: Write>(
    out: &mut W,
    body: &str,
    only: Option<PeerSource>,
) -> Result<(), CliError> {
    let neighbors = data_array(body)?;

    let mut bgp_count = 0usize;
    let mut bmp_count = 0usize;
    let mut rows = Vec::new();

    for n in &neighbors {
        let source = n["source"].as_str().unwrap_or("-");
        match only {
            Some(PeerSource::Bgp) if source != "bgp" => continue,
            Some(PeerSource::Bmp) if source != "bmp" => continue,
            _ => {}
        }
        match source {
            "bgp" => bgp_count += 1,
            "bmp" => bmp_count += 1,
            _ => {}
        }

        // Cisco puts either the prefix count or, when the session is not
        // up, the state in this column — the single most useful cell in
        // the table.
        let state = n["state"].as_str().unwrap_or("-");
        let state_or_pfx = if state == "Established" {
            match n["prefixesReceived"].as_u64() {
                Some(count) => fmt::count(count),
                // Known-established but uncounted: a BMP-observed peer,
                // whose prefix count would cost a full RIB scan.
                None => "-".to_string(),
            }
        } else {
            state.to_string()
        };

        rows.push([
            n["peerAddress"].as_str().unwrap_or("-").to_string(),
            "4".to_string(),
            n["peerAsn"]
                .as_u64()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "-".into()),
            source.to_string(),
            opt_count(&n["updatesReceived"]),
            opt_count(&n["notificationsReceived"]),
            n["upSeconds"]
                .as_u64()
                .map(fmt::uptime)
                .unwrap_or_else(|| "never".into()),
            state_or_pfx,
        ]);
    }

    let mut table = Table::fit(out, SUMMARY_COLS);
    for row in &rows {
        table.row(row)?;
    }
    table.finish()?;

    writeln!(
        out,
        "\nTotal neighbors {} (bgp {}, bmp {})",
        bgp_count + bmp_count,
        bgp_count,
        bmp_count,
    )?;
    Ok(())
}

fn opt_count(value: &serde_json::Value) -> String {
    value
        .as_u64()
        .map(fmt::count)
        .unwrap_or_else(|| "-".to_string())
}

//------------ show ip bgp neighbors -----------------------------------------

pub fn neighbors(
    session: &mut Session,
    c: &Captures,
) -> Result<(), CliError> {
    let path = match c.ip() {
        Some(addr) => format!("/api/v1/bgp/neighbors/{addr}"),
        None => "/api/v1/bgp/neighbors".to_string(),
    };
    if session.json {
        return session.passthrough(&path);
    }
    let body = session.get(&path)?.body_string()?;
    let mut out = session.writer();
    render_neighbors(&mut out, &body)?;
    out.finish()?;
    Ok(())
}

pub fn render_neighbors<W: Write>(
    out: &mut W,
    body: &str,
) -> Result<(), CliError> {
    let neighbors = data_array(body)?;
    if neighbors.is_empty() {
        writeln!(out, "% No matching neighbor.")?;
        return Ok(());
    }

    for (i, n) in neighbors.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        let addr = n["peerAddress"].as_str().unwrap_or("-");
        write!(out, "BGP neighbor is {addr}")?;
        if let Some(asn) = n["peerAsn"].as_u64() {
            write!(out, ", remote AS {asn}")?;
        }
        writeln!(out)?;

        if let Some(name) = n["name"].as_str() {
            writeln!(out, "  Description: {name}")?;
        }
        if let Some(id) = n["routerId"].as_str() {
            writeln!(out, "  BGP router identifier: {id}")?;
        }

        writeln!(
            out,
            "  BGP state = {}{}",
            n["state"].as_str().unwrap_or("unknown"),
            n["upSeconds"]
                .as_u64()
                .map(|s| format!(", up for {}", fmt::uptime(s)))
                .unwrap_or_default(),
        )?;

        writeln!(
            out,
            "  Learned via: {}",
            match n["source"].as_str() {
                Some("bmp") => "BMP feed",
                _ => "direct BGP session",
            },
        )?;
        if let Some(via) = n["viaRouter"].as_str() {
            writeln!(
                out,
                "  Monitored router: {via} (ingress {})",
                n["viaIngressId"].as_u64().unwrap_or(0),
            )?;
        }
        if let Some(rib) = n["peerRibType"].as_str() {
            writeln!(out, "  RIB type: {rib}")?;
        }
        if n["configured"].as_bool().unwrap_or(false) {
            writeln!(
                out,
                "  Configured: yes{}",
                if n["connectMode"].as_bool().unwrap_or(false) {
                    " (active mode; we initiate the connection)"
                } else {
                    ""
                },
            )?;
        }
        if let Some(hold) = n["holdTimeConfigured"].as_u64() {
            // Named for what it is: routecore keeps the negotiated value
            // private, so this is our configured hold time.
            writeln!(out, "  Configured hold time: {hold} seconds")?;
        }
        if let Some(id) = n["ingressId"].as_u64() {
            writeln!(out, "  Ingress id: {id}")?;
        }

        writeln!(out, "  Message statistics:")?;
        writeln!(
            out,
            "    UPDATEs received:       {}",
            opt_count(&n["updatesReceived"]),
        )?;
        writeln!(
            out,
            "    NOTIFICATIONs received: {}",
            opt_count(&n["notificationsReceived"]),
        )?;
        writeln!(
            out,
            "    (netom is a collector: it sends no UPDATEs, and \
             KEEPALIVEs are handled inside the FSM and not counted)",
        )?;

        if n["prefixesReceived"].is_u64() || n["prefixesRejected"].is_u64() {
            writeln!(out, "  Prefix statistics:")?;
            // "Current" and not "Accepted": this is the size of the peer's
            // Adj-RIB-In right now, which is what an operator comparing it
            // against a full-table figure expects. The announcements that
            // did not change it are on the next line.
            writeln!(
                out,
                "    Current:    {}",
                opt_count(&n["prefixesReceived"]),
            )?;
            writeln!(
                out,
                "    Rejected:   {}",
                opt_count(&n["prefixesRejected"]),
            )?;
            writeln!(
                out,
                "    Duplicates: {}",
                opt_count(&n["dupPrefixAdvertisements"]),
            )?;
        }

        if let Some(err) = n["lastError"].as_str() {
            writeln!(out, "  Last error: {err}")?;
        }
    }
    Ok(())
}

//------------ show ip bgp <prefix> / table ----------------------------------

/// Build the RIB path for an address family and SAFI.
fn rib_base(afi: Afi, safi: Safi) -> &'static str {
    match (afi, safi) {
        (Afi::V4, Safi::Unicast) => "/api/v1/ribs/ipv4unicast/routes",
        (Afi::V6, Safi::Unicast) => "/api/v1/ribs/ipv6unicast/routes",
        (Afi::V4, Safi::FlowSpec) => "/api/v1/ribs/ipv4flowspec/routes",
        (Afi::V6, Safi::FlowSpec) => "/api/v1/ribs/ipv6flowspec/routes",
    }
}

pub fn routes(session: &mut Session, c: &Captures) -> Result<(), CliError> {
    let base = rib_base(c.afi(), c.safi());

    match c.prefix() {
        // A single prefix is a bounded lookup, so it can be buffered and
        // rendered as a fitted table.
        Some((addr, len)) => {
            let path = format!("{base}/{addr}/{len}");
            if session.json {
                return session.passthrough(&path);
            }
            let body = session.get(&path)?.body_string()?;
            let mut out = session.writer();
            render_prefix(&mut out, &body)?;
            out.finish()?;
            Ok(())
        }
        // A whole-table dump. The daemon auto-adds moreSpecifics to a bare
        // /routes and rejects it with 400 unless format=jsonl, so the
        // streaming path is mandatory, not an optimisation.
        None => {
            let path = format!("{base}?format=jsonl");
            if session.json {
                return session.passthrough(&path);
            }
            stream_table(session, &path)
        }
    }
}

static ROUTE_COLS: &[Col] =
    &[left("Network", 20), left("Next Hop", 20), left("Path", 20)];

/// Render the routes for one prefix.
pub fn render_prefix<W: Write>(
    out: &mut W,
    body: &str,
) -> Result<(), CliError> {
    let value: serde_json::Value = parse(body)?;
    let data = &value["data"];
    let nlri = data["nlri"].as_str().unwrap_or("-");

    let Some(routes) = data["routes"].as_array().filter(|r| !r.is_empty())
    else {
        writeln!(out, "% Network not in table.")?;
        return Ok(());
    };

    writeln!(out, "BGP routing table entry for {nlri}")?;
    let mut table = Table::fit(out, ROUTE_COLS);
    for route in routes {
        let attrs = route_attrs(route);
        table.row(&[nlri.to_string(), attrs.next_hop, attrs.as_path])?;
    }
    table.finish()?;
    Ok(())
}

struct RouteAttrs {
    next_hop: String,
    as_path: String,
}

/// Pull the display fields out of a route's `pathAttributes` array.
///
/// Attributes are a heterogeneous array of single-key objects, so this
/// looks for the keys it needs rather than assuming any order.
fn route_attrs(route: &serde_json::Value) -> RouteAttrs {
    let mut next_hop = "-".to_string();
    let mut as_path = String::new();

    if let Some(attrs) = route["pathAttributes"].as_array() {
        for attr in attrs {
            if let Some(nh) = attr["conventionalNextHop"].as_str() {
                next_hop = nh.to_string();
            }
            if let Some(nh) = attr["mpReachNlri"]["nextHop"].as_str() {
                if next_hop == "-" {
                    next_hop = nh.to_string();
                }
            }
            if let Some(path) = attr["asPath"].as_array() {
                // The API renders hops as "AS65001"; operators read plain
                // numbers in this column.
                as_path = path
                    .iter()
                    .filter_map(|h| h.as_str())
                    .map(|h| h.trim_start_matches("AS").to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
            }
        }
    }
    if as_path.is_empty() {
        as_path = "i".to_string();
    }
    RouteAttrs { next_hop, as_path }
}

/// Stream an NDJSON table, rendering rows as they arrive.
fn stream_table(session: &mut Session, path: &str) -> Result<(), CliError> {
    let mut resp = session.get(path)?;
    let mut out = session.writer();
    let mut table = Table::fixed(&mut out, ROUTE_COLS);

    let mut count = 0u64;
    {
        let reader = BufReader::new(&mut resp);
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let Ok(record) = serde_json::from_str::<serde_json::Value>(&line)
            else {
                continue;
            };
            let attrs = route_attrs(&record);
            table.row(&[
                record["prefix"].as_str().unwrap_or("-").to_string(),
                attrs.next_hop,
                attrs.as_path,
            ])?;
            count += 1;
        }
    }
    table.finish()?;
    writeln!(out, "\nTotal routes {}", fmt::count(count))?;
    out.finish()?;

    // NDJSON has no terminator, so without this a dump the daemon
    // abandoned would look exactly like a complete one.
    if resp.truncated() {
        return Err(CliError::transport(
            "Output truncated: the daemon closed the connection before the \
             dump was complete. It aborts dumps whose reader stalls, so \
             avoid paging this command.",
        ));
    }
    Ok(())
}

//------------ helpers -------------------------------------------------------

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

    const NEIGHBORS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-data/cli/bgp-neighbors.json"
    ));

    fn render(body: &str, only: Option<PeerSource>) -> String {
        let mut buf = Vec::new();
        render_summary(&mut buf, body, only).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn summary_lists_both_sources_with_a_total() {
        let out = render(NEIGHBORS, None);
        assert!(out.contains("10.1.0.1"));
        assert!(out.contains("192.0.2.7"));
        assert!(out.contains("Total neighbors 4 (bgp 3, bmp 1)"), "{out}");
    }

    /// The whole point of the FSM work: a configured peer that never came
    /// up must appear, showing why.
    #[test]
    fn summary_shows_down_peers_with_their_state() {
        let out = render(NEIGHBORS, None);
        let dead = out
            .lines()
            .find(|l| l.contains("127.0.0.9"))
            .expect("configured-but-down peer must have a row");
        assert!(dead.contains("Active"), "{dead}");
        assert!(dead.contains("never"), "{dead}");
    }

    #[test]
    fn summary_shows_prefix_count_for_established_peers() {
        let out = render(NEIGHBORS, None);
        let up = out.lines().find(|l| l.contains("10.1.0.2")).unwrap();
        assert!(up.contains("84,211"), "{up}");
        assert!(up.contains("02:14:33") || up.contains(":"), "{up}");
    }

    /// A BMP-observed peer has no cheap prefix count, so the cell must read
    /// as "unknown" rather than as zero.
    #[test]
    fn summary_does_not_report_zero_prefixes_for_bmp_peers() {
        let out = render(NEIGHBORS, None);
        let bmp = out.lines().find(|l| l.contains("192.0.2.7")).unwrap();
        assert!(bmp.trim_end().ends_with('-'), "{bmp}");
    }

    #[test]
    fn summary_can_be_narrowed_to_one_source() {
        let out = render(NEIGHBORS, Some(PeerSource::Bgp));
        assert!(!out.contains("192.0.2.7"));
        assert!(out.contains("Total neighbors 3 (bgp 3, bmp 0)"), "{out}");

        let out = render(NEIGHBORS, Some(PeerSource::Bmp));
        assert!(out.contains("192.0.2.7"));
        assert!(!out.contains("10.1.0.1 "));
    }

    #[test]
    fn summary_of_an_empty_table_still_has_a_header() {
        let out = render(r#"{"data":[]}"#, None);
        assert!(out.starts_with("Neighbor"));
        assert!(out.contains("Total neighbors 0"));
    }

    #[test]
    fn neighbor_detail_explains_the_counter_limitation() {
        let mut buf = Vec::new();
        render_neighbors(&mut buf, NEIGHBORS).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("BGP neighbor is 10.1.0.2"));
        assert!(out.contains("remote AS 65002"));
        assert!(out.contains("KEEPALIVEs"), "{out}");
        // A BMP-learned peer names the router it was seen through.
        assert!(out.contains("Monitored router: 10.99.0.1"), "{out}");
    }

    /// The prefix count is a table size and the churn is a separate
    /// counter, so an operator can see both a plausible full-view figure
    /// and the re-advertisement volume that used to be folded into it.
    #[test]
    fn neighbor_detail_separates_table_size_from_churn() {
        let mut buf = Vec::new();
        render_neighbors(&mut buf, NEIGHBORS).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Current:    84,211"), "{out}");
        assert!(out.contains("Duplicates: 2,410,338"), "{out}");
    }

    #[test]
    fn neighbor_detail_reports_no_match_clearly() {
        let mut buf = Vec::new();
        render_neighbors(&mut buf, r#"{"data":[]}"#).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "% No matching neighbor.\n"
        );
    }

    #[test]
    fn prefix_lookup_renders_each_path() {
        let body = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/cli/routes-prefix.json"
        ));
        let mut buf = Vec::new();
        render_prefix(&mut buf, body).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("BGP routing table entry for 10.0.0.0/24"));
        assert!(out.contains("192.0.2.1"));
        assert!(out.contains("192.0.2.2"));
        // AS path hops lose the API's "AS" prefix.
        assert!(out.contains("65001"));
        assert!(!out.contains("AS65001"));
    }

    #[test]
    fn prefix_lookup_reports_a_miss() {
        let mut buf = Vec::new();
        render_prefix(&mut buf, r#"{"data":{"nlri":null,"routes":[]}}"#)
            .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "% Network not in table.\n"
        );
    }

    #[test]
    fn rib_paths_cover_every_family() {
        assert_eq!(
            rib_base(Afi::V4, Safi::Unicast),
            "/api/v1/ribs/ipv4unicast/routes"
        );
        assert_eq!(
            rib_base(Afi::V6, Safi::Unicast),
            "/api/v1/ribs/ipv6unicast/routes"
        );
        assert_eq!(
            rib_base(Afi::V4, Safi::FlowSpec),
            "/api/v1/ribs/ipv4flowspec/routes"
        );
        assert_eq!(
            rib_base(Afi::V6, Safi::FlowSpec),
            "/api/v1/ribs/ipv6flowspec/routes"
        );
    }
}
