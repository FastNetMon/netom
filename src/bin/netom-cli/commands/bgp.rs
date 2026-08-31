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

/// The `filter[...]` parameters implied by the command that was typed.
///
/// Each narrowing keyword under `show ip bgp` contributes one, and the tree
/// is a path, so at most one is ever present. Brackets go on the wire raw,
/// as `show bmp routers` has always sent `filter[type]`.
fn filter_params(c: &Captures) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(source) = c.source() {
        params.push(format!("filter[ingressType]={}", source.ingress_type()));
    }
    if let Some(id) = c.ingress_id() {
        // Not a filter[...] parameter: the store matches this one directly.
        params.push(format!("ingressId={id}"));
    }
    // Only `neighbors <ip> routes` puts an address in the captures; the
    // neighbor detail command has its own handler.
    if let Some(addr) = c.ip() {
        params.push(format!("filter[peerAddress]={addr}"));
    }
    if let Some(asn) = c.asn() {
        params.push(format!("filter[originAsn]={asn}"));
    }
    if let Some(community) = c.community() {
        params.push(format!("filter[community]={community}"));
    }

    params
}

pub fn routes(session: &mut Session, c: &Captures) -> Result<(), CliError> {
    // `best` is a narrowing keyword in the tree, so it arrives here as a flag
    // and shares the whole route-filter subtree. It answers a different
    // endpoint with a different renderer, so it branches out immediately.
    if c.best() {
        return best_path(session, c);
    }

    let base = rib_base(c.afi(), c.safi());
    let filters = filter_params(c);

    // FlowSpec answers buffered JSON only -- it rejects format=jsonl with a
    // 400 -- and its rows are rules, not routes, so it needs its own path
    // and its own renderer for both the whole-table and single-prefix cases.
    if c.safi() == Safi::FlowSpec {
        let mut path = match c.prefix() {
            Some((addr, len)) => format!("{base}/{addr}/{len}"),
            None => base.to_string(),
        };
        if !filters.is_empty() {
            path.push('?');
            path.push_str(&filters.join("&"));
        }
        if session.json {
            return session.passthrough(&path);
        }
        let body = session.get(&path)?.body_string()?;
        let mut out = session.writer();
        render_flowspec(&mut out, &body)?;
        out.finish()?;
        return Ok(());
    }

    match c.prefix() {
        // A single prefix is a bounded lookup, so it can be buffered and
        // rendered as a fitted table.
        Some((addr, len)) => {
            let mut path = format!("{base}/{addr}/{len}");
            if !filters.is_empty() {
                path.push('?');
                path.push_str(&filters.join("&"));
            }
            if session.json {
                return session.passthrough(&path);
            }
            let body = session.get(&path)?.body_string()?;
            let mut out = session.writer();
            render_prefix(&mut out, &body)?;
            out.finish()?;
            Ok(())
        }
        // A whole-table dump, narrowed or not. The daemon auto-adds
        // moreSpecifics to a bare /routes and rejects it with 400 unless
        // format=jsonl, so the streaming path is mandatory, not an
        // optimisation -- a filter narrows the output, not the walk.
        None => {
            let mut query = vec![String::from("format=jsonl")];
            query.extend(filters);
            let path = format!("{base}?{}", query.join("&"));
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

//------------ show ip bgp <prefix> best / best <addr> -----------------------

/// The RIB path for the best-path endpoint of an address family.
fn best_path_base(afi: Afi) -> &'static str {
    match afi {
        Afi::V4 => "/api/v1/ribs/ipv4unicast/best-path",
        Afi::V6 => "/api/v1/ribs/ipv6unicast/best-path",
    }
}

/// `show ip bgp <prefix> best` and `show ip bgp best <addr>`.
///
/// Reached from [`routes`] when the tree set [`Flag::Best`], never registered
/// as a handler of its own.
///
/// The first is an exact-prefix decision; the second is a longest-prefix
/// match answering "which route would forward this address", so the prefix in
/// the answer need not be the one that was typed.
fn best_path(session: &mut Session, c: &Captures) -> Result<(), CliError> {
    let base = best_path_base(c.afi());
    // Whether the captured address is the thing being looked up, rather than
    // a `neighbors <ip> routes`-style peer filter.
    let mut addr_is_the_query = false;
    let mut path = match (c.prefix(), c.ip()) {
        (Some((addr, len)), _) => format!("{base}/{addr}/{len}"),
        (None, Some(addr)) => {
            addr_is_the_query = true;
            format!("{base}/{addr}")
        }
        // The tree only reaches this command through a prefix or an address
        // node, so this is unreachable in practice.
        (None, None) => {
            return Err(CliError::Usage(
                "best path needs a prefix or an address".into(),
            ))
        }
    };

    // The endpoint takes the same filters as /routes, so `source bgp` and
    // friends narrow the candidate set rather than the output.
    //
    // `filter_params` turns any captured address into `filter[peerAddress]`,
    // which is right for `neighbors <ip> routes` but wrong here: in
    // `show ip bgp best <addr>` the address is the destination being looked
    // up, not a peer. Sending both would ask for the best path to an address
    // among only the routes learned *from* that same address, which is
    // essentially always empty.
    let filters: Vec<String> = filter_params(c)
        .into_iter()
        .filter(|p| {
            !(addr_is_the_query && p.starts_with("filter[peerAddress]="))
        })
        .collect();
    if !filters.is_empty() {
        path.push('?');
        path.push_str(&filters.join("&"));
    }

    if session.json {
        return session.passthrough(&path);
    }
    let body = session.get(&path)?.body_string()?;
    let mut out = session.writer();
    render_best_path(&mut out, &body)?;
    out.finish()?;
    Ok(())
}

static BEST_PATH_COLS: &[Col] = &[
    left("", 3),
    left("Network", 20),
    left("Next Hop", 20),
    left("Path", 18),
    left("Peer", 6),
    left("Decided by", 20),
];

/// Render a best-path decision.
///
/// The winner is marked `>` the way every vendor's `show ip bgp` marks it.
/// The `Decided by` column carries the RFC 4271 section 9.1.2.2 step that put
/// each row where it is: on the best path it is the step that separated it
/// from the runner-up, on the others the step at which they lost to the best.
pub fn render_best_path<W: Write>(
    out: &mut W,
    body: &str,
) -> Result<(), CliError> {
    let value: serde_json::Value = parse(body)?;
    let data = &value["data"];
    let nlri = data["nlri"].as_str().unwrap_or("-");

    if data["best"].is_null() {
        // A prefix with no eligible route is not the same as a prefix with no
        // route at all, so say which happened.
        let ineligible =
            data["ineligible"].as_array().map(|a| a.len()).unwrap_or(0);
        if ineligible == 0 {
            writeln!(out, "% Network not in table.")?;
        } else {
            writeln!(
                out,
                "% No eligible path ({ineligible} route(s) excluded from the \
                 decision process)."
            )?;
        }
        render_ineligible(out, data)?;
        return Ok(());
    }

    match data["queryAddress"].as_str() {
        Some(addr) => {
            writeln!(out, "BGP routing table entry for {nlri} (best path for {addr})")?
        }
        None => writeln!(out, "BGP routing table entry for {nlri}")?,
    }
    if let Some(strategy) = data["strategy"].as_str() {
        if strategy != "rfc4271" {
            writeln!(out, "  decision process: {strategy}")?;
        }
    }

    let mut table = Table::fit(out, BEST_PATH_COLS);
    let mut row = |marker: &str, route: &serde_json::Value, step: &str| {
        let attrs = route_attrs(route);
        table.row(&[
            marker.to_string(),
            nlri.to_string(),
            attrs.next_hop,
            attrs.as_path,
            peer_cell(route),
            step.to_string(),
        ])
    };

    let best = &data["best"];
    row(">", best, best["decidedBy"].as_str().unwrap_or("-"))?;

    if let Some(alternatives) = data["alternatives"].as_array() {
        for alt in alternatives {
            row(" ", alt, alt["lostAt"].as_str().unwrap_or("-"))?;
        }
    }
    table.finish()?;

    // Anything the decision process could not weigh is worth showing: a
    // silently missing route looks like a RIB bug from the outside.
    render_ineligible(out, data)?;

    if let Some(assumed) = best["assumed"].as_array() {
        if !assumed.is_empty() {
            let names: Vec<&str> =
                assumed.iter().filter_map(|a| a.as_str()).collect();
            writeln!(
                out,
                "  note: best path assumed {} (not recorded for this peer)",
                names.join(", ")
            )?;
        }
    }
    Ok(())
}

/// The owning session for a row, which for an ADD-PATH path-child is the
/// parent peer rather than the store mui.
fn peer_cell(route: &serde_json::Value) -> String {
    match route["source"]["ingressId"].as_u64() {
        Some(id) => id.to_string(),
        None => "-".to_string(),
    }
}

fn render_ineligible<W: Write>(
    out: &mut W,
    data: &serde_json::Value,
) -> Result<(), CliError> {
    let Some(rows) = data["ineligible"].as_array().filter(|r| !r.is_empty())
    else {
        return Ok(());
    };
    writeln!(out, "  excluded from the decision process:")?;
    for route in rows {
        writeln!(
            out,
            "    peer {} - {}",
            peer_cell(route),
            route["reason"].as_str().unwrap_or("unknown")
        )?;
    }
    Ok(())
}

/// Stream an NDJSON table, rendering rows as they arrive.
static FLOWSPEC_COLS: &[Col] = &[
    left("Prefix", 18),
    left("Rule", 30),
    left("Actions", 20),
    left("Valid", 14),
    left("Peer", 6),
];

/// Render the FlowSpec rules in a `{"data": [ … ]}` response.
///
/// The rows are rules rather than routes: keyed on the destination prefix,
/// carrying a decoded rule and its traffic actions, and validated against
/// the unicast RIB (RFC 8955 §6). `Peer` is the owning session, so an
/// ADD-PATH peer's rules do not appear under an id `show ingresses` shows
/// as a path child.
pub fn render_flowspec<W: Write>(
    out: &mut W,
    body: &str,
) -> Result<(), CliError> {
    let rules = data_array(body)?;

    let mut count = 0u64;
    {
        let mut table = Table::fit(out, FLOWSPEC_COLS);
        for rule in &rules {
            let actions = rule["actions"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let peer = match rule["source"]["pathId"].as_u64() {
                Some(path_id) => format!(
                    "{} path {path_id}",
                    rule["source"]["ingressId"].as_u64().unwrap_or_default()
                ),
                None => rule["source"]["ingressId"]
                    .as_u64()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            };
            table.row(&[
                rule["keyPrefix"].as_str().unwrap_or("-").to_string(),
                rule["nlri"].as_str().unwrap_or("-").to_string(),
                actions,
                rule["validity"].as_str().unwrap_or("-").to_string(),
                peer,
            ])?;
            count += 1;
        }
        table.finish()?;
    }
    writeln!(out, "\nTotal rules {}", fmt::count(count))?;
    Ok(())
}

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
    use crate::tree::{Flag, Value};

    const NEIGHBORS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-data/cli/bgp-neighbors.json"
    ));

    const BEST_PATH: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-data/cli/best-path.json"
    ));

    fn best(body: &str) -> String {
        let mut buf = Vec::new();
        render_best_path(&mut buf, body).unwrap();
        String::from_utf8(buf).unwrap()
    }

    /// Only the winner is marked, the way every vendor's `show ip bgp` does.
    #[test]
    fn best_path_marks_exactly_one_winner() {
        let out = best(BEST_PATH);
        let marked: Vec<&str> =
            out.lines().filter(|l| l.trim_start().starts_with('>')).collect();
        assert_eq!(marked.len(), 1, "{out}");
        assert!(marked[0].contains("65001"), "{marked:?}");
        assert!(marked[0].contains("10.0.0.2"), "{marked:?}");
    }

    /// The point of the command: every row says which RFC 4271 step put it
    /// where it is.
    #[test]
    fn best_path_shows_the_deciding_step_for_every_row() {
        let out = best(BEST_PATH);
        assert!(out.contains("asPathLength"), "{out}");
        assert!(out.contains("med"), "{out}");
    }

    /// A route the decision process could not weigh must be visible with its
    /// reason -- silently dropping it looks like a missing route.
    #[test]
    fn best_path_lists_ineligible_routes_with_their_reason() {
        let out = best(BEST_PATH);
        assert!(out.contains("excluded from the decision process"), "{out}");
        assert!(out.contains("missingAsPath"), "{out}");
        assert!(out.contains("peer 9"), "{out}");
    }

    /// An ADD-PATH alternative is attributed to its session, not to the
    /// internal path-child mui.
    #[test]
    fn best_path_attributes_addpath_rows_to_the_session() {
        let out = best(BEST_PATH);
        let alt = out
            .lines()
            .find(|l| l.contains("65001 65002"))
            .expect("the two-hop alternative must be listed");
        // source.ingressId is 2; the child mui 4 must not be the Peer cell.
        let peer = alt.split_whitespace().last().unwrap();
        assert_eq!(peer, "asPathLength", "{alt}");
        assert!(alt.contains(" 2 "), "session id, not the child: {alt}");
    }

    /// The longest-prefix form says which address it resolved, because the
    /// answer's prefix is not the one that was typed.
    #[test]
    fn best_path_for_an_address_names_the_address() {
        let body = BEST_PATH.replace(
            r#""strategy": "rfc4271","#,
            r#""queryAddress": "198.51.100.7", "matchType": "longestMatch", "strategy": "rfc4271","#,
        );
        let out = best(&body);
        assert!(out.contains("198.51.100.0/24"), "{out}");
        assert!(out.contains("best path for 198.51.100.7"), "{out}");
    }

    /// A non-default decision process must be stated, or the output is
    /// misleading about why a route won.
    #[test]
    fn best_path_states_a_non_default_strategy() {
        // Matched on the whole line: the ineligible section's header also
        // contains the words "decision process".
        let stated = |out: &str| {
            out.lines()
                .any(|l| l.trim_start().starts_with("decision process:"))
        };

        assert!(!stated(&best(BEST_PATH)), "rfc4271 is the default");

        let body = BEST_PATH.replace(r#""rfc4271""#, r#""skipMed""#);
        let out = best(&body);
        assert!(stated(&out), "{out}");
        assert!(out.contains("decision process: skipMed"), "{out}");
    }

    #[test]
    fn best_path_reports_an_empty_table_and_an_all_ineligible_one_differently()
    {
        let empty = r#"{"data":{"nlri":"10.0.0.0/8","best":null,"alternatives":[],"ineligible":[]}}"#;
        assert!(best(empty).contains("Network not in table"));

        let excluded = r#"{"data":{"nlri":"10.0.0.0/8","best":null,"alternatives":[],
            "ineligible":[{"reason":"unknownIngress","source":{"ingressId":1},"pathAttributes":[]}]}}"#;
        let out = best(excluded);
        assert!(out.contains("No eligible path"), "{out}");
        assert!(out.contains("unknownIngress"), "{out}");
    }

    /// `best` is a narrowing keyword, so it reaches `routes` as a flag and
    /// must be dispatched there -- otherwise `show ip bgp <prefix> best` would
    /// silently run the plain route query.
    #[test]
    fn the_best_flag_is_what_selects_the_best_path_command() {
        use crate::tree::resolve;

        for line in [
            "show ip bgp 10.0.0.0/24 best",
            "show ip bgp best 10.0.0.7",
            // The filters hang off the shared subtree, so they must keep the
            // flag rather than fall back to a plain route query.
            "show ip bgp 10.0.0.0/24 best source bgp",
            "show ip bgp best 10.0.0.7 origin-as 65001",
            "show ipv6 bgp 2001:db8::/32 best",
        ] {
            let (_, captures) = resolve(line)
                .unwrap_or_else(|_| panic!("{line} must parse"));
            assert!(captures.best(), "{line} lost the Best flag");
        }

        // ... and a plain route query must not pick it up.
        let (_, captures) = resolve("show ip bgp 10.0.0.0/24").unwrap();
        assert!(!captures.best());
    }

    /// An assumption behind the winner has to surface: a ranking based on a
    /// guessed identifier should not read as certain.
    #[test]
    fn best_path_notes_assumptions_behind_the_winner() {
        let body = BEST_PATH.replace(
            r#""decidedBy": "asPathLength","#,
            r#""decidedBy": "asPathLength", "assumed": ["routeSource"],"#,
        );
        let out = best(&body);
        assert!(out.contains("assumed routeSource"), "{out}");
    }

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
    fn captures(args: Vec<Value>, flags: Vec<Flag>) -> Captures {
        Captures { args, flags }
    }

    #[test]
    fn filters_map_onto_the_query_parameters() {
        assert!(filter_params(&Captures::default()).is_empty());

        assert_eq!(
            filter_params(&captures(
                vec![],
                vec![Flag::Source(PeerSource::Bmp)]
            )),
            vec!["filter[ingressType]=bmp"]
        );
        assert_eq!(
            filter_params(&captures(
                vec![],
                vec![Flag::Source(PeerSource::Mrt)]
            )),
            vec!["filter[ingressType]=mrt"]
        );
        assert_eq!(
            filter_params(&captures(vec![Value::IngressId(5)], vec![])),
            vec!["ingressId=5"]
        );
        assert_eq!(
            filter_params(&captures(
                vec![Value::Ip("10.0.0.1".parse().unwrap())],
                vec![]
            )),
            vec!["filter[peerAddress]=10.0.0.1"]
        );
        assert_eq!(
            filter_params(&captures(vec![Value::Asn(65001)], vec![])),
            vec!["filter[originAsn]=65001"]
        );
        assert_eq!(
            filter_params(&captures(
                vec![Value::Community("65000:100".into())],
                vec![]
            )),
            vec!["filter[community]=65000:100"]
        );
    }

    /// A narrowed dump is still a dump: format=jsonl has to survive, or the
    /// daemon answers 400.
    #[test]
    fn a_filtered_table_dump_keeps_format_jsonl() {
        let mut query = vec![String::from("format=jsonl")];
        query.extend(filter_params(&captures(
            vec![],
            vec![Flag::Source(PeerSource::Bgp)],
        )));
        assert_eq!(
            format!(
                "{}?{}",
                rib_base(Afi::V4, Safi::Unicast),
                query.join("&")
            ),
            "/api/v1/ribs/ipv4unicast/routes\
             ?format=jsonl&filter[ingressType]=bgp"
                .replace(['\n', ' '], "")
        );
    }
}
