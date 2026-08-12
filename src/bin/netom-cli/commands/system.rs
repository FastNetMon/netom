//! `show version`, `show status`, `show running-config`, `show filters`.

use std::io::Write;

use crate::error::CliError;
use crate::render::{fmt, left, right, Col, Table};
use crate::session::Session;
use crate::tree::Captures;

pub fn exit(session: &mut Session, _c: &Captures) -> Result<(), CliError> {
    session.should_exit = true;
    Ok(())
}

pub fn version(session: &mut Session, _c: &Captures) -> Result<(), CliError> {
    if session.json {
        return session.passthrough("/api/v1/status");
    }

    let data = session.get_data("/api/v1/status")?;
    let mut out = session.writer();
    writeln!(
        out,
        "netom {}",
        data["version"].as_str().unwrap_or("unknown"),
    )?;
    writeln!(out, "netom-cli {}", env!("CARGO_PKG_VERSION"))?;
    if let Some(uptime) = data["uptimeSeconds"].as_u64() {
        writeln!(out, "Uptime {}", fmt::uptime(uptime))?;
    }
    if let Some(started) = data["started"].as_str() {
        writeln!(out, "Started {started}")?;
    }
    out.finish()?;
    Ok(())
}

static UNIT_COLS: &[Col] = &[left("Name", 16), left("Type", 14)];
static RIB_COLS: &[Col] = &[
    left("Store", 10),
    right("Prefixes", 12),
    right("IPv4", 12),
    right("IPv6", 12),
    right("Routes", 12),
];

pub fn status(session: &mut Session, _c: &Captures) -> Result<(), CliError> {
    if session.json {
        return session.passthrough("/api/v1/status");
    }

    let data = session.get_data("/api/v1/status")?;
    let mut out = session.writer();

    writeln!(
        out,
        "netom {}, up {}",
        data["version"].as_str().unwrap_or("unknown"),
        fmt::uptime(data["uptimeSeconds"].as_u64().unwrap_or(0)),
    )?;

    let ingresses = &data["ingresses"];
    writeln!(
        out,
        "Ingresses {} total, {} connected, {} disconnected",
        ingresses["total"].as_u64().unwrap_or(0),
        ingresses["connected"].as_u64().unwrap_or(0),
        ingresses["disconnected"].as_u64().unwrap_or(0),
    )?;

    let memory = &data["memory"];
    if let Some(rss) = memory["rssBytes"].as_u64() {
        write!(out, "Memory RSS {}", fmt::bytes(rss))?;
        let clients = memory["bmpOutClients"].as_u64().unwrap_or(0);
        if clients > 0 {
            write!(
                out,
                ", bmp-out {} client(s) buffering {}",
                clients,
                fmt::bytes(
                    memory["bmpOutBufferedBytes"].as_u64().unwrap_or(0)
                ),
            )?;
        }
        writeln!(out)?;
    }

    for (label, key) in [("Units", "units"), ("Targets", "targets")] {
        let Some(items) = data[key].as_array().filter(|a| !a.is_empty())
        else {
            continue;
        };
        writeln!(out, "\n{label}:")?;
        let mut table = Table::fit(&mut out, UNIT_COLS);
        for item in items {
            table.row(&[
                item["name"].as_str().unwrap_or("-"),
                item["type"].as_str().unwrap_or("-"),
            ])?;
        }
        table.finish()?;
    }

    // Absent when no rib unit is configured, which is a valid deployment.
    if let Some(stores) = data["rib"].as_array().filter(|a| !a.is_empty()) {
        writeln!(out, "\nRIB:")?;
        let mut table = Table::fit(&mut out, RIB_COLS);
        for store in stores {
            table.row(&[
                store["name"].as_str().unwrap_or("-").to_string(),
                fmt::count(store["prefixes"].as_u64().unwrap_or(0)),
                fmt::count(store["prefixesV4"].as_u64().unwrap_or(0)),
                fmt::count(store["prefixesV6"].as_u64().unwrap_or(0)),
                fmt::count(store["routes"].as_u64().unwrap_or(0)),
            ])?;
        }
        table.finish()?;
    }

    out.finish()?;
    Ok(())
}

pub fn running_config(
    session: &mut Session,
    _c: &Captures,
) -> Result<(), CliError> {
    if session.json {
        return session.passthrough("/api/v1/config");
    }

    let data = session.get_data("/api/v1/config")?;
    let mut out = session.writer();

    if let Some(path) = data["path"].as_str() {
        writeln!(out, "! Configuration file: {path}")?;
    }
    writeln!(out, "! Secrets are redacted.")?;
    writeln!(out, "!")?;
    writeln!(out, "{}", data["toml"].as_str().unwrap_or("").trim_end())?;
    out.finish()?;
    Ok(())
}

pub fn filters(session: &mut Session, _c: &Captures) -> Result<(), CliError> {
    if session.json {
        return session.passthrough("/api/v1/filters");
    }

    let data = session.get_data("/api/v1/filters")?;
    let mut out = session.writer();

    match data["rotoScript"].as_str() {
        Some(path) => writeln!(out, "Roto script: {path}")?,
        None => writeln!(out, "No Roto script configured.")?,
    }

    if let Some(entrypoints) = data["entrypoints"].as_array() {
        writeln!(
            out,
            "\nEntrypoints netom calls if the script defines them:"
        )?;
        for name in entrypoints {
            if let Some(name) = name.as_str() {
                writeln!(out, "  {name}")?;
            }
        }
    }

    if let Some(source) = data["source"].as_str() {
        writeln!(out, "\n! ---- script source ----")?;
        writeln!(out, "{}", source.trim_end())?;
    }

    out.finish()?;
    Ok(())
}
