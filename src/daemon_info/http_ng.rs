//! `/api/v1/status`, `/api/v1/config` and `/api/v1/filters`.
//!
//! These back `netom-cli`'s `show version` / `show status` /
//! `show running-config` / `show filters`. They are registered centrally
//! rather than by a unit, so they exist regardless of which units the
//! running config happens to define.

use axum::{extract::State, response::IntoResponse};
use serde::Serialize;

use crate::{
    daemon_info::ConfigSnapshot,
    http_ng::{Api, ApiError, ApiState},
    mem_stats,
};

pub fn register_routes(router: &mut Api) {
    router.add_get("/status", status);
    router.add_get("/config", config);
    router.add_get("/filters", filters);
}

fn json_ok<T: Serialize>(data: T) -> Result<impl IntoResponse, ApiError> {
    let body = serde_json::json!({ "data": data }).to_string();
    Ok(([("content-type", "application/json")], body))
}

//------------ /status -------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    version: &'static str,
    started: String,
    uptime_seconds: u64,
    units: Vec<crate::daemon_info::ComponentInfo>,
    targets: Vec<crate::daemon_info::ComponentInfo>,
    ingresses: IngressCounts,
    /// Absent when no `rib` unit is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    rib: Option<Vec<crate::units::rib_unit::rib::StoreCounts>>,
    memory: Memory,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IngressCounts {
    total: usize,
    connected: usize,
    disconnected: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Memory {
    /// Resident set size, absent on platforms without `/proc/self/statm`.
    #[serde(skip_serializing_if = "Option::is_none")]
    rss_bytes: Option<usize>,
    bmp_out_buffered_bytes: usize,
    bmp_out_buffered_entries: usize,
    bmp_out_clients: usize,
}

async fn status(
    state: State<ApiState>,
) -> Result<impl IntoResponse, ApiError> {
    let info = &state.daemon_info;
    let config = info.config();

    let mut total = 0;
    let mut connected = 0;
    let mut disconnected = 0;
    for (_id, ingress) in state.ingress_register.cloned_info() {
        total += 1;
        match ingress.state {
            Some(crate::ingress::register::IngressState::Connected) => {
                connected += 1
            }
            Some(crate::ingress::register::IngressState::Disconnected) => {
                disconnected += 1
            }
            _ => {}
        }
    }

    let bmp = mem_stats::bmp_out_snapshot();

    json_ok(Status {
        version: info.version(),
        started: info.started().to_rfc3339(),
        uptime_seconds: info.uptime_secs(),
        units: config.as_ref().map(|c| c.units.clone()).unwrap_or_default(),
        targets: config
            .as_ref()
            .map(|c| c.targets.clone())
            .unwrap_or_default(),
        ingresses: IngressCounts {
            total,
            connected,
            disconnected,
        },
        rib: state.store.load().as_ref().map(|rib| rib.store_counts()),
        memory: Memory {
            rss_bytes: mem_stats::read_rss_bytes(),
            bmp_out_buffered_bytes: bmp.buffered_bytes,
            bmp_out_buffered_entries: bmp.buffered_entries,
            bmp_out_clients: bmp.clients,
        },
    })
}

//------------ /config -------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigView {
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    /// The running config as TOML, with secrets redacted.
    toml: String,
    http_listen: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    roto_script: Option<String>,
}

async fn config(
    state: State<ApiState>,
) -> Result<impl IntoResponse, ApiError> {
    let snapshot = state.daemon_info.config().ok_or_else(|| {
        ApiError::ServiceUnavailable("config not loaded yet".into())
    })?;

    // An empty `toml` means redaction failed at load time. Serving the
    // rest of the snapshot while silently omitting the config text would
    // read as "this daemon has no config"; say what actually happened.
    if snapshot.toml.is_empty() {
        return Err(ApiError::InternalServerError(
            "config could not be redacted for display".into(),
        ));
    }

    let ConfigSnapshot {
        path,
        toml,
        roto_script,
        http_listen,
        ..
    } = &*snapshot;

    json_ok(ConfigView {
        path: path.as_ref().map(|p| p.display().to_string()),
        toml: toml.clone(),
        http_listen: http_listen.iter().map(|a| a.to_string()).collect(),
        roto_script: roto_script.as_ref().map(|p| p.display().to_string()),
    })
}

//------------ /filters ------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Filters {
    #[serde(skip_serializing_if = "Option::is_none")]
    roto_script: Option<String>,
    /// The Roto source, read from disk on request. Absent if no script is
    /// configured or it could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    /// The function names netom looks up in the Roto script. A script need
    /// not define all of them; an undefined entrypoint simply means that
    /// hook does no filtering.
    ///
    /// Whether a given entrypoint is actually defined is deliberately not
    /// reported: `roto::Package::get_function` is generic over each
    /// entrypoint's own signature, so probing them all would mean
    /// duplicating six type signatures here purely to render a checkmark.
    entrypoints: &'static [&'static str],
}

async fn filters(
    state: State<ApiState>,
) -> Result<impl IntoResponse, ApiError> {
    let config = state.daemon_info.config();
    let roto_script = config.as_ref().and_then(|c| c.roto_script.clone());

    // Read the script fresh rather than caching it: it is small, this
    // endpoint is not hot, and an operator asking `show filters` wants to
    // see what is on disk right now.
    let source = roto_script
        .as_ref()
        .and_then(|path| std::fs::read_to_string(path).ok());

    json_ok(Filters {
        roto_script: roto_script.as_ref().map(|p| p.display().to_string()),
        source,
        entrypoints: crate::daemon_info::ROTO_ENTRYPOINTS,
    })
}
