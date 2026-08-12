//! `/api/v1/bgp/neighbors` — the data behind `show ip bgp summary`.
//!
//! # Registered centrally, not by the unit
//!
//! Unlike `/api/v1/ribs/*`, these routes are registered from
//! [`Api::new`](crate::http_ng::Api::new) rather than from the `bgp-tcp-in`
//! unit. netom is most often deployed as a pure BMP collector with no
//! `bgp-tcp-in` unit at all, and registering here would make
//! `show ip bgp summary` fail on exactly those boxes. The response merges
//! BMP-monitored peers anyway, so the native-BGP half is simply empty when
//! no such unit is configured.

use std::net::IpAddr;

use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use serde::Serialize;

use crate::{
    http_ng::{Api, ApiError, ApiState},
    ingress::{
        peer_stats, register::IngressState, IngressId, IngressType,
    },
    units::bgp_tcp_in::session_status,
};

pub fn register_routes(router: &mut Api) {
    router.add_get("/bgp/neighbors", neighbors);
    router.add_get("/bgp/neighbors/{peer}", neighbor);
}

/// Where a neighbor's information comes from.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PeerSource {
    /// A session this netom terminates itself (`bgp-tcp-in`).
    Bgp,
    /// A session observed through a BMP feed from a monitored router.
    Bmp,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Neighbor {
    pub peer_address: Option<IpAddr>,
    pub peer_asn: Option<u32>,
    pub source: Option<PeerSource>,

    /// RFC 4271 FSM state. For BMP-observed peers this is derived from the
    /// ingress state — a BMP feed reports a peer as up or down and has no
    /// visibility of the monitored router's own FSM.
    pub state: Option<&'static str>,

    /// Whether the peer appears in the running config. A configured peer
    /// that has never connected still gets a row.
    pub configured: bool,
    /// Whether netom dials this peer rather than waiting for it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub connect_mode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub router_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_id: Option<IngressId>,

    /// Seconds the session has been established, absent when it is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_seconds: Option<u64>,

    /// Our *configured* hold time, not the negotiated one — routecore keeps
    /// the negotiated value private. Native BGP peers only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_time_configured: Option<u16>,

    /// UPDATEs received from this peer.
    ///
    /// There is deliberately no sent counter and no total message counter:
    /// netom is a collector and never originates UPDATEs, and KEEPALIVEs are
    /// consumed inside routecore's FSM without ever surfacing. A Cisco-style
    /// `MsgRcvd`/`MsgSent` pair here would be fiction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updates_received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notifications_received: Option<u64>,

    /// Prefixes currently in this peer's Adj-RIB-In.
    ///
    /// Only known for peers netom terminates itself. For BMP-observed peers
    /// the counter would require a full RIB scan per peer, so it is absent
    /// rather than wrong.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefixes_received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefixes_rejected: Option<u64>,

    /// The BMP router this peer was observed through.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_router: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_ingress_id: Option<IngressId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_rib_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Collect every neighbor netom knows about, from both sources.
fn collect(state: &ApiState) -> Vec<Neighbor> {
    let mut out = native_bgp_neighbors();
    out.extend(bmp_neighbors(state));
    out.sort_by_key(|n| n.peer_address);
    out
}

/// Peers of `bgp-tcp-in`, from the session registry.
fn native_bgp_neighbors() -> Vec<Neighbor> {
    let stats = peer_stats::registry();

    session_status::registry()
        .snapshot()
        .into_iter()
        .map(|(addr, status)| {
            let ingress_id = status.ingress_id();
            let snapshot =
                ingress_id.and_then(|id| stats.get(id)).map(|s| s.snapshot());

            Neighbor {
                peer_address: Some(addr),
                peer_asn: status.remote_asn(),
                source: Some(PeerSource::Bgp),
                state: Some(status.state().as_str()),
                configured: status.configured(),
                connect_mode: status.connect_mode(),
                name: status.name(),
                ingress_id,
                up_seconds: status.uptime_secs(),
                hold_time_configured: status.hold_time(),
                updates_received: Some(status.updates_received()),
                notifications_received: Some(
                    status.notifications_received(),
                ),
                prefixes_received: snapshot
                    .as_ref()
                    .map(|s| s.adj_rib_in_routes),
                prefixes_rejected: snapshot
                    .as_ref()
                    .map(|s| s.prefixes_rejected),
                last_error: status.last_error(),
                ..Default::default()
            }
        })
        .collect()
}

/// Peers observed through BMP feeds, from the ingress register.
fn bmp_neighbors(state: &ApiState) -> Vec<Neighbor> {
    let all = state.ingress_register.cloned_info();

    all.iter()
        .filter(|(_, info)| {
            info.ingress_type == Some(IngressType::BgpViaBmp)
        })
        .map(|(id, info)| {
            // The monitored router this session was seen through.
            let via = info
                .parent_ingress
                .and_then(|parent| state.ingress_register.get(parent));

            let up = info.state == Some(IngressState::Connected);

            Neighbor {
                peer_address: info.remote_addr,
                peer_asn: info.remote_asn.map(|a| a.into_u32()),
                source: Some(PeerSource::Bmp),
                // A BMP feed tells us a peer is up or down; the monitored
                // router's own FSM is not visible to us.
                state: Some(if up { "Established" } else { "Idle" }),
                configured: false,
                router_id: info.bgp_id.map(|id| {
                    format!("{}.{}.{}.{}", id[0], id[1], id[2], id[3])
                }),
                ingress_id: Some(*id),
                // `session_up_time` records when the session came up and
                // is not cleared on peer-down, so reporting it for a
                // disconnected peer would show a still-climbing uptime for
                // a session that is gone.
                up_seconds: info.session_up_time.filter(|_| up).map(|up| {
                    (chrono::Utc::now() - up).num_seconds().max(0) as u64
                }),
                via_router: via.as_ref().and_then(|v| v.remote_addr),
                via_ingress_id: info.parent_ingress,
                peer_rib_type: info
                    .peer_rib_type
                    .map(|t| format!("{t:?}")),
                ..Default::default()
            }
        })
        .collect()
}

async fn neighbors(
    state: State<ApiState>,
) -> Result<impl IntoResponse, ApiError> {
    let body = serde_json::json!({ "data": collect(&state) }).to_string();
    Ok(([("content-type", "application/json")], body))
}

async fn neighbor(
    Path(peer): Path<String>,
    state: State<ApiState>,
) -> Result<impl IntoResponse, ApiError> {
    let addr: IpAddr = peer.parse().map_err(|_| {
        ApiError::BadRequest(format!("{peer:?} is not an IP address"))
    })?;

    // A peer can legitimately appear more than once — the same address
    // monitored through two BMP routers, say — so return every match
    // rather than picking one arbitrarily.
    let matches: Vec<Neighbor> = collect(&state)
        .into_iter()
        .filter(|n| n.peer_address == Some(addr))
        .collect();

    let body = serde_json::json!({ "data": matches }).to_string();
    Ok(([("content-type", "application/json")], body))
}
