use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info, warn};

use rotonda_store::prefix_record::RouteStatus;

use crate::{
    ingress::{
        self, http_ng::QueryFilter, register::IngressState, IngressId,
        IngressInfo, IngressType,
    },
    payload::{Payload, RotondaRoute, Update},
    units::rib_unit::rib::{DumpGuard, Rib},
};
use routecore::bgp::types::AfiSafiType;

use super::{
    bmp_builder::{self, PeerInfo},
    client_state::{ClientPhase, ClientState},
    metrics::BmpTcpOutMetrics,
    status_reporter::BmpTcpOutStatusReporter,
    unit::FanInPeerDistinguisher,
};

/// Memory budget for the dump-phase route aggregator. Because the RIB walk is
/// prefix-major, a (peer, attribute-set) group's prefixes are scattered
/// across the whole walk, so groups must stay open to aggregate fully; this
/// bounds how much may be held before the fullest groups are evicted early.
/// The aggregator now holds attribute bytes via shared `Arc`s and looks up
/// peer info instead of cloning it, so the real per-group footprint is small
/// — 256 MB comfortably holds a full-table walk's groups, letting aggregation
/// reach the table's natural attribute-sharing ratio rather than being capped
/// by premature eviction. Logged `budget evictions` near zero confirm the
/// budget is not the limiting factor.
const DUMP_AGGREGATOR_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Look up the parent (router-level) IngressInfo for a peer and build a
/// JSON Admin Label string from its sysName/sysDescr.
fn resolve_admin_label(
    info: &IngressInfo,
    ingress_register: &register::Register,
    forward_router_info: bool,
) -> Option<String> {
    if !forward_router_info {
        return None;
    }
    let parent_id = info.parent_ingress?;
    let parent = ingress_register.get(parent_id)?;
    bmp_builder::build_admin_label_json(
        parent.name.as_deref(),
        parent.desc.as_deref(),
    )
}

/// Build a `PeerInfo` for re-streamed BMP output, applying both the
/// optional Admin Label TLV and the fan-in `peer_distinguisher` tag.
///
/// Centralising both steps here keeps every emitted message type (PeerUp,
/// PeerDown, RouteMonitoring, StatisticsReport, EoR) consistent on the
/// wire. The fan-in tag depends only on the peer's `parent_ingress` and
/// the configured policy, so the same upstream router always produces
/// the same tag regardless of which message type is being built.
fn build_peer_info_for_emit(
    info: &IngressInfo,
    ingress_register: &register::Register,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
) -> PeerInfo {
    let mut peer_info = PeerInfo::from_ingress_info(info);
    peer_info.admin_label =
        resolve_admin_label(info, ingress_register, forward_router_info);
    if fan_in_peer_distinguisher.is_enabled() {
        if let Some(parent_id) = info.parent_ingress {
            let tag = bmp_builder::fan_in_distinguisher_tag(parent_id);
            peer_info.apply_fan_in_distinguisher(tag);
        }
    }
    peer_info
}

/// Resolve the ingress an Update entry is *emitted as*: an ADD-PATH
/// path-child (`IngressType::BgpPath`) maps to its parent session for the
/// downstream per-peer header, carrying its RFC 7911 path id along for NLRI
/// encoding; anything else emits as itself with no path id. Memoized per
/// client (the relation is immutable per ingress id); an id not (yet) in
/// the register resolves to itself and is NOT memoized, so it re-resolves
/// once registered.
async fn resolve_emit_target(
    client: &Arc<ClientState>,
    ingress_register: &register::Register,
    ingress_id: IngressId,
) -> (IngressId, Option<u32>) {
    if let Some(target) = client.cached_emit_target(ingress_id).await {
        return target;
    }
    let target = match ingress_register.get(ingress_id) {
        Some(info) if info.ingress_type == Some(IngressType::BgpPath) => (
            info.parent_ingress.unwrap_or(ingress_id),
            info.path_id,
        ),
        Some(_) => (ingress_id, None),
        None => return (ingress_id, None),
    };
    client.cache_emit_target(ingress_id, target).await;
    target
}

/// Perform the initial table dump for a newly connected BMP client.
///
/// Uses a two-phase approach for fast dumps with many peers:
/// 1. BMP Initiation Message
/// 2. Peer Up for ALL active peers
/// 3. Single RIB walk sending all routes for all peers (interleaved)
/// 4. End-of-RIB markers for all peers
/// 5. Drains any buffered updates that arrived during dump
/// 6. Transitions client to Live phase
#[allow(clippy::too_many_arguments)]
pub async fn perform_initial_dump(
    client: &Arc<ClientState>,
    rib: &Arc<Rib>,
    ingress_register: &Arc<register::Register>,
    sys_name: &str,
    sys_descr: &str,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
    _metrics: &Arc<BmpTcpOutMetrics>,
    status_reporter: &Arc<BmpTcpOutStatusReporter>,
) -> bool {
    status_reporter.dump_started(client.remote_addr);

    // Occupy a global dump slot for the lifetime of this dump (released when
    // `_dump_permit` drops at function return). BMP collectors are trusted and
    // must be served, so we `enter()` unconditionally; the slot still counts
    // toward the global cap so the unauthenticated HTTP `?format=jsonl` dump
    // endpoint backs off (503) when many table dumps are already in flight.
    let _dump_permit = DumpGuard::enter();

    // 1. Send Initiation Message
    let init_msg = bmp_builder::build_initiation_message(sys_name, sys_descr);
    if !client.send_message(init_msg).await {
        return false;
    }

    // 2. Find active BGP peers (BgpViaBmp, Bgp, and Mrt-replayed types).
    //
    // For Bgp / BgpViaBmp we filter on IngressState::Connected so that
    // peers preserved across flaps (bmp_tcp_in::peer_down keeps the
    // register entry around for IngressId rebinding, bgp_tcp_in does the
    // same) are not enumerated — their routes have been withdrawn and
    // would otherwise show up as ZERO-ROUTE peers in the dump.
    // Mrt ingresses do not track connection state (no lifecycle), so we
    // include them unconditionally.
    let peers = {
        let mut all_peers = Vec::new();
        for ingress_type in
            [IngressType::BgpViaBmp, IngressType::Bgp, IngressType::Mrt]
        {
            let type_name = format!("{:?}", ingress_type);
            let ingress_state = match ingress_type {
                IngressType::Mrt => None,
                _ => Some(IngressState::Connected),
            };
            let filter = QueryFilter {
                ingress_type: Some(ingress_type),
                ingress_state,
                ..Default::default()
            };
            let found = ingress_register.search(filter);
            info!(
                "bmp-out dump for {}: found {} peers of type {}",
                client.remote_addr,
                found.len(),
                type_name,
            );
            all_peers.extend(found);
        }
        all_peers
    };

    info!(
        "bmp-out dump for {}: total {} peers to dump",
        client.remote_addr,
        peers.len()
    );

    // 3. Phase 1: Send Peer Up for ALL peers first
    let dump_start = Instant::now();
    let bytes_before_dump = client.bytes_sent.load(Ordering::Relaxed);

    // Build a lookup map: IngressId -> PeerInfo for quick access during RIB walk
    let mut peer_info_map: HashMap<IngressId, PeerInfo> =
        HashMap::with_capacity(peers.len());

    for peer_entry in &peers {
        let ingress_id = peer_entry.ingress_id;
        let info = &peer_entry.ingress_info;
        let peer_info = build_peer_info_for_emit(
            info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        );

        // Send Peer Up
        let peer_up_msg = bmp_builder::build_peer_up(&peer_info, true);
        if !client.send_message(peer_up_msg).await {
            return false;
        }

        client.add_known_peer(ingress_id).await;
        peer_info_map.insert(ingress_id, peer_info);
    }

    info!(
        "bmp-out dump for {}: sent Peer Up for {} peers in {:.2}s",
        client.remote_addr,
        peers.len(),
        dump_start.elapsed().as_secs_f64(),
    );

    // 4. Phase 2: Single RIB walk — send all routes for all peers interleaved
    //
    // Streaming model: a blocking thread walks the RIB (via
    // `stream_prefix_records`) and builds BMP RouteMonitoring messages,
    // pushing them into a bounded mpsc channel. The async side `recv`s from
    // the channel and forwards each message to the client's writer task.
    // Backpressure is natural — a full channel blocks the producer until the
    // consumer drains a slot, which ties the RIB-walk rate to the client's
    // TCP throughput.
    //
    // Crucially, `stream_prefix_records` holds NO crossbeam_epoch guard while
    // our closure blocks on that bounded channel: it enumerates prefix keys
    // up front and then fetches each chunk's records under short-lived guards,
    // invoking the closure with no guard live. So a slow/stalled collector can
    // no longer pin concurrent BGP/BMP churn garbage for the whole walk — peak
    // RSS no longer tracks `churn_rate × walk_wall_time`.
    //
    // Why not just collect into a `Vec` first (the previous behavior):
    // at 100M+ routes the `Vec<PrefixRecord>` alone is many GB, and that
    // allocation has to coexist with the writer's mpsc, the dump_buffer
    // accumulating live updates, and every other client's identical
    // structures. The streaming bound is "channel capacity × message
    // size" — kilobytes, not gigabytes.
    //
    // The blocking thread also owns the per-ingress route counters and
    // the skipped-unknown map; both are returned via the JoinHandle so
    // diagnostic output is unchanged.
    //
    // Channel capacity 1024 → ~150 KB worth of queued messages at the
    // average BMP RouteMon size; small enough to apply backpressure
    // quickly, large enough to smooth over short writer hiccups.
    let rib_walk_start = Instant::now();
    // Keep an Arc copy of the enumerated (Connected) peers for the post-walk
    // EoR loop and the ZERO-ROUTE diagnostic. The aggregator OWNS its own
    // mutable copy of the same map (passed by value below) so it can absorb
    // peers discovered mid-walk; this Arc is the enumerated set only.
    let peer_info_arc: Arc<HashMap<IngressId, PeerInfo>> =
        Arc::new(peer_info_map.clone());
    // Channel item is (message bytes, number of routes packed in it): with
    // NLRI aggregation one message may carry many prefixes, so the consumer
    // needs the route count to keep its progress accounting accurate.
    let (msg_tx, mut msg_rx) =
        tokio::sync::mpsc::channel::<(Vec<u8>, usize)>(1024);
    let rib_for_walk = rib.clone();
    // Captured by the blocking walk so a peer whose routes are ACTIVE in the
    // store but whose register entry was NOT enumerated (e.g. reactivated on
    // reconnect without the register state flipping back to Connected) can be
    // discovered and emitted instead of silently dropped.
    let ingress_register_for_walk = ingress_register.clone();
    let walk_handle = tokio::task::spawn_blocking(move || {
        let mut routes_per_ingress: HashMap<IngressId, usize> =
            HashMap::with_capacity(peer_info_map.len());
        let mut skipped_unknown: HashMap<IngressId, usize> = HashMap::new();
        // Peers found mid-walk via the register fallback (active routes but
        // not in the enumerated set). Returned out so the async side can send
        // their EoR markers and register them as known peers.
        let mut discovered: Vec<(IngressId, PeerInfo)> = Vec::new();
        let mut aggregator = bmp_builder::RouteAggregator::new(
            DUMP_AGGREGATOR_MAX_BYTES,
            peer_info_map,
        );
        // Walk-local memo of mui -> (emit ingress, path id): ADD-PATH
        // path-children (IngressType::BgpPath) hold RIB records under
        // their own mui but are emitted under their parent session's
        // per-peer header with the path id re-attached to the NLRI.
        // The relation is immutable per id, so one register lookup per
        // distinct mui suffices for the whole walk.
        let mut emit_targets: HashMap<IngressId, (IngressId, Option<u32>)> =
            HashMap::new();
        // Set if the consumer (client) goes away mid-walk, so we skip the
        // post-walk flush instead of re-encoding messages for a dead socket.
        let mut client_gone = false;
        let walk_result = rib_for_walk.stream_prefix_records(|pr| {
            let prefix = pr.prefix;
            for route_record in pr.meta {
                let record_mui = route_record.multi_uniq_id;
                let (ingress_id, path_id) = match emit_targets
                    .get(&record_mui)
                {
                    Some(t) => *t,
                    None => {
                        let t = match ingress_register_for_walk
                            .get(record_mui)
                        {
                            Some(info)
                                if info.ingress_type
                                    == Some(IngressType::BgpPath) =>
                            {
                                (
                                    info.parent_ingress
                                        .unwrap_or(record_mui),
                                    info.path_id,
                                )
                            }
                            _ => (record_mui, None),
                        };
                        emit_targets.insert(record_mui, t);
                        t
                    }
                };
                let mut sink = |msg: Vec<u8>, n: usize| {
                    msg_tx.blocking_send((msg, n)).is_ok()
                };
                // FIX A: include any peer that actually has active routes,
                // regardless of register state. If it wasn't enumerated, look
                // it up in the register and, if it's a real peer type, emit
                // its Peer Up now (so it precedes this peer's routes) and add
                // it to the aggregator's peer map.
                if !aggregator.has_peer(ingress_id) {
                    match ingress_register_for_walk.get(ingress_id) {
                        Some(info)
                            if matches!(
                                info.ingress_type,
                                Some(IngressType::BgpViaBmp)
                                    | Some(IngressType::Bgp)
                                    | Some(IngressType::Mrt)
                            ) =>
                        {
                            let pi = build_peer_info_for_emit(
                                &info,
                                &ingress_register_for_walk,
                                forward_router_info,
                                fan_in_peer_distinguisher,
                            );
                            let peer_up =
                                bmp_builder::build_peer_up(&pi, false);
                            if !sink(peer_up, 0) {
                                client_gone = true;
                                return false;
                            }
                            aggregator.insert_peer(ingress_id, pi.clone());
                            discovered.push((ingress_id, pi));
                        }
                        _ => {
                            *skipped_unknown
                                .entry(ingress_id)
                                .or_insert(0) += 1;
                            continue;
                        }
                    }
                }
                let pamap = &route_record.meta;
                *routes_per_ingress.entry(ingress_id).or_insert(0) += 1;
                if !aggregator.add(
                    ingress_id, path_id, prefix, pamap, &mut sink,
                ) {
                    // Consumer dropped (client disconnected). Bail out of the
                    // iteration so the walk stops promptly.
                    client_gone = true;
                    return false;
                }
            }
            true
        });
        // FlowSpec table walk (SAFI 133), sharing the same aggregator and
        // peer map as the unicast walk so a flowspec-only peer gets exactly
        // one Peer Up and the same byte budget applies. Runs before the
        // final flush; the SAFI-133 EoR markers go out with the other EoRs
        // after this walker joins.
        let fs_walk_result = if client_gone {
            Ok(0)
        } else {
            rib_for_walk.stream_flowspec_records(|pr| {
                let key_prefix = pr.prefix;
                for record in pr.meta {
                    let record_mui = record.multi_uniq_id;
                    // Same mui -> (emit ingress, path id) resolution as the
                    // unicast walk above: rules under ADD-PATH path-children
                    // emit under their parent session's per-peer header with
                    // the path id re-attached to the NLRI.
                    let (ingress_id, path_id) = match emit_targets
                        .get(&record_mui)
                    {
                        Some(t) => *t,
                        None => {
                            let t = match ingress_register_for_walk
                                .get(record_mui)
                            {
                                Some(info)
                                    if info.ingress_type
                                        == Some(IngressType::BgpPath) =>
                                {
                                    (
                                        info.parent_ingress
                                            .unwrap_or(record_mui),
                                        info.path_id,
                                    )
                                }
                                _ => (record_mui, None),
                            };
                            emit_targets.insert(record_mui, t);
                            t
                        }
                    };
                    let mut sink = |msg: Vec<u8>, n: usize| {
                        msg_tx.blocking_send((msg, n)).is_ok()
                    };
                    // Same mid-walk peer discovery as the unicast walk
                    // above (FIX A): flowspec-only peers must still get
                    // their Peer Up before their rules.
                    if !aggregator.has_peer(ingress_id) {
                        match ingress_register_for_walk.get(ingress_id) {
                            Some(info)
                                if matches!(
                                    info.ingress_type,
                                    Some(IngressType::BgpViaBmp)
                                        | Some(IngressType::Bgp)
                                        | Some(IngressType::Mrt)
                                ) =>
                            {
                                let pi = build_peer_info_for_emit(
                                    &info,
                                    &ingress_register_for_walk,
                                    forward_router_info,
                                    fan_in_peer_distinguisher,
                                );
                                let peer_up =
                                    bmp_builder::build_peer_up(&pi, false);
                                if !sink(peer_up, 0) {
                                    client_gone = true;
                                    return false;
                                }
                                aggregator
                                    .insert_peer(ingress_id, pi.clone());
                                discovered.push((ingress_id, pi));
                            }
                            _ => {
                                *skipped_unknown
                                    .entry(ingress_id)
                                    .or_insert(0) += 1;
                                continue;
                            }
                        }
                    }
                    let is_v4 = key_prefix.is_v4();
                    for rule in record.meta.iter() {
                        *routes_per_ingress
                            .entry(ingress_id)
                            .or_insert(0) += 1;
                        if !aggregator.add_flowspec(
                            ingress_id,
                            path_id,
                            is_v4,
                            &rule.nlri,
                            &rule.pamap,
                            &mut sink,
                        ) {
                            client_gone = true;
                            return false;
                        }
                    }
                }
                true
            })
        };
        let walk_result = match (walk_result, fs_walk_result) {
            (Ok(unicast), Ok(flowspec)) => Ok(unicast + flowspec),
            (Err(e), _) | (_, Err(e)) => Err(e),
        };
        // Flush whatever is still buffered into final aggregated messages,
        // unless the client already disconnected.
        if !client_gone {
            let mut sink = |msg: Vec<u8>, n: usize| {
                msg_tx.blocking_send((msg, n)).is_ok()
            };
            let _ = aggregator.flush_all(&mut sink);
        }
        let agg_stats = aggregator.stats();
        (
            routes_per_ingress,
            skipped_unknown,
            walk_result,
            agg_stats,
            discovered,
        )
    });

    const YIELD_EVERY: usize = 1024;
    const PROGRESS_LOG_EVERY: Duration = Duration::from_secs(5);
    let mut total_routes: usize = 0;
    let mut total_messages: usize = 0;
    let mut since_yield: usize = 0;
    let mut last_progress_at = rib_walk_start;
    let mut last_progress_routes: usize = 0;
    let mut client_disconnected = false;

    while let Some((msg, route_count)) = msg_rx.recv().await {
        if !client.send_message(msg).await {
            // Writer task gone — drop the receiver so the blocking
            // walker's next blocking_send fails and it can exit.
            client_disconnected = true;
            break;
        }
        total_routes += route_count;
        total_messages += 1;

        since_yield += 1;
        if since_yield >= YIELD_EVERY {
            tokio::task::yield_now().await;
            since_yield = 0;

            // Stop forwarding to a client already flagged for disconnect
            // (e.g. a dump-buffer overflow tripped in `direct_update` while
            // this walk was still streaming, or a live-path backpressure
            // failure). Bailing here lets the eager buffer release below run
            // without waiting for the next `send_message` to fail.
            if client.disconnect_pending.load(Ordering::Relaxed) {
                client_disconnected = true;
                break;
            }

            let now = Instant::now();
            if now.duration_since(last_progress_at) >= PROGRESS_LOG_EVERY {
                let interval = now.duration_since(last_progress_at);
                let delta = total_routes - last_progress_routes;
                let instant_rate = delta as f64 / interval.as_secs_f64();
                let avg_rate = total_routes as f64
                    / now.duration_since(rib_walk_start).as_secs_f64();
                let buf_len = client.dump_buffer.lock().await.len();
                let buf_bytes = client.buffered_bytes.load(Ordering::Relaxed);
                let bytes_sent_total = client
                    .bytes_sent
                    .load(Ordering::Relaxed)
                    .saturating_sub(bytes_before_dump);
                info!(
                    "bmp-out dump for {}: progress {} routes in {} msgs \
                     ({:.0} r/s now, {:.0} r/s avg), {} buffered ({:.1} MB), \
                     {:.1} MB sent",
                    client.remote_addr,
                    total_routes,
                    total_messages,
                    instant_rate,
                    avg_rate,
                    buf_len,
                    buf_bytes as f64 / (1024.0 * 1024.0),
                    bytes_sent_total as f64 / (1024.0 * 1024.0),
                );
                last_progress_at = now;
                last_progress_routes = total_routes;
            }
        }
    }
    drop(msg_rx);

    // If the client went away mid-walk (overflow flagged it for disconnect,
    // or a send failed), free the buffered live updates now. They are
    // discarded on reconnect re-dump anyway, but would otherwise stay pinned
    // across `walk_handle.await` below — the blocking walker only notices its
    // dropped receiver on its next send — and the subsequent
    // `Arc<ClientState>` teardown. On a large dump that buffer can hold
    // hundreds of MB. `request_disconnect()` first so `direct_update` stops
    // re-buffering into it before we clear.
    if client_disconnected {
        client.request_disconnect();
        client.discard_dump_buffer().await;
    }

    // Wait for the walker to finish before we proceed (it carries the
    // side-channel counters back via its JoinHandle).
    let (
        routes_per_ingress,
        skipped_unknown,
        walk_result,
        agg_stats,
        discovered,
    ) = match walk_handle.await {
        Ok(tuple) => tuple,
        Err(join_err) => {
            warn!(
                "bmp-out dump for {}: RIB walker task failed: {}",
                client.remote_addr, join_err
            );
            (HashMap::new(), HashMap::new(), Ok(0), (0, 0), Vec::new())
        }
    };
    if let Err(e) = walk_result {
        warn!(
            "bmp-out dump for {}: stream_prefix_records error: {}",
            client.remote_addr, e
        );
    }

    if client_disconnected {
        return false;
    }

    let rib_walk_elapsed = rib_walk_start.elapsed();
    let agg_ratio = if total_messages > 0 {
        total_routes as f64 / total_messages as f64
    } else {
        0.0
    };
    let (agg_groups, agg_budget_evictions) = agg_stats;
    info!(
        "bmp-out dump for {}: RIB walk sent {} routes in {} msgs \
         ({:.1} routes/msg via NLRI aggregation; {} groups, {} budget \
         evictions) in {:.2}s",
        client.remote_addr,
        total_routes,
        total_messages,
        agg_ratio,
        agg_groups,
        agg_budget_evictions,
        rib_walk_elapsed.as_secs_f64(),
    );

    // Diagnostic: per-peer breakdown of sent routes. Highlight any peer that
    // is in peer_info_map but had zero routes sent — those are the silent
    // drops we're hunting.
    let mut peer_rows: Vec<(IngressId, &PeerInfo, usize)> = peer_info_arc
        .iter()
        .map(|(id, pi)| {
            (*id, pi, routes_per_ingress.get(id).copied().unwrap_or(0))
        })
        .collect();
    peer_rows.sort_by_key(|(_, _, count)| std::cmp::Reverse(*count));
    let zero_count = peer_rows.iter().filter(|(_, _, c)| *c == 0).count();
    info!(
        "bmp-out dump for {}: per-peer RIB-walk counts: {} peers with routes, {} peers with ZERO routes",
        client.remote_addr,
        peer_rows.len() - zero_count,
        zero_count,
    );
    for (id, pi, count) in &peer_rows {
        if *count == 0 {
            info!(
                "bmp-out dump for {}: ZERO-ROUTE peer ingress_id={} {} {}",
                client.remote_addr, id, pi.peer_asn, pi.peer_address,
            );
        }
    }
    if !skipped_unknown.is_empty() {
        let total_skipped: usize = skipped_unknown.values().sum();
        info!(
            "bmp-out dump for {}: skipped {} routes across {} unknown ingress_ids (not in peer_info_map)",
            client.remote_addr,
            total_skipped,
            skipped_unknown.len(),
        );
        let mut rows: Vec<(IngressId, usize)> =
            skipped_unknown.into_iter().collect();
        rows.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        for (id, c) in rows.iter().take(20) {
            info!(
                "bmp-out dump for {}: skipped unknown ingress_id={} routes={}",
                client.remote_addr, id, c
            );
        }
    }

    // 5. Phase 3: Send End-of-RIB markers for every AFI/SAFI advertised in
    // the synthetic Peer Up OPENs. Even an empty table needs an EoR marker.
    for peer_entry in &peers {
        let ingress_id = peer_entry.ingress_id;
        let peer_info = match peer_info_arc.get(&ingress_id) {
            Some(pi) => pi,
            None => continue,
        };

        for afisafi in peer_info.supported_afisafis() {
            if let Some(msg) =
                bmp_builder::build_end_of_rib_marker(peer_info, afisafi)
            {
                if !client.send_message(msg).await {
                    return false;
                }
            }
        }
    }

    // FIX A: peers discovered mid-walk (active routes in the store but not
    // enumerated from the register). Their Peer Up was already sent inline by
    // the walk; here we register them as known peers and send their EoR
    // markers, exactly like the enumerated peers above.
    for (ingress_id, peer_info) in &discovered {
        client.add_known_peer(*ingress_id).await;
        for afisafi in peer_info.supported_afisafis() {
            if let Some(msg) =
                bmp_builder::build_end_of_rib_marker(peer_info, afisafi)
            {
                if !client.send_message(msg).await {
                    return false;
                }
            }
        }
    }

    let dump_bytes =
        client.bytes_sent.load(Ordering::Relaxed) - bytes_before_dump;
    let dump_elapsed = dump_start.elapsed();
    info!(
        "bmp-out dump for {}: dump complete, {} peers ({} discovered via walk \
         fallback), {} total routes, {:.2} MB in {:.2}s",
        client.remote_addr,
        peers.len() + discovered.len(),
        discovered.len(),
        total_routes,
        dump_bytes as f64 / (1024.0 * 1024.0),
        dump_elapsed.as_secs_f64(),
    );

    // 4. Drain the dump buffer in chunks. Holding `phase.write()` across
    // the entire drain (potentially tens of millions of updates accumulated
    // during a long RIB walk) parks `direct_update` on `phase.read()` for
    // the duration, which then parks rib's `update_data` and cascades back
    // to bmp-in stalling on its sockets — the whole pipeline freezes for
    // many minutes. Instead: take a batch, release the lock, send it;
    // re-acquire and check if more arrived. When we reacquire and find the
    // buffer empty, we transition to Live atomically (no DU can be mid-push
    // because `buffer_update_if_dumping` holds `phase.read()` across the
    // `dump_buffer.lock()` acquisition).
    loop {
        let mut phase = client.phase.write().await;
        let buffered = client.take_buffered_updates().await;
        if buffered.is_empty() {
            *phase = ClientPhase::Live;
            break;
        }
        debug!(
            "Draining batch of {} buffered updates for client {}",
            buffered.len(),
            client.remote_addr
        );
        drop(phase); // release before slow sends; new DU calls re-buffer

        for update in buffered {
            // Per-client dump task: blocking send is correct here (only this
            // client's own task is back-pressured).
            if !send_update_to_client(
                client,
                &update,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
                true,
            )
            .await
            {
                return false;
            }
        }
    }
    status_reporter.dump_completed(client.remote_addr);

    true
}

/// Convert an Update to BMP messages and send to a single client.
///
/// Returns false if the send failed (client disconnected).
///
/// `blocking` is threaded down to the per-message send: `true` for the
/// per-client dump / buffered-replay tasks, `false` for the shared live
/// `direct_update` path (which must not park the ingest pipeline on a slow
/// consumer — see [`ClientState::send_message_mode`]).
pub async fn send_update_to_client(
    client: &Arc<ClientState>,
    update: &Update,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
    blocking: bool,
) -> bool {
    match update {
        Update::Single(payload) => {
            send_payload_to_client(
                client,
                payload,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
                blocking,
            )
            .await
        }
        Update::Bulk(payloads) => {
            for payload in payloads.iter() {
                if !send_payload_to_client(
                    client,
                    payload,
                    ingress_register,
                    forward_router_info,
                    fan_in_peer_distinguisher,
                    blocking,
                )
                .await
                {
                    return false;
                }
            }
            true
        }
        Update::Withdraw(ingress_id, _afisafi) => {
            send_peer_down(
                client,
                *ingress_id,
                None,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
                blocking,
            )
            .await
        }
        Update::WithdrawBulk(entries) => {
            for (ingress_id, info) in entries.iter() {
                if !send_peer_down(
                    client,
                    *ingress_id,
                    info.as_ref(),
                    ingress_register,
                    forward_router_info,
                    fan_in_peer_distinguisher,
                    blocking,
                )
                .await
                {
                    return false;
                }
            }
            true
        }
        Update::IngressReappeared(ingress_id) => {
            send_peer_reappeared(
                client,
                *ingress_id,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
                blocking,
            )
            .await
        }
        Update::PeerStats { ingress_id, body } => {
            send_peer_stats(
                client,
                *ingress_id,
                body,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
                blocking,
            )
            .await
        }
        Update::RouteMonitoringRaw { ingress_id, body } => {
            // Fastpath: only reaches a client when the unit has
            // `fastpath` enabled — `direct_update` drops these Updates
            // (both from live forwarding and from the dump-phase buffer)
            // otherwise.
            send_raw_route_monitoring(
                client,
                *ingress_id,
                body,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
                blocking,
            )
            .await
        }
        _ => {
            // Other update types are ignored for BMP out
            true
        }
    }
}

/// Forward an upstream BMP Route Monitoring message verbatim (fastpath).
///
/// `body` is the original per-peer header + encapsulated BGP UPDATE as
/// received by bmp-tcp-in. The UPDATE bytes go out untouched;
/// `bmp_builder::build_route_monitoring_raw` re-synthesizes the per-peer
/// header so it matches the Peer Up this client was sent for `ingress_id`
/// (mirroring the original A-flag and timestamp). Lazy Peer Up and the
/// per-peer PeerInfo cache mirror `send_payload_to_client`.
async fn send_raw_route_monitoring(
    client: &Arc<ClientState>,
    ingress_id: IngressId,
    body: &bytes::Bytes,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
    blocking: bool,
) -> bool {
    // Fast path: reuse the PeerInfo cached when the Peer Up (or a prior
    // route) for this peer was sent — no register lookups per message.
    if let Some(peer_info) = client.cached_peer_info(ingress_id).await {
        return match bmp_builder::build_route_monitoring_raw(&peer_info, body)
        {
            Some(msg) => client.send_message_mode(msg, blocking).await,
            None => true, // Malformed/truncated body; drop the message
        };
    }

    // First sight of this peer on this client: ensure Peer Up goes first.
    if client.register_known_peer_if_absent(ingress_id).await {
        if let Some(info) = ingress_register.get(ingress_id) {
            let peer_info = build_peer_info_for_emit(
                &info,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
            );
            let peer_up = bmp_builder::build_peer_up(&peer_info, false);
            if !client.send_message_mode(peer_up, blocking).await {
                client.remove_known_peer(ingress_id).await;
                return false;
            }
        }
    }

    let peer_info = match ingress_register.get(ingress_id) {
        Some(info) => Arc::new(build_peer_info_for_emit(
            &info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        )),
        None => {
            // Peer is gone (e.g. just torn down); drop the message rather
            // than emit one with bogus PPH fields.
            return true;
        }
    };
    client.cache_peer_info(ingress_id, peer_info.clone()).await;

    match bmp_builder::build_route_monitoring_raw(&peer_info, body) {
        Some(msg) => client.send_message_mode(msg, blocking).await,
        None => true, // Malformed/truncated body; drop the message
    }
}

/// Forward an upstream BMP Statistics Report (RFC 7854 §4.8) to the
/// client. Ensures Peer Up has been re-streamed for this `ingress_id`
/// (lazy peer-up mirrors what `send_payload_to_client` does for Route
/// Monitoring), then re-encodes the stats body under a fresh per-peer
/// header that matches what we already sent for this peer.
async fn send_peer_stats(
    client: &Arc<ClientState>,
    ingress_id: IngressId,
    body: &bytes::Bytes,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
    blocking: bool,
) -> bool {
    if client.register_known_peer_if_absent(ingress_id).await {
        if let Some(info) = ingress_register.get(ingress_id) {
            let peer_info = build_peer_info_for_emit(
                &info,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
            );
            let peer_up = bmp_builder::build_peer_up(&peer_info, false);
            if !client.send_message_mode(peer_up, blocking).await {
                client.remove_known_peer(ingress_id).await;
                return false;
            }
        }
    }

    let peer_info = match ingress_register.get(ingress_id) {
        Some(info) => build_peer_info_for_emit(
            &info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        ),
        None => {
            // Peer is gone (e.g. just torn down); drop the stats report
            // rather than emit one with bogus PPH fields.
            return true;
        }
    };

    let msg = bmp_builder::build_statistics_report(&peer_info, body);
    client.send_message_mode(msg, blocking).await
}

/// Send a single Payload as a Route Monitoring BMP message.
async fn send_payload_to_client(
    client: &Arc<ClientState>,
    payload: &Payload,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
    blocking: bool,
) -> bool {
    // ADD-PATH path-children emit under their parent session's per-peer
    // header, with their path id re-attached to the NLRI. Everything below
    // (known_peers, PeerInfo cache, lazy Peer Up) keys on the emit id, so
    // sibling paths share one downstream peer.
    let (ingress_id, path_id) = resolve_emit_target(
        client,
        ingress_register,
        payload.ingress_id,
    )
    .await;

    // Fast path: PeerInfo is constant per peer for the session, so once it is
    // cached (Peer Up already sent, header already built) every subsequent
    // route just reuses it -- no register lookups, no IngressInfo clones, no
    // per-route known_peers write-lock.
    if let Some(peer_info) = client.cached_peer_info(ingress_id).await {
        let is_withdrawal = payload.route_status == RouteStatus::Withdrawn;
        return match bmp_builder::build_route_monitoring_from_route(
            &peer_info,
            &payload.rx_value,
            is_withdrawal,
            path_id,
        ) {
            Some(msg) => client.send_message_mode(msg, blocking).await,
            None => true, // Skip if we can't build the message
        };
    }

    // Cache miss (first route for this peer on this client). This block is the
    // legacy first-sight path verbatim -- ensure Peer Up has been sent -- and
    // is followed by caching the built PeerInfo for the fast path above.
    if client.register_known_peer_if_absent(ingress_id).await {
        if let Some(info) = ingress_register.get(ingress_id) {
            let peer_info = build_peer_info_for_emit(
                &info,
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
            );
            let peer_up = bmp_builder::build_peer_up(&peer_info, false);
            if !client.send_message_mode(peer_up, blocking).await {
                client.remove_known_peer(ingress_id).await;
                return false;
            }
        }
    }

    // Build the Route Monitoring peer header. The fan-in distinguisher tag
    // must match the Peer Up we sent for this peer, so use the same builder.
    let peer_info = Arc::new(match ingress_register.get(ingress_id) {
        Some(info) => build_peer_info_for_emit(
            &info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        ),
        None => {
            // Fall back to a default peer info. No parent_ingress is
            // available, so the fan-in branch in
            // build_peer_info_for_emit is a no-op and pd stays at zero —
            // matching the legacy behaviour for this unknown-peer edge
            // case.
            build_peer_info_for_emit(
                &IngressInfo::default(),
                ingress_register,
                forward_router_info,
                fan_in_peer_distinguisher,
            )
        }
    });

    // Cache only when the peer is actually registered, so the rare
    // route-before-register race re-resolves on the next route instead of
    // sticking with the default header.
    if ingress_register.get(ingress_id).is_some() {
        client.cache_peer_info(ingress_id, peer_info.clone()).await;
    }

    let is_withdrawal = payload.route_status == RouteStatus::Withdrawn;
    if let Some(msg) = bmp_builder::build_route_monitoring_from_route(
        &peer_info,
        &payload.rx_value,
        is_withdrawal,
        path_id,
    ) {
        client.send_message_mode(msg, blocking).await
    } else {
        true // Skip if we can't build the message
    }
}

/// Send a Peer Down notification for an ingress.
///
/// `snapshot_info` is preferred when present: producers that are about to
/// drop the entry from `ingress_register` (e.g. `bmp_tcp_in::peer_down`
/// reaping synthesized siblings) snapshot the info inline on
/// `Update::WithdrawBulk` so the lookup-after-remove race can't yield a
/// Peer Down with `IngressInfo::default()`.
async fn send_peer_down(
    client: &Arc<ClientState>,
    ingress_id: IngressId,
    snapshot_info: Option<&IngressInfo>,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
    blocking: bool,
) -> bool {
    if !client.has_known_peer(ingress_id).await {
        return true; // Client doesn't know about this peer, nothing to do
    }

    let fetched = if snapshot_info.is_none() {
        ingress_register.get(ingress_id)
    } else {
        None
    };
    let peer_info = match (snapshot_info, fetched.as_ref()) {
        (Some(info), _) => build_peer_info_for_emit(
            info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        ),
        (None, Some(info)) => build_peer_info_for_emit(
            info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        ),
        (None, None) => build_peer_info_for_emit(
            &IngressInfo::default(),
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        ),
    };

    let msg = bmp_builder::build_peer_down(&peer_info);
    let sent = client.send_message_mode(msg, blocking).await;

    client.remove_known_peer(ingress_id).await;

    sent
}

/// Handle IngressReappeared: send Peer Up for the reappeared peer.
async fn send_peer_reappeared(
    client: &Arc<ClientState>,
    ingress_id: IngressId,
    ingress_register: &Arc<register::Register>,
    forward_router_info: bool,
    fan_in_peer_distinguisher: FanInPeerDistinguisher,
    blocking: bool,
) -> bool {
    // A re-activated ADD-PATH path-child (rib re-activation emits the
    // child's mui) reappears as its parent session downstream: children
    // are never peers of their own, and a Peer Up synthesized from the
    // child's thin register entry would carry a bogus header.
    let (ingress_id, _path_id) =
        resolve_emit_target(client, ingress_register, ingress_id).await;
    if let Some(info) = ingress_register.get(ingress_id) {
        let peer_info = build_peer_info_for_emit(
            &info,
            ingress_register,
            forward_router_info,
            fan_in_peer_distinguisher,
        );

        // Only send Peer Up if this peer was not already known.
        if client.register_known_peer_if_absent(ingress_id).await {
            // Send Peer Up
            let peer_up = bmp_builder::build_peer_up(&peer_info, false);
            if !client.send_message_mode(peer_up, blocking).await {
                client.remove_known_peer(ingress_id).await;
                return false;
            }
        }
    }
    true
}

// Make register accessible from the ingress module
use crate::ingress::register;

#[cfg(test)]
mod tests {
    use super::*;
    use inetnum::asn::Asn;
    use std::net::{IpAddr, Ipv6Addr};

    /// What one emitted BMP message is, for sequence assertions.
    #[derive(Debug, PartialEq)]
    enum MsgKind {
        Initiation,
        PeerUp,
        /// Route Monitoring carrying routes: (afi, safi) of its MP_REACH,
        /// or (1, 1) for a plain IPv4 NLRI-field UPDATE.
        Route(u16, u8),
        /// End-of-RIB for (afi, safi).
        Eor(u16, u8),
    }

    fn classify(msg: &[u8]) -> MsgKind {
        match msg[5] {
            4 => MsgKind::Initiation,
            3 => MsgKind::PeerUp,
            0 => {
                // Route Monitoring: BGP UPDATE after common(6) + pph(42).
                let bgp = &msg[48..];
                let withdrawn_len =
                    u16::from_be_bytes([bgp[19], bgp[20]]) as usize;
                let pa_len = u16::from_be_bytes([bgp[21], bgp[22]]) as usize;
                let has_nlri =
                    bgp.len() > 23 + withdrawn_len + pa_len;
                if withdrawn_len == 0 && pa_len == 0 {
                    return if has_nlri {
                        MsgKind::Route(1, 1)
                    } else {
                        MsgKind::Eor(1, 1)
                    };
                }
                // Walk attributes for MP_REACH (14) / MP_UNREACH (15).
                let pas = &bgp[23 + withdrawn_len..23 + withdrawn_len + pa_len];
                let mut pos = 0;
                while pos + 2 < pas.len() {
                    let flags = pas[pos];
                    let type_code = pas[pos + 1];
                    let (attr_len, header_len) = if flags & 0x10 != 0 {
                        (
                            u16::from_be_bytes([pas[pos + 2], pas[pos + 3]])
                                as usize,
                            4,
                        )
                    } else {
                        (pas[pos + 2] as usize, 3)
                    };
                    let value = &pas[pos + header_len
                        ..(pos + header_len + attr_len).min(pas.len())];
                    if type_code == 14 {
                        return MsgKind::Route(
                            u16::from_be_bytes([value[0], value[1]]),
                            value[2],
                        );
                    }
                    if type_code == 15 {
                        let afi = u16::from_be_bytes([value[0], value[1]]);
                        let safi = value[2];
                        return if attr_len == 3 {
                            MsgKind::Eor(afi, safi)
                        } else {
                            MsgKind::Route(afi, safi)
                        };
                    }
                    pos += header_len + attr_len;
                }
                // No MP attribute: plain IPv4 unicast NLRI-field UPDATE.
                MsgKind::Route(1, 1)
            }
            other => panic!("unexpected BMP message type {other}"),
        }
    }

    /// Full dump sequence with a unicast+flowspec peer and a flowspec-only
    /// peer: Initiation -> one Peer Up per peer -> unicast routes ->
    /// flowspec routes (never mixed per UPDATE) -> 4 EoRs per peer, and
    /// the flowspec NLRI bytes round-trip verbatim.
    #[tokio::test]
    async fn dump_sequence_covers_flowspec() {
        use crate::payload::{RotondaPaMap, RotondaRoute};
        use crate::roto_runtime::Ctx;
        use rotonda_store::prefix_record::RouteStatus;
        use std::str::FromStr;
        use std::sync::Mutex;

        // {dst 10.0.1.0/24, proto =17} raw components (no length header)
        const FS_NLRI: &[u8] = &[0x01, 0x18, 10, 0, 1, 0x03, 0x81, 0x11];

        fn mk_flowspec_route(raw_components: &[u8]) -> RotondaRoute {
            let mut wire = Vec::with_capacity(raw_components.len() + 1);
            wire.push(u8::try_from(raw_components.len()).unwrap());
            wire.extend_from_slice(raw_components);
            let bytes = bytes::Bytes::from(wire);
            let mut parser = octseq::Parser::from_ref(&bytes);
            let nlri = routecore::bgp::nlri::flowspec::FlowSpecNlri::parse(
                &mut parser,
                routecore::bgp::types::Afi::Ipv4,
            )
            .unwrap();
            RotondaRoute::Ipv4FlowSpec(
                nlri.into(),
                RotondaPaMap::empty_path_attributes(),
            )
        }

        let register: Arc<register::Register> = Default::default();
        let ctx = Arc::new(Mutex::new(Ctx::empty()));
        let rib =
            Arc::new(Rib::new(register.clone(), None, ctx).unwrap());

        // Peer 1: unicast + flowspec. Peer 2: flowspec-only.
        let peer1 = register.register();
        let peer2 = register.register();
        for (peer, addr) in [(peer1, "10.9.9.1"), (peer2, "10.9.9.2")] {
            register.update_info(
                peer,
                IngressInfo::new()
                    .with_ingress_type(IngressType::BgpViaBmp)
                    .with_state(IngressState::Connected)
                    .with_remote_addr(addr.parse::<IpAddr>().unwrap())
                    .with_remote_asn(Asn::from_u32(65000))
                    // MP-BGP capability: IPv4 FlowSpec.
                    .with_remote_capabilities(vec![1, 4, 0, 1, 0, 133]),
            );
        }

        let unicast = RotondaRoute::Ipv4Unicast(
            inetnum::addr::Prefix::from_str("192.0.2.0/24")
                .unwrap()
                .try_into()
                .unwrap(),
            RotondaPaMap::empty_path_attributes(),
        );
        rib.insert(&unicast, RouteStatus::Active, 1, peer1, false, false)
            .unwrap();
        let fs_route = mk_flowspec_route(FS_NLRI);
        rib.insert(&fs_route, RouteStatus::Active, 2, peer1, false, false)
            .unwrap();
        rib.insert(&fs_route, RouteStatus::Active, 3, peer2, false, false)
            .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        let client = Arc::new(ClientState::new(
            "127.0.0.1:0".parse().unwrap(),
            tx,
            10_000,
            10 * 1024 * 1024,
        ));
        let gate = crate::comms::Gate::default();
        let metrics = Arc::new(BmpTcpOutMetrics::new(&gate));
        let status_reporter = Arc::new(BmpTcpOutStatusReporter::new(
            "test",
            metrics.clone(),
        ));

        let ok = perform_initial_dump(
            &client,
            &rib,
            &register,
            "test-sys",
            "test-descr",
            false,
            FanInPeerDistinguisher::Off,
            &metrics,
            &status_reporter,
        )
        .await;
        assert!(ok, "dump must complete");
        drop(client);

        let mut kinds = Vec::new();
        let mut flowspec_nlri_seen: Vec<Vec<u8>> = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            let kind = classify(&msg);
            if kind == MsgKind::Route(1, 133) {
                // Extract the MP_REACH NLRI: value[5..] after afi(2),
                // safi(1), nh_len(1)=0, reserved(1).
                let bgp = &msg[48..];
                let pa_len =
                    u16::from_be_bytes([bgp[21], bgp[22]]) as usize;
                let pas = &bgp[23..23 + pa_len];
                let mut pos = 0;
                while pos + 2 < pas.len() {
                    let flags = pas[pos];
                    let type_code = pas[pos + 1];
                    let (attr_len, header_len) = if flags & 0x10 != 0 {
                        (
                            u16::from_be_bytes([
                                pas[pos + 2],
                                pas[pos + 3],
                            ]) as usize,
                            4,
                        )
                    } else {
                        (pas[pos + 2] as usize, 3)
                    };
                    if type_code == 14 {
                        let value = &pas
                            [pos + header_len..pos + header_len + attr_len];
                        let mut nlri = &value[5..];
                        while !nlri.is_empty() {
                            let len = nlri[0] as usize;
                            flowspec_nlri_seen
                                .push(nlri[1..1 + len].to_vec());
                            nlri = &nlri[1 + len..];
                        }
                    }
                    pos += header_len + attr_len;
                }
            }
            kinds.push(kind);
        }

        // Initiation first.
        assert_eq!(kinds[0], MsgKind::Initiation);
        // Exactly one Peer Up per peer — the flowspec-only peer included.
        let peer_ups =
            kinds.iter().filter(|k| **k == MsgKind::PeerUp).count();
        assert_eq!(peer_ups, 2);
        // Both flowspec rules re-emitted, NLRI bytes verbatim.
        assert_eq!(flowspec_nlri_seen.len(), 2);
        assert!(flowspec_nlri_seen.iter().all(|n| n == FS_NLRI));
        // The unicast route went out, and never in a SAFI-133 UPDATE.
        assert!(kinds.contains(&MsgKind::Route(1, 1)));
        // All routes precede all EoRs; unicast routes precede flowspec.
        let last_route = kinds
            .iter()
            .rposition(|k| matches!(k, MsgKind::Route(..)))
            .unwrap();
        let first_eor = kinds
            .iter()
            .position(|k| matches!(k, MsgKind::Eor(..)))
            .unwrap();
        assert!(last_route < first_eor);
        let last_unicast_route =
            kinds.iter().rposition(|k| *k == MsgKind::Route(1, 1)).unwrap();
        let first_fs_route = kinds
            .iter()
            .position(|k| *k == MsgKind::Route(1, 133))
            .unwrap();
        assert!(last_unicast_route < first_fs_route);
        // Each peer advertised v4 FlowSpec; neither advertised v6.
        let eors: Vec<(u16, u8)> = kinds
            .iter()
            .filter_map(|k| match k {
                MsgKind::Eor(afi, safi) => Some((*afi, *safi)),
                _ => None,
            })
            .collect();
        assert_eq!(eors.len(), 4);
        assert_eq!(
            eors.iter().filter(|(_, safi)| *safi == 133).count(),
            2
        );
    }

    /// Full dump with an ADD-PATH session (two path-children holding one
    /// prefix each under their own mui) plus a plain peer: exactly one
    /// Peer Up per *session* (none for children), the session's Peer Up
    /// advertises cap 69 in both OPENs, both paths are replayed with
    /// their path ids under the parent's per-peer header, the plain
    /// peer stays path-id-free, and EoRs follow all routes.
    #[tokio::test]
    async fn dump_replays_addpath_children_under_parent_session() {
        use crate::payload::{RotondaPaMap, RotondaRoute};
        use crate::roto_runtime::Ctx;
        use bytes::Bytes;
        use rotonda_store::prefix_record::RouteStatus;
        use routecore::bgp::message::{SessionConfig, UpdateMessage};
        use routecore::bgp::nlri::afisafi::{IsPrefix, Nlri};
        use std::str::FromStr;
        use std::sync::Mutex;

        let register: Arc<register::Register> = Default::default();
        let ctx = Arc::new(Mutex::new(Ctx::empty()));
        let rib = Arc::new(Rib::new(register.clone(), None, ctx).unwrap());

        // ADD-PATH session with two path-children, plus a plain peer.
        let session = register.register();
        register.update_info(
            session,
            IngressInfo::new()
                .with_ingress_type(IngressType::BgpViaBmp)
                .with_state(IngressState::Connected)
                .with_remote_addr("10.9.9.1".parse::<IpAddr>().unwrap())
                .with_remote_asn(Asn::from_u32(65001))
                .with_addpath_families(vec![0, 1, 1, 3]),
        );
        let mut children = Vec::new();
        for path_id in [1u32, 2] {
            let child = register.register();
            register.update_info(
                child,
                IngressInfo::new()
                    .with_ingress_type(IngressType::BgpPath)
                    .with_parent_ingress(session)
                    .with_path_id(path_id)
                    .with_state(IngressState::Connected)
                    .with_remote_addr(
                        "10.9.9.1".parse::<IpAddr>().unwrap(),
                    )
                    .with_remote_asn(Asn::from_u32(65001)),
            );
            children.push(child);
        }
        let plain_peer = register.register();
        register.update_info(
            plain_peer,
            IngressInfo::new()
                .with_ingress_type(IngressType::BgpViaBmp)
                .with_state(IngressState::Connected)
                .with_remote_addr("10.9.9.2".parse::<IpAddr>().unwrap())
                .with_remote_asn(Asn::from_u32(65002)),
        );

        let addpath_prefix =
            inetnum::addr::Prefix::from_str("10.1.0.0/24").unwrap();
        let addpath_route = RotondaRoute::Ipv4Unicast(
            addpath_prefix.try_into().unwrap(),
            RotondaPaMap::empty_path_attributes(),
        );
        for child in &children {
            rib.insert(
                &addpath_route,
                RouteStatus::Active,
                1,
                *child,
                false,
                false,
            )
            .unwrap();
        }
        let plain_prefix =
            inetnum::addr::Prefix::from_str("10.2.0.0/24").unwrap();
        let plain_route = RotondaRoute::Ipv4Unicast(
            plain_prefix.try_into().unwrap(),
            RotondaPaMap::empty_path_attributes(),
        );
        rib.insert(
            &plain_route,
            RouteStatus::Active,
            1,
            plain_peer,
            false,
            false,
        )
        .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        let client = Arc::new(ClientState::new(
            "127.0.0.1:0".parse().unwrap(),
            tx,
            10_000,
            10 * 1024 * 1024,
        ));
        let gate = crate::comms::Gate::default();
        let metrics = Arc::new(BmpTcpOutMetrics::new(&gate));
        let status_reporter =
            Arc::new(BmpTcpOutStatusReporter::new("test", metrics.clone()));

        let ok = perform_initial_dump(
            &client,
            &rib,
            &register,
            "test-sys",
            "test-descr",
            false,
            FanInPeerDistinguisher::Off,
            &metrics,
            &status_reporter,
        )
        .await;
        assert!(ok, "dump must complete");
        drop(client);

        let mut kinds = Vec::new();
        let mut peer_up_cap69_counts = Vec::new();
        let mut addpath_pids: Vec<u32> = Vec::new();
        let mut plain_prefix_seen = false;
        let cap69 = [69u8, 4, 0, 1, 1, 3];
        let mut sc_addpath = SessionConfig::modern();
        sc_addpath.add_addpath_rxtx(AfiSafiType::Ipv4Unicast);
        while let Ok(msg) = rx.try_recv() {
            let kind = classify(&msg);
            if kind == MsgKind::PeerUp {
                peer_up_cap69_counts.push(
                    msg.windows(cap69.len())
                        .filter(|w| *w == cap69)
                        .count(),
                );
            }
            if kind == MsgKind::Route(1, 1) {
                let bgp = Bytes::copy_from_slice(&msg[48..]);
                // Try ADD-PATH parse first; a plain single-prefix UPDATE
                // parsed with ADD-PATH enabled cannot yield valid
                // Ipv4UnicastAddpath NLRI for our test prefix.
                let parsed_addpath =
                    UpdateMessage::from_octets(bgp.clone(), &sc_addpath)
                        .ok()
                        .and_then(|upd| {
                            upd.announcements()
                                .ok()?
                                .collect::<Result<Vec<_>, _>>()
                                .ok()
                        })
                        .filter(|anns| {
                            anns.iter().all(|n| {
                                matches!(
                                    n,
                                    Nlri::Ipv4UnicastAddpath(a)
                                        if a.prefix() == addpath_prefix
                                )
                            }) && !anns.is_empty()
                        });
                if let Some(anns) = parsed_addpath {
                    for n in anns {
                        if let Nlri::Ipv4UnicastAddpath(a) = n {
                            addpath_pids.extend(
                                IsPrefix::path_id(&a).map(|p| p.0),
                            );
                        }
                    }
                } else {
                    let upd = UpdateMessage::from_octets(
                        bgp,
                        &SessionConfig::modern(),
                    )
                    .expect("plain UPDATE must parse");
                    for n in upd.announcements().unwrap() {
                        if let Nlri::Ipv4Unicast(u) = n.unwrap() {
                            assert_eq!(u.prefix(), plain_prefix);
                            plain_prefix_seen = true;
                        }
                    }
                }
            }
            kinds.push(kind);
        }

        assert_eq!(kinds[0], MsgKind::Initiation);
        // One Peer Up per session — children never become peers.
        assert_eq!(peer_up_cap69_counts.len(), 2);
        // Exactly one of the two Peer Ups advertises cap 69, in both OPENs.
        let mut counts = peer_up_cap69_counts.clone();
        counts.sort_unstable();
        assert_eq!(
            counts,
            vec![0, 2],
            "the ADD-PATH session must advertise cap 69 in both OPENs, \
             the plain peer in neither"
        );
        // Both paths replayed with their ids; the plain route without.
        addpath_pids.sort_unstable();
        assert_eq!(addpath_pids, vec![1, 2]);
        assert!(plain_prefix_seen);
        // All routes precede all EoRs.
        let last_route = kinds
            .iter()
            .rposition(|k| matches!(k, MsgKind::Route(..)))
            .unwrap();
        let first_eor = kinds
            .iter()
            .position(|k| matches!(k, MsgKind::Eor(..)))
            .unwrap();
        assert!(last_route < first_eor);
    }

    /// Build the same peer (same peer_ip, peer_asn) attributed to two
    /// different upstream BMP routers, and assert the fan-in distinguisher
    /// stamping yields two distinct non-zero pd values when enabled, but
    /// stays at pd=0 when disabled.
    #[test]
    fn build_peer_info_stamps_pd_from_parent_ingress() {
        let register = register::Register::default();
        let parent_a = register.register();
        let parent_b = register.register();
        register.update_info(
            parent_a,
            IngressInfo::new().with_name("router-edge-1"),
        );
        register.update_info(
            parent_b,
            IngressInfo::new().with_name("router-edge-2"),
        );

        let peer_for = |parent_id| {
            IngressInfo::new()
                .with_parent_ingress(parent_id)
                .with_remote_addr(IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0x7f8, 0x6c, 0, 0, 0, 0, 0x230,
                )))
                .with_remote_asn(Asn::from_u32(6939))
        };

        let info_a = peer_for(parent_a);
        let info_b = peer_for(parent_b);

        // With fan-in enabled the two upstreams must emit different
        // non-zero distinguishers despite sharing (peer_ip, peer_asn).
        let pi_a = build_peer_info_for_emit(
            &info_a,
            &register,
            false,
            FanInPeerDistinguisher::IngressHash,
        );
        let pi_b = build_peer_info_for_emit(
            &info_b,
            &register,
            false,
            FanInPeerDistinguisher::IngressHash,
        );
        assert_ne!(pi_a.peer_distinguisher, [0u8; 8]);
        assert_ne!(pi_b.peer_distinguisher, [0u8; 8]);
        assert_ne!(pi_a.peer_distinguisher, pi_b.peer_distinguisher);

        // With fan-in disabled both fall back to legacy pd=0.
        let off_a = build_peer_info_for_emit(
            &info_a,
            &register,
            false,
            FanInPeerDistinguisher::Off,
        );
        let off_b = build_peer_info_for_emit(
            &info_b,
            &register,
            false,
            FanInPeerDistinguisher::Off,
        );
        assert_eq!(off_a.peer_distinguisher, [0u8; 8]);
        assert_eq!(off_b.peer_distinguisher, [0u8; 8]);
    }

    /// A peer with no parent_ingress (e.g. synthetic IngressInfo::default
    /// fallback paths) must leave pd unchanged — there is no upstream
    /// identity to encode.
    #[test]
    fn build_peer_info_no_parent_leaves_pd_zero() {
        let register = register::Register::default();
        let info = IngressInfo::new();
        let pi = build_peer_info_for_emit(
            &info,
            &register,
            false,
            FanInPeerDistinguisher::IngressHash,
        );
        assert_eq!(pi.peer_distinguisher, [0u8; 8]);
    }

    /// A peer that already carries a real RD (non-zero inbound
    /// distinguisher, e.g. a VPN peer per RFC 7854 §4.2) must pass
    /// through unmodified even when fan-in stamping is on.
    #[test]
    fn build_peer_info_preserves_real_rd() {
        let register = register::Register::default();
        let parent = register.register();
        let real_rd = [0u8, 1, 0, 0xfd, 0xe9, 0, 0, 7];
        let info = IngressInfo::new()
            .with_parent_ingress(parent)
            .with_distinguisher(real_rd);
        let pi = build_peer_info_for_emit(
            &info,
            &register,
            false,
            FanInPeerDistinguisher::IngressHash,
        );
        assert_eq!(pi.peer_distinguisher, real_rd);
    }
}
