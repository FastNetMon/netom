//! Active (outbound) BGP session establishment.
//!
//! This unit is passive at the socket layer only: everything above the
//! socket — `handle_connection()` and the routecore FSM it drives — is
//! direction-agnostic, and for an exactly configured peer the FSM already
//! sends the OPEN itself as soon as the connection is up (RFC 4271 section
//! 8.2.2, `Active` + `TcpConnectionConfirmed` with DelayOpen disabled).
//!
//! So "active mode" is only about who opens the TCP connection. This module
//! dials peers configured with `connect = true` and hands the resulting
//! stream to the very same session machinery the listener uses. The FSM's
//! own ConnectRetryTimer is not involved: routecore expects its owner to do
//! the connecting (its `Idle`/`ManualStart` arm logs "waiting for an actively
//! established TCP stream"), so the retry loop lives here.
//!
//! The listener keeps accepting connections from these peers, so whichever
//! side connects first wins. If both connect at once, the collision
//! resolution in `router_handler` (keyed on the negotiated address + ASN)
//! tears one of the two down.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use log::{debug, warn};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::common::status_reporter::Chainable;
use crate::comms::Gate;
use crate::ingress;
use crate::ingress::peer_stats::BgpPeerStatsRegistry;
use crate::roto_runtime::Ctx;

use super::peer_config::{PeerConfig, PrefixOrExact};
use super::status_reporter::BgpTcpInStatusReporter;
use super::tcp_md5;
use super::unit::{spawn_session, BgpTcpIn, LiveSessions, RotoFunc};

/// How long to wait for a TCP connection to be established before giving up
/// and falling back to the retry interval. Without this we would inherit the
/// kernel's SYN retry budget (over two minutes), which makes the configured
/// `connect_retry_secs` meaningless for a silently filtered peer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the supervisor reconciles its set of dialer tasks against the
/// (live-reconfigurable) unit config.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

/// How long a dialer waits before re-checking a peer that already has a live
/// session — typically one the peer itself established.
const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// A spawned task that is aborted when the handle is dropped.
///
/// Used so that dropping the supervisor's future — which is what happens
/// when the unit terminates and its `AbortOnDrop` guard fires — also tears
/// down the per-peer dialers it spawned, instead of leaving them dialing on
/// behalf of a unit that no longer exists.
pub(super) struct AbortOnDrop(JoinHandle<()>);

impl AbortOnDrop {
    pub(super) fn new(handle: JoinHandle<()>) -> Self {
        Self(handle)
    }

    fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Everything a dialer task needs to stand up a session, cloned per peer.
pub(super) struct ConnectorContext {
    pub bgp: Arc<ArcSwap<BgpTcpIn>>,
    pub gate: Gate,
    pub status_reporter: Arc<BgpTcpInStatusReporter>,
    pub live_sessions: Arc<Mutex<LiveSessions>>,
    pub ingresses: Arc<ingress::Register>,
    pub peer_stats: Arc<BgpPeerStatsRegistry>,
    pub roto_function: Option<RotoFunc>,
    pub roto_context: Arc<Mutex<Ctx>>,
}

impl Clone for ConnectorContext {
    fn clone(&self) -> Self {
        Self {
            bgp: self.bgp.clone(),
            gate: self.gate.clone(),
            status_reporter: self.status_reporter.clone(),
            live_sessions: self.live_sessions.clone(),
            ingresses: self.ingresses.clone(),
            peer_stats: self.peer_stats.clone(),
            roto_function: self.roto_function.clone(),
            roto_context: self.roto_context.clone(),
        }
    }
}

/// Open a TCP connection to `remote`, optionally from `source_addr` and
/// optionally protected by a TCP MD5 key.
///
/// The MD5 key is installed on the socket before connecting, because the SYN
/// already has to carry the option.
pub(super) async fn dial(
    remote: SocketAddr,
    source_addr: Option<IpAddr>,
    md5_key: Option<&str>,
) -> std::io::Result<TcpStream> {
    let socket = if remote.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    if let Some(key) = md5_key {
        tcp_md5::configure_tcp_md5_socket(
            &socket,
            remote.ip(),
            key.as_bytes(),
        )?;
    }

    if let Some(source_addr) = source_addr {
        if source_addr.is_ipv4() != remote.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "source_addr {source_addr} does not match \
                     address family of peer {}",
                    remote.ip()
                ),
            ));
        }
        // Port 0: let the kernel pick the ephemeral source port.
        socket.bind(SocketAddr::new(source_addr, 0))?;
    }

    match timeout(CONNECT_TIMEOUT, socket.connect(remote)).await {
        Ok(res) => res,
        Err(_elapsed) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("connect to {remote} timed out"),
        )),
    }
}

/// Supervise one dialer task per peer configured with `connect = true`.
///
/// Runs for the lifetime of the unit and picks up configuration changes:
/// peers that gained `connect` get a task, peers that lost it (or whose
/// connect parameters changed) have theirs replaced.
pub(super) async fn run_connectors(ctx: ConnectorContext) {
    let mut tasks: HashMap<IpAddr, (PeerConfig, AbortOnDrop)> =
        HashMap::new();
    // Peers we already complained about, so a misconfiguration does not
    // produce a warning every reconcile pass.
    let mut warned: HashSet<PrefixOrExact> = HashSet::new();

    loop {
        let mut wanted: HashMap<IpAddr, PeerConfig> = HashMap::new();
        for (key, peer_cfg) in ctx.bgp.load().peer_configs.iter() {
            if !peer_cfg.connect() {
                continue;
            }
            match key {
                PrefixOrExact::Exact(addr) => {
                    wanted.insert(*addr, peer_cfg.clone());
                }
                PrefixOrExact::Prefix(prefix) => {
                    if warned.insert(*key) {
                        warn!(
                            "peer '{}' ({}): connect = true needs an exact \
                             peer address, not a prefix; not connecting",
                            peer_cfg.name(),
                            prefix
                        );
                    }
                }
            }
        }

        // Drop tasks for peers that are gone, changed, or died. Dropping the
        // entry aborts the task.
        tasks.retain(|addr, (running_cfg, task)| {
            let keep = matches!(
                wanted.get(addr),
                Some(new_cfg) if new_cfg == running_cfg
            ) && !task.is_finished();
            if !keep {
                debug!("stopping BGP connector for {}", addr);
            }
            keep
        });

        for (addr, peer_cfg) in wanted {
            if tasks.contains_key(&addr) {
                continue;
            }
            debug!(
                "starting BGP connector for {} (peer '{}')",
                addr,
                peer_cfg.name()
            );
            let task = AbortOnDrop::new(crate::tokio::spawn(
                "bgp-in-connector",
                connect_loop(ctx.clone(), addr),
            ));
            tasks.insert(addr, (peer_cfg, task));
        }

        sleep(RECONCILE_INTERVAL).await;
    }
}

/// Keep one outbound session to `remote_addr` up, forever.
async fn connect_loop(ctx: ConnectorContext, remote_addr: IpAddr) {
    loop {
        // Re-read the config every pass so a reconfigure that only changes
        // session parameters takes effect on the next attempt.
        let bgp = ctx.bgp.load_full();
        let key = PrefixOrExact::Exact(remote_addr);
        let Some(peer_cfg) = bgp
            .peer_configs
            .get_exact(&key)
            .filter(|cfg| cfg.connect())
            .cloned()
        else {
            // The peer was removed or set back to passive. The supervisor
            // reaps finished tasks, so just stop.
            debug!("no connect config left for {}, stopping", remote_addr);
            return;
        };

        // Do not dial a peer that already has a session, either one we set
        // up earlier or one the peer established towards our listener.
        if has_live_session(&ctx.live_sessions, remote_addr) {
            sleep(IDLE_POLL_INTERVAL).await;
            continue;
        }

        let remote = SocketAddr::new(remote_addr, peer_cfg.remote_port());
        match dial(remote, peer_cfg.source_addr(), peer_cfg.md5_key()).await {
            Ok(tcp_stream) => {
                ctx.status_reporter.connection_initiated(remote);
                let child_name =
                    format!("bgp-out[{}:{}]", remote.ip(), remote.port());
                let child_status_reporter =
                    Arc::new(ctx.status_reporter.add_child(&child_name));
                let jh = spawn_session(
                    child_name,
                    ctx.roto_function.clone(),
                    ctx.roto_context.clone(),
                    &ctx.gate,
                    &bgp,
                    tcp_stream,
                    true, // we opened this connection
                    &peer_cfg,
                    key,
                    child_status_reporter,
                    ctx.live_sessions.clone(),
                    ctx.ingresses.clone(),
                    ctx.peer_stats.clone(),
                    // Tentative register(), as on the accept path: the real
                    // reuse check happens at SessionNegotiated time, where
                    // the remote ASN is known.
                    ctx.ingresses.register(),
                );
                // Resolves when the session ends (including when collision
                // resolution aborts it), which is our cue to dial again.
                let _ = jh.await;
                debug!("outbound session to {} ended", remote);
            }
            Err(err) => {
                ctx.status_reporter.connect_error(remote, &err);
            }
        }

        let retry = peer_cfg.connect_retry();
        sleep(retry + jitter(retry / 4)).await;
    }
}

fn has_live_session(
    live_sessions: &Mutex<LiveSessions>,
    remote_addr: IpAddr,
) -> bool {
    live_sessions
        .lock()
        .unwrap()
        .keys()
        .any(|(addr, _asn)| *addr == remote_addr)
}

/// A crude 0..=max jitter, to keep peers from re-dialing in lockstep and to
/// break up connect collisions when both ends dial each other.
fn jitter(max: Duration) -> Duration {
    let max_ms = max.as_millis() as u64;
    if max_ms == 0 {
        return Duration::ZERO;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()))
        .unwrap_or(0);
    Duration::from_millis(nanos % (max_ms + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn dial_connects_to_a_listener() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accepted =
            tokio::spawn(async move { listener.accept().await.unwrap().1 });

        let stream = dial(addr, None, None).await.unwrap();
        let peer = accepted.await.unwrap();

        assert_eq!(stream.peer_addr().unwrap(), addr);
        assert_eq!(stream.local_addr().unwrap(), peer);
    }

    #[tokio::test]
    async fn dial_binds_the_configured_source_address() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted =
            tokio::spawn(async move { listener.accept().await.unwrap().1 });

        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let stream = dial(addr, Some(source), None).await.unwrap();
        let peer = accepted.await.unwrap();

        assert_eq!(peer.ip(), source);
        assert_eq!(stream.local_addr().unwrap().ip(), source);
    }

    #[tokio::test]
    async fn dial_rejects_a_mismatched_source_family() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 179);
        let source = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let err = dial(remote, Some(source), None).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn dial_times_out_rather_than_hanging() {
        // 203.0.113.0/24 (TEST-NET-3) is not routed, so the SYN goes
        // nowhere; without our timeout this would take minutes.
        let remote =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 179);
        let started = tokio::time::Instant::now();
        let res = dial(remote, None, None).await;
        assert!(res.is_err());
        assert!(
            started.elapsed() <= CONNECT_TIMEOUT + Duration::from_secs(2)
        );
    }
}
