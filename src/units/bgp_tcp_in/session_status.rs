//! Per-peer BGP session status, for `/api/v1/bgp/neighbors`.
//!
//! # Why this exists
//!
//! The ingress register records only `Connected`/`Disconnected`, which is
//! enough to say whether routes are arriving but not enough for a
//! `show ip bgp summary`. Two things are missing:
//!
//! * the RFC 4271 FSM state, so a peer that is retrying shows as `Active`
//!   rather than as merely "not connected"; and
//! * peers that have *never* established, which have no ingress entry at
//!   all and would simply be absent from the table — precisely the peers an
//!   operator is looking for when something is wrong.
//!
//! # Why mirroring, rather than asking the session
//!
//! routecore exposes `Command::GetAttributes`, but the command channel only
//! reaches sessions in [`LiveSessions`](super::unit::LiveSessions), which is
//! populated at `SessionNegotiated` time — i.e. it holds *established*
//! sessions only, and so could never report the pre-established states that
//! are the interesting ones. The FSM's own transitions are recorded only by
//! a `debug!` line inside routecore. So the session task mirrors its state
//! here after each tick instead: a relaxed atomic store, guarded by a change
//! check, on a path that is already doing socket I/O.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{
    AtomicBool, AtomicI64, AtomicU16, AtomicU32, AtomicU64, AtomicU8,
    Ordering,
};
use std::sync::{Arc, LazyLock, RwLock};

use routecore::bgp::fsm::state_machine::State;

use crate::ingress::IngressId;

/// The RFC 4271 finite state machine states.
///
/// Mirrors routecore's `State` but owns its wire representation, so the
/// stored `u8` cannot silently change meaning if routecore's enum grows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FsmState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl FsmState {
    fn as_u8(self) -> u8 {
        match self {
            FsmState::Idle => 1,
            FsmState::Connect => 2,
            FsmState::Active => 3,
            FsmState::OpenSent => 4,
            FsmState::OpenConfirm => 5,
            FsmState::Established => 6,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            2 => FsmState::Connect,
            3 => FsmState::Active,
            4 => FsmState::OpenSent,
            5 => FsmState::OpenConfirm,
            6 => FsmState::Established,
            _ => FsmState::Idle,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FsmState::Idle => "Idle",
            FsmState::Connect => "Connect",
            FsmState::Active => "Active",
            FsmState::OpenSent => "OpenSent",
            FsmState::OpenConfirm => "OpenConfirm",
            FsmState::Established => "Established",
        }
    }
}

impl From<State> for FsmState {
    fn from(state: State) -> Self {
        // routecore's State is a `typeenum!` over u16 with the RFC's own
        // numbering, plus an `Unimplemented` catch-all.
        FsmState::from_u8(u16::from(state) as u8)
    }
}

/// Live status of one configured or connected peer.
///
/// Counters are atomics so the receive path can update them without a lock.
#[derive(Debug)]
pub struct SessionStatus {
    fsm: AtomicU8,
    /// The session's ingress id once negotiated; 0 means "not yet".
    ingress_id: AtomicU32,
    /// Unix seconds at which the session last reached Established; 0 means
    /// it never has.
    established_unix: AtomicI64,
    /// Negotiated hold time, in seconds; 0 means not yet negotiated.
    hold_time: AtomicU16,
    /// Peer ASN, learned at negotiation or from an exact config; 0 unknown.
    remote_asn: AtomicU32,
    /// True when netom dials this peer (`connect = true`).
    connect_mode: AtomicBool,
    /// True when the peer appears in the running config, as opposed to
    /// having only ever turned up on the listener.
    configured: AtomicBool,

    updates_received: AtomicU64,
    notifications_received: AtomicU64,
    notifications_sent: AtomicU64,

    /// Configured name, for the display column.
    name: RwLock<Option<String>>,
    /// Why the session last went down, if we know.
    last_error: RwLock<Option<String>>,
}

impl Default for SessionStatus {
    fn default() -> Self {
        Self {
            fsm: AtomicU8::new(FsmState::Idle.as_u8()),
            ingress_id: AtomicU32::new(0),
            established_unix: AtomicI64::new(0),
            hold_time: AtomicU16::new(0),
            remote_asn: AtomicU32::new(0),
            connect_mode: AtomicBool::new(false),
            configured: AtomicBool::new(false),
            updates_received: AtomicU64::new(0),
            notifications_received: AtomicU64::new(0),
            notifications_sent: AtomicU64::new(0),
            name: RwLock::new(None),
            last_error: RwLock::new(None),
        }
    }
}

impl SessionStatus {
    pub fn state(&self) -> FsmState {
        FsmState::from_u8(self.fsm.load(Ordering::Relaxed))
    }

    /// Record the FSM state. Returns true if it changed.
    ///
    /// Called once per tick on the session's hot path, so the common case
    /// is a single relaxed load and comparison.
    pub fn set_state(&self, state: FsmState) -> bool {
        let encoded = state.as_u8();
        if self.fsm.load(Ordering::Relaxed) == encoded {
            return false;
        }
        self.fsm.store(encoded, Ordering::Relaxed);
        if state == FsmState::Established {
            self.established_unix
                .store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
        }
        true
    }

    pub fn set_ingress_id(&self, id: IngressId) {
        self.ingress_id.store(id, Ordering::Relaxed);
    }

    pub fn ingress_id(&self) -> Option<IngressId> {
        match self.ingress_id.load(Ordering::Relaxed) {
            0 => None,
            id => Some(id),
        }
    }

    /// Seconds since the session came up, or `None` if it never has or is
    /// not currently up.
    pub fn uptime_secs(&self) -> Option<u64> {
        if self.state() != FsmState::Established {
            return None;
        }
        match self.established_unix.load(Ordering::Relaxed) {
            0 => None,
            since => {
                let now = chrono::Utc::now().timestamp();
                Some((now - since).max(0) as u64)
            }
        }
    }

    pub fn set_hold_time(&self, secs: u16) {
        self.hold_time.store(secs, Ordering::Relaxed);
    }

    pub fn hold_time(&self) -> Option<u16> {
        match self.hold_time.load(Ordering::Relaxed) {
            0 => None,
            v => Some(v),
        }
    }

    pub fn set_remote_asn(&self, asn: u32) {
        self.remote_asn.store(asn, Ordering::Relaxed);
    }

    pub fn remote_asn(&self) -> Option<u32> {
        match self.remote_asn.load(Ordering::Relaxed) {
            0 => None,
            asn => Some(asn),
        }
    }

    pub fn set_connect_mode(&self, on: bool) {
        self.connect_mode.store(on, Ordering::Relaxed);
    }

    pub fn connect_mode(&self) -> bool {
        self.connect_mode.load(Ordering::Relaxed)
    }

    pub fn set_configured(&self, on: bool) {
        self.configured.store(on, Ordering::Relaxed);
    }

    pub fn configured(&self) -> bool {
        self.configured.load(Ordering::Relaxed)
    }

    pub fn inc_updates_received(&self) {
        self.updates_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn updates_received(&self) -> u64 {
        self.updates_received.load(Ordering::Relaxed)
    }

    pub fn inc_notifications_received(&self) {
        self.notifications_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn notifications_received(&self) -> u64 {
        self.notifications_received.load(Ordering::Relaxed)
    }

    pub fn inc_notifications_sent(&self) {
        self.notifications_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn notifications_sent(&self) -> u64 {
        self.notifications_sent.load(Ordering::Relaxed)
    }

    pub fn set_name(&self, name: impl Into<String>) {
        *self.name.write().unwrap() = Some(name.into());
    }

    pub fn name(&self) -> Option<String> {
        self.name.read().unwrap().clone()
    }

    pub fn set_last_error(&self, err: impl Into<String>) {
        *self.last_error.write().unwrap() = Some(err.into());
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.read().unwrap().clone()
    }
}

/// Per-peer session status, keyed by peer address.
///
/// Global rather than per-unit so that the HTTP API can read it without the
/// endpoint having to be registered by (and therefore to exist only
/// alongside) a `bgp-tcp-in` unit. Ingress ids are process-wide unique, so
/// one map is correct even with several units configured.
#[derive(Debug, Default)]
pub struct BgpSessionRegistry {
    inner: RwLock<HashMap<IpAddr, Arc<SessionStatus>>>,
}

impl BgpSessionRegistry {
    pub fn get_or_create(&self, peer: IpAddr) -> Arc<SessionStatus> {
        if let Some(status) = self.inner.read().unwrap().get(&peer) {
            return status.clone();
        }
        self.inner
            .write()
            .unwrap()
            .entry(peer)
            .or_default()
            .clone()
    }

    pub fn get(&self, peer: IpAddr) -> Option<Arc<SessionStatus>> {
        self.inner.read().unwrap().get(&peer).cloned()
    }

    pub fn snapshot(&self) -> Vec<(IpAddr, Arc<SessionStatus>)> {
        let mut all: Vec<_> = self
            .inner
            .read()
            .unwrap()
            .iter()
            .map(|(addr, status)| (*addr, status.clone()))
            .collect();
        all.sort_by_key(|(addr, _)| *addr);
        all
    }

    /// Forget peers that are neither configured nor established.
    ///
    /// A peer that connected once from an address matched by a prefix, and
    /// never came back, would otherwise accumulate forever.
    pub fn forget_unconfigured_idle(&self) {
        self.inner.write().unwrap().retain(|_, status| {
            status.configured() || status.state() != FsmState::Idle
        });
    }

    /// Drop the "configured" mark from every peer, so that a config reload
    /// can re-mark only the peers the new config actually names.
    pub fn clear_configured_marks(&self) {
        for status in self.inner.read().unwrap().values() {
            status.set_configured(false);
        }
    }
}

static REGISTRY: LazyLock<Arc<BgpSessionRegistry>> =
    LazyLock::new(|| Arc::new(BgpSessionRegistry::default()));

/// The process-wide session registry.
pub fn registry() -> Arc<BgpSessionRegistry> {
    REGISTRY.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn fsm_states_round_trip_through_their_wire_form() {
        for state in [
            FsmState::Idle,
            FsmState::Connect,
            FsmState::Active,
            FsmState::OpenSent,
            FsmState::OpenConfirm,
            FsmState::Established,
        ] {
            assert_eq!(FsmState::from_u8(state.as_u8()), state);
        }
    }

    #[test]
    fn converts_from_routecore_states() {
        assert_eq!(FsmState::from(State::Idle), FsmState::Idle);
        assert_eq!(FsmState::from(State::Connect), FsmState::Connect);
        assert_eq!(FsmState::from(State::Active), FsmState::Active);
        assert_eq!(FsmState::from(State::OpenSent), FsmState::OpenSent);
        assert_eq!(
            FsmState::from(State::OpenConfirm),
            FsmState::OpenConfirm
        );
        assert_eq!(
            FsmState::from(State::Established),
            FsmState::Established
        );
    }

    #[test]
    fn set_state_reports_only_real_changes() {
        let status = SessionStatus::default();
        assert_eq!(status.state(), FsmState::Idle);
        // Idle -> Idle is not a transition.
        assert!(!status.set_state(FsmState::Idle));
        assert!(status.set_state(FsmState::Active));
        assert!(!status.set_state(FsmState::Active));
        assert_eq!(status.state(), FsmState::Active);
    }

    #[test]
    fn uptime_is_only_reported_while_established() {
        let status = SessionStatus::default();
        assert_eq!(status.uptime_secs(), None);

        status.set_state(FsmState::Established);
        assert!(status.uptime_secs().is_some());

        // Going down stops the clock rather than reporting a stale uptime.
        status.set_state(FsmState::Idle);
        assert_eq!(status.uptime_secs(), None);
    }

    #[test]
    fn registry_returns_the_same_entry_for_one_peer() {
        let reg = BgpSessionRegistry::default();
        let a = reg.get_or_create(ip("10.0.0.1"));
        let b = reg.get_or_create(ip("10.0.0.1"));
        a.inc_updates_received();
        assert_eq!(b.updates_received(), 1);
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn snapshot_is_ordered_by_peer_address() {
        let reg = BgpSessionRegistry::default();
        reg.get_or_create(ip("10.0.0.3"));
        reg.get_or_create(ip("10.0.0.1"));
        reg.get_or_create(ip("10.0.0.2"));
        let addrs: Vec<_> =
            reg.snapshot().into_iter().map(|(a, _)| a).collect();
        assert_eq!(
            addrs,
            vec![ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")]
        );
    }

    #[test]
    fn unconfigured_idle_peers_are_forgotten() {
        let reg = BgpSessionRegistry::default();

        // Configured but down: must be kept, it is exactly the row an
        // operator is looking for.
        reg.get_or_create(ip("10.0.0.1")).set_configured(true);
        // Transient peer from a prefix match, now idle: drop it.
        reg.get_or_create(ip("10.0.0.2"));
        // Unconfigured but live: keep.
        reg.get_or_create(ip("10.0.0.3"))
            .set_state(FsmState::Established);

        reg.forget_unconfigured_idle();

        let addrs: Vec<_> =
            reg.snapshot().into_iter().map(|(a, _)| a).collect();
        assert_eq!(addrs, vec![ip("10.0.0.1"), ip("10.0.0.3")]);
    }

    #[test]
    fn configured_marks_can_be_cleared_for_a_reload() {
        let reg = BgpSessionRegistry::default();
        let status = reg.get_or_create(ip("10.0.0.1"));
        status.set_configured(true);
        reg.clear_configured_marks();
        assert!(!status.configured());
    }
}
