//! Automatic snapshot renewal for BMP state that can no longer be trusted.
//! RFC 7854 sections 3.2, 3.3 and 5: dropping TCP restarts monitoring; the
//! exporter replays established peers and their current Adj-RIBs-In.

use serde::Deserialize;
use std::time::Duration;
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, try_from = "ConfigValues")]
pub struct Config {
    pub interval_secs: u64,
    pub min_session_secs: u64,
    pub replay_grace_secs: u64,
    pub max_peer_states: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval_secs: 6 * 60 * 60,
            min_session_secs: 60,
            replay_grace_secs: 5 * 60,
            max_peer_states: 65_536,
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ConfigValues {
    interval_secs: u64,
    min_session_secs: u64,
    replay_grace_secs: u64,
    max_peer_states: usize,
}

impl Default for ConfigValues {
    fn default() -> Self {
        let c = Config::default();
        Self {
            interval_secs: c.interval_secs,
            min_session_secs: c.min_session_secs,
            replay_grace_secs: c.replay_grace_secs,
            max_peer_states: c.max_peer_states,
        }
    }
}

impl TryFrom<ConfigValues> for Config {
    type Error = &'static str;
    fn try_from(c: ConfigValues) -> Result<Self, Self::Error> {
        if c.min_session_secs == 0
            || c.min_session_secs > c.replay_grace_secs
            || c.replay_grace_secs >= c.interval_secs
            || c.interval_secs > 7 * 24 * 60 * 60
            || c.max_peer_states == 0
        {
            return Err("BMP reconciliation requires 0 < min_session_secs <= replay_grace_secs < interval_secs <= 604800 and max_peer_states > 0");
        }
        Ok(Self {
            interval_secs: c.interval_secs,
            min_session_secs: c.min_session_secs,
            replay_grace_secs: c.replay_grace_secs,
            max_peer_states: c.max_peer_states,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Periodic,
    UnmatchedPeerDown,
    PossibleReplacement,
    PeerStateLimit,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Periodic => "periodic snapshot renewal",
            Self::UnmatchedPeerDown => "unmatched Peer Down",
            Self::PossibleReplacement => {
                "possible unnumbered peer replacement"
            }
            Self::PeerStateLimit => "peer-state limit reached",
        })
    }
}

pub struct Reconciliation {
    config: Config,
    started: Instant,
    deadline: Instant,
    reason: Reason,
}

impl Reconciliation {
    pub fn new(config: Config, now: Instant, jitter_seed: u64) -> Self {
        // Spread periodic refreshes over an additional 0..10% interval.
        let jitter = jitter_seed % (config.interval_secs / 10 + 1);
        Self {
            config,
            started: now,
            deadline: now
                + Duration::from_secs(config.interval_secs + jitter),
            reason: Reason::Periodic,
        }
    }

    pub fn observe(
        &mut self,
        now: Instant,
        reason: Option<Reason>,
        peer_states: usize,
    ) {
        if peer_states >= self.config.max_peer_states {
            // Capacity takes precedence over the minimum session lifetime.
            self.deadline = now;
            self.reason = Reason::PeerStateLimit;
            return;
        }
        let Some(reason) = reason else { return };
        if reason == Reason::PossibleReplacement
            && now
                < self.started
                    + Duration::from_secs(self.config.replay_grace_secs)
        {
            // Peer Ups during startup can be legitimate parallel sessions.
            // There is no global end-of-snapshot marker in BMP. Do not use
            // one peer's EOR as proof all peers have been enumerated.
            return;
        }
        let deadline = now.max(
            self.started + Duration::from_secs(self.config.min_session_secs),
        );
        if deadline < self.deadline {
            self.deadline = deadline;
            self.reason = reason;
        }
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn reason(&self) -> Reason {
        self.reason
    }
}
