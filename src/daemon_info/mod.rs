//! Process-wide operational facts served by the read-only inspection API.
//!
//! This backs `/api/v1/status`, `/api/v1/config` and `/api/v1/filters`, and
//! with them `netom-cli`'s `show version` / `show status` /
//! `show running-config` / `show filters`.
//!
//! # Why a TOML snapshot rather than serializing `Config`
//!
//! [`Config`](crate::config::Config) and every unit and target config struct
//! below it are `Deserialize`-only. Deriving `Serialize` across that whole
//! tree just to render a config would be a wide, invasive change, and it
//! would give us back a *re-encoded* config rather than the one the operator
//! wrote. [`ConfigFile`](crate::config::ConfigFile) already retains the
//! normalized TOML (it re-serializes the parsed `toml::Value` in order to
//! compute line offsets for parse diagnostics), so we snapshot that string
//! and serve it. The snapshot is refreshed on every load, which includes
//! SIGHUP reloads, so it always describes the running config.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwapOption;
use chrono::{DateTime, Utc};

pub mod http_ng;

/// The Roto function names netom looks up, for `/api/v1/filters`.
///
/// Kept in sync by hand with the `ROTO_FUNC_*_NAME` constants in the units
/// (`units::bgp_tcp_in::unit`, `units::bmp_tcp_in::unit`,
/// `units::rib_unit::unit`); see the test below.
pub const ROTO_ENTRYPOINTS: &[&str] = &[
    "bgp_in",
    "bmp_in",
    "rib_in_pre",
    "rib_in_post",
    "vrp_update",
    "rib_in_rov_status_update",
];

/// Config keys whose values are secrets and must never leave the process.
///
/// The HTTP API is unauthenticated, so this is the only thing standing
/// between a configured TCP-MD5 key and anyone who can reach the API port.
///
/// Note what is deliberately *not* here: `tls_cert` and `tls_key` hold
/// filesystem *paths*, not key material. Operators need to see them to debug
/// a TLS setup, and the key file itself is protected by its own permissions.
const REDACTED_KEYS: &[&str] = &[
    "md5_key",  // BGP TCP-MD5 shared secret (bgp-tcp-in peers)
    "password", // MQTT target credentials
];

/// Replacement value for a redacted secret. Matches the existing
/// `PeerConfig` `Debug` impl so redaction reads the same everywhere.
const REDACTED: &str = "<redacted>";

/// A configured unit or target, for the `/api/v1/status` component list.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ComponentInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: &'static str,
}

/// Everything the inspection API needs to know about the running config.
///
/// Rebuilt from scratch on each config load rather than mutated in place, so
/// a reader either sees the whole old config or the whole new one.
#[derive(Debug)]
pub struct ConfigSnapshot {
    /// Path the config was loaded from, if it came from a file.
    pub path: Option<PathBuf>,

    /// The normalized config TOML, with secrets redacted.
    pub toml: String,

    /// Configured units, in name order.
    pub units: Vec<ComponentInfo>,

    /// Configured targets, in name order.
    pub targets: Vec<ComponentInfo>,

    /// Path to the Roto script, resolved relative to the config file.
    pub roto_script: Option<PathBuf>,

    /// Interfaces the HTTP API is configured to listen on.
    pub http_listen: Vec<SocketAddr>,
}

/// Shared, process-wide operational state.
///
/// Held as an `Arc` by the `Manager` and by the HTTP API state.
#[derive(Debug)]
pub struct DaemonInfo {
    /// Wall-clock time the process started, for display.
    started: DateTime<Utc>,

    /// Monotonic start, for computing uptime (immune to clock steps).
    started_at: Instant,

    /// The running config, unset until the first successful load.
    config: ArcSwapOption<ConfigSnapshot>,
}

impl Default for DaemonInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonInfo {
    pub fn new() -> Self {
        Self {
            started: Utc::now(),
            started_at: Instant::now(),
            config: ArcSwapOption::empty(),
        }
    }

    /// The netom version this binary was built from.
    pub fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    pub fn started(&self) -> DateTime<Utc> {
        self.started
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// The running config, or `None` before the first load completes.
    pub fn config(&self) -> Option<Arc<ConfigSnapshot>> {
        self.config.load_full()
    }

    /// Install a new config snapshot, replacing any previous one.
    pub fn set_config(&self, snapshot: ConfigSnapshot) {
        self.config.store(Some(Arc::new(snapshot)));
    }
}

/// Redact secret values from a TOML document.
///
/// Walks the parsed tree rather than the text so that a key is matched
/// structurally — no risk of a substring match mangling an unrelated value,
/// and no dependence on how the value was quoted. Any key named in
/// [`REDACTED_KEYS`] has its value replaced with [`REDACTED`], at any depth.
///
/// On a parse failure this returns `None` rather than the unredacted input:
/// failing closed is the only safe behaviour for a redaction function.
pub fn redact_toml(input: &str) -> Option<String> {
    // `toml::de::from_str`, matching `ConfigFile::new` — `Value` does not
    // implement `FromStr` in toml 0.9.
    let mut value: toml::Value = toml::de::from_str(input).ok()?;
    redact_value(&mut value);
    toml::to_string(&value).ok()
}

fn redact_value(value: &mut toml::Value) {
    match value {
        toml::Value::Table(table) => {
            for (key, val) in table.iter_mut() {
                if REDACTED_KEYS.contains(&key.as_str()) {
                    *val = toml::Value::String(REDACTED.into());
                } else {
                    redact_value(val);
                }
            }
        }
        toml::Value::Array(array) => {
            for val in array.iter_mut() {
                redact_value(val);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_bgp_md5_key() {
        let input = r#"
http_listen = ["[::]:8080"]

[units.bgp-in]
type = "bgp-tcp-in"
listen = "10.1.0.254:179"

[units.bgp-in.peers."10.1.0.1"]
name = "PeerA"
md5_key = "s3cr3t"
"#;
        let out = redact_toml(input).unwrap();
        assert!(
            !out.contains("s3cr3t"),
            "md5_key leaked into output:\n{out}"
        );
        assert!(out.contains(REDACTED));
        // Non-secret neighbouring values must survive.
        assert!(out.contains("10.1.0.254:179"));
        assert!(out.contains("PeerA"));
    }

    #[test]
    fn redacts_mqtt_password_but_keeps_username() {
        let input = r#"
[targets.mqtt]
type = "mqtt-out"
destination = "localhost"
username = "netom"
password = "hunter2"
"#;
        let out = redact_toml(input).unwrap();
        assert!(!out.contains("hunter2"));
        assert!(out.contains("netom"));
    }

    #[test]
    fn keeps_tls_paths_visible() {
        // tls_key is a path to a key file, not the key itself; operators
        // need it to debug a TLS setup.
        let input = r#"
[units.bmp-out]
type = "bmp-tcp-out"
tls = true
tls_cert = "/etc/netom/bmp-out.crt"
tls_key = "/etc/netom/bmp-out.key"
"#;
        let out = redact_toml(input).unwrap();
        assert!(out.contains("/etc/netom/bmp-out.key"));
    }

    #[test]
    fn redacts_at_any_depth() {
        let input = r#"
[a.b.c.d]
md5_key = "deep-secret"
"#;
        let out = redact_toml(input).unwrap();
        assert!(!out.contains("deep-secret"));
    }

    #[test]
    fn fails_closed_on_unparseable_input() {
        assert!(redact_toml("this is = = not toml").is_none());
    }

    /// `ROTO_ENTRYPOINTS` is hand-maintained; if a unit renames or adds a
    /// hook, `/api/v1/filters` would quietly advertise the wrong set.
    #[test]
    fn roto_entrypoints_match_the_units() {
        use crate::units::{bgp_tcp_in, bmp_tcp_in, rib_unit};

        for name in [
            bgp_tcp_in::unit::ROTO_FUNC_FILTER_NAME,
            bmp_tcp_in::unit::ROTO_FUNC_FILTER_NAME,
            rib_unit::unit::ROTO_FUNC_PRE_FILTER_NAME,
            rib_unit::unit::ROTO_FUNC_POST_FILTER_NAME,
            rib_unit::unit::ROTO_FUNC_VRP_UPDATE_FILTER_NAME,
            rib_unit::unit::ROTO_FUNC_ROV_STATUS_UPDATE_NAME,
        ] {
            assert!(
                ROTO_ENTRYPOINTS.contains(&name),
                "roto entrypoint {name:?} is used by a unit but missing \
                 from ROTO_ENTRYPOINTS",
            );
        }
        assert_eq!(
            ROTO_ENTRYPOINTS.len(),
            6,
            "ROTO_ENTRYPOINTS has entries no unit uses",
        );
    }
}

