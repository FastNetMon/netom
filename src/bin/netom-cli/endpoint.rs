//! Finding the daemon's HTTP API.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::error::CliError;

pub const DEFAULT_PORT: u16 = 8080;

/// Config files to consult when none was named.
const IMPLICIT_CONFIGS: &[&str] =
    &["./netom.conf", "/etc/netom/netom.conf"];

/// Where to connect, and how we decided.
pub struct Endpoint {
    pub addrs: Vec<SocketAddr>,
    /// Human-readable provenance, shown when the connection fails.
    pub provenance: String,
}

/// Resolve the API endpoint.
///
/// Precedence: `--url`, then `NETOM_URL`, then an explicitly named config,
/// then the well-known config paths, then the documented default.
pub fn resolve(
    url_flag: Option<&str>,
    config_flag: Option<&str>,
) -> Result<Endpoint, CliError> {
    if let Some(url) = url_flag {
        return from_url(url, "from --url");
    }
    if let Ok(url) = std::env::var("NETOM_URL") {
        if !url.is_empty() {
            return from_url(&url, "from $NETOM_URL");
        }
    }
    if let Some(path) = config_flag {
        // An explicitly named config that cannot be used is an error, not
        // something to silently fall back from.
        let addrs = http_listen_from(Path::new(path))?;
        return Ok(endpoint_from(
            addrs,
            format!("from {path}: http_listen"),
        ));
    }
    for candidate in IMPLICIT_CONFIGS {
        let path = PathBuf::from(candidate);
        if !path.exists() {
            continue;
        }
        // A config we found on our own may be unreadable or may not
        // configure the API at all; keep looking rather than failing.
        if let Ok(addrs) = http_listen_from(&path) {
            if !addrs.is_empty() {
                return Ok(endpoint_from(
                    addrs,
                    format!("from {candidate}: http_listen"),
                ));
            }
        }
    }

    Ok(Endpoint {
        addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_PORT))],
        provenance: "default endpoint; no --url, $NETOM_URL or config found"
            .to_string(),
    })
}

fn endpoint_from(addrs: Vec<SocketAddr>, provenance: String) -> Endpoint {
    Endpoint {
        addrs: addrs.iter().copied().flat_map(connectable).collect(),
        provenance,
    }
}

/// Parse a `--url`-style endpoint.
///
/// Accepts `http://host:port`, `host:port` and a bare `host`.
fn from_url(url: &str, provenance: &str) -> Result<Endpoint, CliError> {
    let rest = match url.split_once("://") {
        Some(("http", rest)) => rest,
        Some((scheme, _)) => {
            return Err(CliError::usage(format!(
                "% Unsupported URL scheme {scheme:?}: the netom API is \
                 plain HTTP.",
            )))
        }
        None => url,
    };
    // Drop any path component; every request builds its own path.
    let hostport = rest.split('/').next().unwrap_or(rest);

    let addrs = parse_host_port(hostport).ok_or_else(|| {
        CliError::usage(format!("% Cannot parse endpoint {url:?}."))
    })?;

    Ok(Endpoint {
        addrs,
        provenance: provenance.to_string(),
    })
}

fn parse_host_port(hostport: &str) -> Option<Vec<SocketAddr>> {
    // A literal socket address, including bracketed IPv6.
    if let Ok(addr) = hostport.parse::<SocketAddr>() {
        return Some(connectable(addr));
    }
    // A bare IP with no port.
    if let Ok(ip) = hostport.parse::<IpAddr>() {
        return Some(connectable(SocketAddr::from((ip, DEFAULT_PORT))));
    }
    // A hostname, with or without a port. Resolve it now so that the
    // failure message can name the addresses actually tried.
    use std::net::ToSocketAddrs;
    let with_port = if hostport.contains(':') {
        hostport.to_string()
    } else {
        format!("{hostport}:{DEFAULT_PORT}")
    };
    with_port
        .to_socket_addrs()
        .ok()
        .map(|addrs| addrs.collect::<Vec<_>>())
        .filter(|addrs| !addrs.is_empty())
}

/// Turn a *listen* address into addresses that can be *connected* to.
///
/// `http_listen = ["[::]:8080"]` is netom's shipped default and is not a
/// connectable address. The wildcard means "every local interface", so
/// loopback is both correct and the safe choice: it never sends an
/// unauthenticated query off-box on the CLI's own initiative.
///
/// `[::]` yields both `[::1]` and `127.0.0.1`, tried in that order: with
/// `bindv6only=0` a daemon on `[::]` also serves IPv4, and hosts with IPv6
/// disabled at runtime need the v4 fallback.
fn connectable(addr: SocketAddr) -> Vec<SocketAddr> {
    let port = addr.port();
    match addr.ip() {
        IpAddr::V4(ip) if ip == Ipv4Addr::UNSPECIFIED => {
            vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))]
        }
        IpAddr::V6(ip) if ip == Ipv6Addr::UNSPECIFIED => {
            vec![
                SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            ]
        }
        _ => vec![addr],
    }
}

/// Pluck `http_listen` out of a netom config.
///
/// Deliberately a `toml::Value` lookup rather than the daemon's `Config`:
/// that type is `deny_unknown_fields`, requires `units` and `targets`, and
/// needs a `Manager` to deserialize — none of which the CLI has, or should
/// link.
fn http_listen_from(path: &Path) -> Result<Vec<SocketAddr>, CliError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        CliError::usage(format!("% Cannot read {}: {e}", path.display()))
    })?;
    let value: toml::Value = toml::de::from_str(&text).map_err(|e| {
        CliError::usage(format!("% Cannot parse {}: {e}", path.display()))
    })?;

    let addrs: Vec<SocketAddr> = value
        .get("http_listen")
        .and_then(|v| v.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| e.as_str())
                .filter_map(|s| s.parse().ok())
                .collect()
        })
        .unwrap_or_default();

    if addrs.is_empty() {
        return Err(CliError::usage(format!(
            "% {} does not set a usable http_listen; the daemon's HTTP API \
             is disabled or the value is malformed.",
            path.display(),
        )));
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn rewrites_the_ipv4_wildcard_to_loopback() {
        assert_eq!(
            connectable(sock("0.0.0.0:8080")),
            vec![sock("127.0.0.1:8080")]
        );
    }

    /// netom ships `http_listen = ["[::]:8080"]`, so this is the default
    /// path for essentially every deployment.
    #[test]
    fn rewrites_the_ipv6_wildcard_to_both_loopbacks() {
        assert_eq!(
            connectable(sock("[::]:8080")),
            vec![sock("[::1]:8080"), sock("127.0.0.1:8080")],
        );
    }

    #[test]
    fn leaves_concrete_addresses_alone() {
        assert_eq!(
            connectable(sock("10.0.0.5:9000")),
            vec![sock("10.0.0.5:9000")]
        );
        assert_eq!(
            connectable(sock("[2001:db8::1]:9000")),
            vec![sock("[2001:db8::1]:9000")]
        );
    }

    #[test]
    fn parses_url_forms() {
        let e = from_url("http://127.0.0.1:9", "t").unwrap();
        assert_eq!(e.addrs, vec![sock("127.0.0.1:9")]);

        let e = from_url("127.0.0.1:9", "t").unwrap();
        assert_eq!(e.addrs, vec![sock("127.0.0.1:9")]);

        // A bare address gets the documented default port.
        let e = from_url("127.0.0.1", "t").unwrap();
        assert_eq!(e.addrs, vec![sock("127.0.0.1:8080")]);

        // Bracketed IPv6 literal.
        let e = from_url("http://[::1]:9", "t").unwrap();
        assert_eq!(e.addrs, vec![sock("[::1]:9")]);

        // A path component is not part of the endpoint.
        let e = from_url("http://127.0.0.1:9/api/v1", "t").unwrap();
        assert_eq!(e.addrs, vec![sock("127.0.0.1:9")]);
    }

    #[test]
    fn rejects_non_http_schemes() {
        // The API has no TLS; accepting https:// would just fail obscurely
        // later.
        assert!(from_url("https://127.0.0.1:9", "t").is_err());
    }

    #[test]
    fn reads_http_listen_from_a_config() {
        let dir = std::env::temp_dir().join("netom-cli-endpoint-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("netom.conf");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"
http_listen = ["[::]:8809", "10.0.0.1:8810"]

[units.rib]
type = "rib"
sources = []
"#
        )
        .unwrap();

        let addrs = http_listen_from(&path).unwrap();
        assert_eq!(addrs, vec![sock("[::]:8809"), sock("10.0.0.1:8810")]);

        // And the wildcard is rewritten on the way to an Endpoint.
        let e = endpoint_from(addrs, "test".into());
        assert_eq!(
            e.addrs,
            vec![
                sock("[::1]:8809"),
                sock("127.0.0.1:8809"),
                sock("10.0.0.1:8810"),
            ],
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reports_a_config_without_http_listen() {
        let dir =
            std::env::temp_dir().join("netom-cli-endpoint-test-nolisten");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("netom.conf");
        std::fs::write(&path, "[units.rib]\ntype = \"rib\"\n").unwrap();

        let err = http_listen_from(&path).unwrap_err();
        assert!(format!("{err}").contains("http_listen"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reports_a_missing_config() {
        let err =
            http_listen_from(Path::new("/nonexistent/netom.conf")).unwrap_err();
        assert!(format!("{err}").contains("Cannot read"));
    }

    #[test]
    fn url_flag_beats_everything_else() {
        let e = resolve(Some("http://10.0.0.9:1234"), Some("/nonexistent"))
            .unwrap();
        assert_eq!(e.addrs, vec![sock("10.0.0.9:1234")]);
    }

    #[test]
    fn named_config_that_cannot_be_used_is_an_error() {
        // Silently falling back would hide the operator's typo.
        assert!(resolve(None, Some("/nonexistent/netom.conf")).is_err());
    }
}
