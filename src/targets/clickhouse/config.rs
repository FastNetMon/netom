use serde::Deserialize;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub endpoint: String,
    pub database: String,
    pub table: String,
    pub username: String,
    // Read at startup; credentials are never written to the spool manifest.
    pub password_file: Option<PathBuf>,
    pub collector_id: String,
    pub spool_dir: PathBuf,
    pub spool_bytes: u64,
    pub reserve_bytes: u64,
    pub queue_bytes: u32,
    pub batch_rows: u32,
    pub batch_bytes: u64,
    pub flush_seconds: u64,
    pub retention_hours: u32,
    pub request_timeout_seconds: u64,
    pub shutdown_seconds: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:8123".into(),
            database: "netom".into(),
            table: "events".into(),
            username: "default".into(),
            password_file: None,
            collector_id: String::new(),
            spool_dir: "/var/lib/netom/clickhouse".into(),
            spool_bytes: 32 << 30,
            reserve_bytes: 5 << 30,
            queue_bytes: 64 << 20,
            batch_rows: 100_000,
            batch_bytes: 32 << 20,
            flush_seconds: 5,
            retention_hours: 24,
            request_timeout_seconds: 60,
            shutdown_seconds: 30,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<(), String> {
        for id in [&self.database, &self.table] {
            if id.is_empty()
                || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(
                    "database/table must be plain SQL identifiers".into()
                );
            }
        }
        let u =
            reqwest::Url::parse(&self.endpoint).map_err(|e| e.to_string())?;
        if !["http", "https"].contains(&u.scheme())
            || u.host_str().is_none()
            || u.query().is_some()
            || u.fragment().is_some()
            || !u.username().is_empty()
            || u.password().is_some()
        {
            return Err("endpoint must be an HTTP(S) URL without credentials, query or fragment".into());
        }
        if self.queue_bytes < 2 << 20
            || self.batch_rows == 0
            || self.batch_rows > 1_000_000
            || self.batch_bytes < 1 << 20
            || self.batch_bytes > 512 << 20
            || self.spool_bytes < self.batch_bytes * 2
            || self.retention_hours == 0
            || self.retention_hours > 8760
            || self.flush_seconds == 0
            || self.flush_seconds > 3600
            || self.request_timeout_seconds == 0
            || self.shutdown_seconds == 0
        {
            return Err(
                "invalid ClickHouse resource limits (see docs/clickhouse.md)"
                    .into(),
            );
        }
        Ok(())
    }
    pub fn binding(&self) -> String {
        // Destination and deterministic insert block settings are immutable for
        // existing segments. Changing credentials is safe across restarts.
        format!(
            "schema=1;endpoint={};database={};table={};collector={};block=v1",
            self.endpoint, self.database, self.table, self.collector_id
        )
    }
}
