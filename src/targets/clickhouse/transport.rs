use super::{config::Config, event::COLUMN_NAMES, spool};
use std::{io, path::PathBuf, time::Duration};
use tokio_stream::wrappers::ReceiverStream;

pub struct Transport {
    client: reqwest::Client,
    config: Config,
    password: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets::clickhouse::event::Event;
    use std::sync::Arc;

    // Run explicitly against an operator-selected test database. Leaves the
    // table intact on failure for inspection; never truncates an existing one.
    #[tokio::test]
    #[ignore = "requires NETOM_CLICKHOUSE_TEST_ENDPOINT and netom_test database"]
    async fn real_clickhouse_binary_roundtrip_and_retry() {
        let endpoint = std::env::var("NETOM_CLICKHOUSE_TEST_ENDPOINT")
            .expect("test endpoint");
        let table = format!("test_{}", uuid::Uuid::new_v4().simple());
        let config = Config {
            endpoint,
            database: "netom_test".into(),
            table: table.clone(),
            ..Default::default()
        };
        let t = Transport::new(config).unwrap();
        let ddl = include_str!("../../../docs/clickhouse/schema.sql")
            .split("CREATE VIEW")
            .next()
            .unwrap()
            .replace(
                "CREATE TABLE events",
                &format!("CREATE TABLE netom_test.{table}"),
            );
        Transport::response(t.request().body(ddl).send().await.unwrap())
            .await
            .unwrap();
        t.check().await.unwrap();
        let dir = std::env::temp_dir()
            .join(format!("netom-ch-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let mut s = spool::Segment::create(&dir).unwrap();
        let mut body = Vec::new();
        for seq in 0..10000 {
            Event {
                seq,
                received_ms: chrono::Utc::now().timestamp_millis(),
                expires: u32::MAX,
                class: 1,
                kind: 1,
                afi: 1,
                safi: 1,
                prefix: "192.0.2.0"
                    .parse()
                    .map(crate::targets::clickhouse::event::ip_bytes)
                    .unwrap(),
                prefix_len: 24,
                path_id: Some(42),
                attrs: Arc::from([0, 1, 128, 99, 3, 0, 255, 128]),
                ..Default::default()
            }
            .encode(&mut body);
        }
        s.append(&body, 10000).unwrap();
        let path = s.seal().unwrap();
        assert_eq!(t.insert(path.clone()).await.unwrap(), 10000);
        assert_eq!(t.insert(path).await.unwrap(), 10000);
        let sql = format!("SELECT count(), uniqExact(event_seq), hex(any(raw_attrs)), any(path_id), toString(any(prefix_addr)) FROM netom_test.{table} FORMAT TabSeparated");
        let result = Transport::response(
            t.request().query(&[("query", sql)]).send().await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            result.trim(),
            "10000\t10000\t80630300FF80\t42\t::ffff:192.0.2.0"
        );
        Transport::response(
            t.request()
                .body(format!("DROP TABLE netom_test.{table}"))
                .send()
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
impl Transport {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let password = config
            .password_file
            .as_ref()
            .map(std::fs::read_to_string)
            .transpose()?
            .unwrap_or_default()
            .trim_end_matches(['\r', '\n'])
            .to_owned();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(config.request_timeout_seconds))
            .build()?;
        Ok(Self {
            client,
            config,
            password,
        })
    }
    fn request(&self) -> reqwest::RequestBuilder {
        self.client
            .post(&self.config.endpoint)
            .basic_auth(&self.config.username, Some(&self.password))
            // A nonempty body forces Content-Length even for URL-only queries.
            // ClickHouse rejects POSTs lacking both length and chunked framing.
            .body("\n")
    }
    async fn response(response: reqwest::Response) -> anyhow::Result<String> {
        let status = response.status();
        // Even HTTP 200 can carry a ClickHouse error in the body. Successful
        // inserts have an empty body. Bound error responses to avoid an OOM.
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                body.len() + chunk.len() <= 65536,
                "oversized ClickHouse response"
            );
            body.extend_from_slice(&chunk);
        }
        let text = String::from_utf8_lossy(&body).into_owned();
        anyhow::ensure!(
            status.is_success(),
            "ClickHouse HTTP {status}: {text}"
        );
        Ok(text)
    }
    pub async fn check(&self) -> anyhow::Result<()> {
        let response = self
            .request()
            .query(&[("query", "SELECT version()")])
            .send()
            .await?;
        let version = Self::response(response).await?;
        let mut v = version.trim().split('.').take(2).map(str::parse::<u32>);
        let major = v.next().transpose()?.unwrap_or(0);
        let minor = v.next().transpose()?.unwrap_or(0);
        anyhow::ensure!(
            (major, minor) >= (25, 8),
            "ClickHouse >=25.8 required; found {version}"
        );
        // Resolve every required column before admitting new observations.
        let sql = format!(
            "SELECT {COLUMN_NAMES} FROM {}.{} LIMIT 0",
            self.config.database, self.config.table
        );
        let result = Self::response(
            self.request().query(&[("query", &sql)]).send().await?,
        )
        .await?;
        anyhow::ensure!(
            result.trim().is_empty(),
            "unexpected schema-check response: {result}"
        );
        let sql = format!("SELECT name, type FROM system.columns WHERE database = '{}' AND table = '{}' FORMAT JSON", self.config.database, self.config.table);
        let body = Self::response(
            self.request().query(&[("query", sql)]).send().await?,
        )
        .await?;
        let description: serde_json::Value = serde_json::from_str(&body)?;
        let types = [
            "UInt16",
            "FixedString(16)",
            "FixedString(16)",
            "UInt64",
            "DateTime64(3, 'UTC')",
            "DateTime",
            "UInt8",
            "UInt8",
            "FixedString(16)",
            "UInt32",
            "Nullable(UInt32)",
            "UInt16",
            "UInt8",
            "IPv6",
            "UInt8",
            "UInt8",
            "UInt8",
            "String",
            "Array(UInt32)",
            "Array(UInt32)",
            "Array(UInt32)",
            "Array(FixedString(12))",
            "Array(FixedString(8))",
            "Nullable(IPv6)",
            "Nullable(UInt32)",
            "Nullable(UInt32)",
            "UInt8",
            "String",
        ];
        let columns = description["data"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("invalid schema response"))?;
        for (name, typ) in COLUMN_NAMES.split(',').zip(types) {
            anyhow::ensure!(
                columns
                    .iter()
                    .any(|c| c["name"] == name && c["type"] == typ),
                "schema mismatch: {name} must have type {typ}"
            );
        }
        // Verify the retry prerequisite on this table (not the global default).
        let sql = format!(
            "SHOW CREATE TABLE {}.{}",
            self.config.database, self.config.table
        );
        let ddl = Self::response(
            self.request().query(&[("query", &sql)]).send().await?,
        )
        .await?;
        anyhow::ensure!(ddl.contains("ENGINE = MergeTree") && ddl.contains("non_replicated_deduplication_window = ") && !ddl.contains("non_replicated_deduplication_window = 0"), "v1 requires local MergeTree with non_replicated_deduplication_window > 0");
        Ok(())
    }
    pub async fn insert(&self, path: PathBuf) -> anyhow::Result<u32> {
        // Validate the entire file before sending even its first byte. Replay
        // also checks frames so detected on-disk corruption is never ACKed.
        let p = path.clone();
        let (token, rows) =
            tokio::task::spawn_blocking(move || spool::validate(&p))
                .await??;
        if rows == 0 {
            return Ok(0);
        }
        let (tx, rx) =
            tokio::sync::mpsc::channel::<Result<bytes::Bytes, io::Error>>(2);
        let reader = tokio::task::spawn_blocking(move || {
            spool::replay(&path, |bytes| {
                tx.blocking_send(Ok(bytes.into())).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "insert cancelled",
                    )
                })
            })
        });
        let sql = format!(
            "INSERT INTO {}.{} ({COLUMN_NAMES}) FORMAT RowBinary",
            self.config.database, self.config.table
        );
        let result = self
            .request()
            .query(&[
                ("query", sql.as_str()),
                ("insert_deduplication_token", &token),
                ("insert_deduplicate", "1"),
                ("async_insert", "0"),
                ("wait_end_of_query", "1"),
                ("input_format_parallel_parsing", "0"),
                ("max_insert_threads", "1"),
                ("max_insert_block_size", "2000000"),
                ("min_insert_block_size_rows", "2000000"),
                ("min_insert_block_size_bytes", "1073741824"),
            ])
            .body(reqwest::Body::wrap_stream(ReceiverStream::new(rx)))
            .send()
            .await;
        // Sending failure drops the request stream and unblocks the reader.
        let response = match result {
            Ok(response) => Self::response(response).await,
            Err(e) => Err(e.into()),
        };
        reader.await??;
        let body = response?;
        anyhow::ensure!(
            body.trim().is_empty(),
            "ClickHouse insert error: {body}"
        );
        Ok(rows)
    }
}
