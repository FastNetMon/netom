use super::{
    config::Config,
    event::{ip_bytes, Event},
    spool::{self, Segment, Spool},
    transport::Transport,
};
use crate::{
    comms::{AnyDirectUpdate, DirectLink, DirectUpdate, Terminated},
    ingress::{IngressInfo, Register},
    manager::{Component, TargetCommand, WaitPoint},
    payload::{Payload, RotondaRoute, Update, UpstreamStatus},
};
use async_trait::async_trait;
use non_empty_vec::NonEmpty;
use rotonda_store::prefix_record::RouteStatus;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        mpsc as blocking, Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Deserialize)]
pub struct ClickHouse {
    sources: NonEmpty<DirectLink>,
    #[serde(flatten)]
    config: Config,
}

#[derive(Debug, Default)]
struct Metrics {
    accepted: AtomicU64,
    inserted: AtomicU64,
    errors: AtomicU64,
    unsupported: AtomicU64,
    missing_identity: AtomicU64,
    stopped: AtomicU64,
    disk_bytes: AtomicU64,
    queue_bytes: AtomicU64,
    healthy: AtomicU64,
}
impl crate::metrics::Source for Metrics {
    fn append(&self, name: &str, target: &mut crate::metrics::Target) {
        use crate::metrics::{Metric, MetricType, MetricUnit};
        for (key, help, value, gauge) in [
            (
                "clickhouse_accepted",
                "Observations admitted to exporter memory",
                &self.accepted,
                false,
            ),
            (
                "clickhouse_inserted",
                "Rows acknowledged, including control and identity rows",
                &self.inserted,
                false,
            ),
            (
                "clickhouse_errors",
                "Spool or ClickHouse errors",
                &self.errors,
                false,
            ),
            (
                "clickhouse_unsupported",
                "Unsupported route families",
                &self.unsupported,
                false,
            ),
            (
                "clickhouse_missing_identity",
                "Observations without registry metadata",
                &self.missing_identity,
                false,
            ),
            (
                "clickhouse_stopped",
                "Observations rejected after exporter shutdown/failure",
                &self.stopped,
                false,
            ),
            (
                "clickhouse_spool_bytes",
                "Approximate pending spool bytes",
                &self.disk_bytes,
                true,
            ),
            (
                "clickhouse_queue_bytes",
                "Accounted bytes waiting for the spool writer",
                &self.queue_bytes,
                true,
            ),
            (
                "clickhouse_healthy",
                "Last spool/insert operation succeeded",
                &self.healthy,
                true,
            ),
        ] {
            let metric = Metric::new(
                key,
                help,
                if gauge {
                    MetricType::Gauge
                } else {
                    MetricType::Counter
                },
                if gauge {
                    MetricUnit::State
                } else {
                    MetricUnit::Total
                },
            );
            target.append_simple(&metric, Some(name), value.load(Relaxed));
        }
    }
}

type CacheKey = (u32, u64, u64, u64);
#[derive(Debug, Default)]
struct Identities {
    entries: HashMap<CacheKey, Arc<str>>,
    bytes: usize,
}

#[derive(Debug)]
struct Receiver {
    tx: blocking::Sender<Queued>,
    budget: Arc<Semaphore>,
    register: Arc<Register>,
    identities: Mutex<Identities>,
    stream: [u8; 16],
    epoch: [u8; 16],
    collector: String,
    metrics: Arc<Metrics>,
    anchor: (Instant, i64),
}
#[derive(Debug)]
struct Queued {
    event: Event,
    _permit: OwnedSemaphorePermit,
    _accounting: QueueAccounting,
}
#[derive(Debug)]
struct QueueAccounting {
    bytes: u64,
    metrics: Arc<Metrics>,
}
impl Drop for QueueAccounting {
    fn drop(&mut self) {
        self.metrics.queue_bytes.fetch_sub(self.bytes, Relaxed);
    }
}

impl Receiver {
    fn identity(
        &self,
        id: u32,
        inline: Option<&IngressInfo>,
    ) -> ([u8; 16], Option<u32>, Arc<str>) {
        self.register.with_history_info(id, |session, path, found, router| {
            let info = inline.or(found);
            let generation = info.map_or(0, |i| i.history_generation);
            let revision = info.map_or(0, |i| i.history_revision);
            let key = (session, generation, revision, router.map_or(0, |i| i.history_revision));
            let mut h = Sha256::new();
            h.update(self.stream); h.update(self.epoch); h.update(session.to_le_bytes()); h.update(generation.to_le_bytes());
            let peer = h.finalize()[..16].try_into().unwrap();
            let mut cache = self.identities.lock().unwrap();
            if let Some(json) = cache.entries.get(&key) { return (peer, path, json.clone()); }
            if info.is_none() { self.metrics.missing_identity.fetch_add(1, Relaxed); }
            let json: Arc<str> = serde_json::json!({"collector": self.collector, "session_ingress": session, "generation": generation, "peer": info, "router": router, "missing": info.is_none()}).to_string().into();
            // Whole-cache eviction is bounded O(cache size), never O(register
            // size). Generations live in the register and survive this eviction.
            if cache.entries.len() >= 65536 || cache.bytes + json.len() + 128 > 16 << 20 { cache.entries.clear(); cache.bytes = 0; }
            if json.len() < 256 << 10 {
                cache.bytes += json.len() + 128;
                cache.entries.insert(key, json.clone());
            }
            (peer, path, json)
        })
    }
    fn base(&self, id: u32, kind: u8, inline: Option<&IngressInfo>) -> Event {
        let (peer, path_id, identity) = self.identity(id, inline);
        Event {
            stream: self.stream,
            epoch: self.epoch,
            received_ms: chrono::Utc::now().timestamp_millis(),
            kind,
            peer,
            ingress: id,
            path_id,
            identity,
            ..Default::default()
        }
    }
    async fn send(&self, event: Event) {
        // Count shared buffers conservatively as owned, preventing Arc retention
        // from making the queue an unbounded attribute or identity store.
        let bytes = (std::mem::size_of::<Queued>()
            + event.attrs.len()
            + event.identity.len()
            + 128) as u64;
        if bytes > 1 << 20 {
            self.metrics.errors.fetch_add(1, Relaxed);
            log::error!("clickhouse-out: event exceeds 1 MiB input bound");
            return;
        }
        let Ok(permit) =
            self.budget.clone().acquire_many_owned(bytes as u32).await
        else {
            self.metrics.stopped.fetch_add(1, Relaxed);
            return;
        };
        self.metrics.queue_bytes.fetch_add(bytes, Relaxed);
        if self
            .tx
            .send(Queued {
                event,
                _permit: permit,
                _accounting: QueueAccounting {
                    bytes,
                    metrics: self.metrics.clone(),
                },
            })
            .is_err()
        {
            self.metrics.stopped.fetch_add(1, Relaxed);
        } else {
            self.metrics.accepted.fetch_add(1, Relaxed);
        }
    }
    async fn route(&self, payload: Payload) {
        let afi = match &payload.rx_value {
            RotondaRoute::Ipv4Unicast(..) => 1,
            RotondaRoute::Ipv6Unicast(..) => 2,
            _ => {
                self.metrics.unsupported.fetch_add(1, Relaxed);
                return;
            }
        };
        let prefix = payload.rx_value.index_prefix();
        let mut e = self.base(
            payload.ingress_id,
            if payload.route_status == RouteStatus::Withdrawn {
                2
            } else {
                1
            },
            None,
        );
        // Source Instant mapped through a process anchor. This is receive time,
        // not the router's BMP timestamp, and is immune to later wall-clock steps.
        e.received_ms = if payload.received >= self.anchor.0 {
            self.anchor.1.saturating_add(
                payload.received.duration_since(self.anchor.0).as_millis()
                    as i64,
            )
        } else {
            self.anchor.1.saturating_sub(
                self.anchor.0.duration_since(payload.received).as_millis()
                    as i64,
            )
        };
        e.class = 1;
        e.afi = afi;
        e.safi = 1;
        e.prefix = ip_bytes(prefix.addr());
        e.prefix_len = prefix.len();
        e.attrs = payload.rx_value.rotonda_pamap().raw_arc();
        self.send(e).await;
    }
}
impl AnyDirectUpdate for Receiver {}
#[async_trait]
impl DirectUpdate for Receiver {
    async fn direct_update(&self, update: Update) {
        match update {
            Update::Single(p) => self.route(p).await,
            Update::Bulk(ps) => {
                for p in *ps {
                    self.route(p).await;
                }
            }
            Update::Withdraw(id, family) => {
                let mut e =
                    self.base(id, if family.is_some() { 5 } else { 4 }, None);
                if let Some(family) = family {
                    use routecore::bgp::types::AfiSafiType;
                    match family {
                        AfiSafiType::Ipv4Unicast => {
                            e.afi = 1;
                            e.safi = 1;
                        }
                        AfiSafiType::Ipv6Unicast => {
                            e.afi = 2;
                            e.safi = 1;
                        }
                        _ => {
                            self.metrics.unsupported.fetch_add(1, Relaxed);
                            return;
                        }
                    }
                }
                self.send(e).await;
            }
            Update::WithdrawBulk(ids) => {
                for (id, info) in *ids {
                    self.send(self.base(id, 4, info.as_ref())).await;
                }
            }
            Update::IngressReappeared(id) => {
                self.send(self.base(id, 6, None)).await
            }
            Update::UpstreamStatusChange(UpstreamStatus::EndOfStream {
                ingress_id,
            }) => self.send(self.base(ingress_id, 9, None)).await,
            // Raw BMP duplicates parsed updates; exporting both doubles history.
            _ => {}
        }
    }
}

fn expiry(ms: i64, retention_hours: u32) -> u32 {
    // Hour-aligned expiry permits whole-part TTL drops and ensures identity
    // rows retained alongside their segment never expire ahead of route rows.
    let hour_end = ms
        .div_euclid(3_600_000)
        .saturating_add(1)
        .saturating_mul(3600);
    hour_end
        .saturating_add(i64::from(retention_hours) * 3600)
        .clamp(0, u32::MAX as i64) as u32
}

fn writer(
    spool: Arc<Spool>,
    config: Config,
    rx: blocking::Receiver<Queued>,
    stop: Arc<AtomicBool>,
    metrics: Arc<Metrics>,
    epoch: [u8; 16],
) -> anyhow::Result<()> {
    let mut segment: Option<Segment> = None;
    let mut frame = Vec::with_capacity(1 << 20);
    let mut frame_rows = 0u32;
    let mut seen = HashSet::new();
    let mut seq = 0u64;
    let mut started = Instant::now();
    let mut synced = Instant::now();
    let mut shutdown = None;
    let mut current: Option<Queued> = None;
    let mut first = true;
    let mut ended = false;
    let mut pending_event: Option<Event> = None;
    let mut last_space_check = Instant::now() - Duration::from_secs(1);
    let mut full = false;
    loop {
        if stop.load(Relaxed) && shutdown.is_none() {
            shutdown = Some(Instant::now());
        }
        if shutdown.is_some_and(|t: Instant| {
            t.elapsed().as_secs() >= config.shutdown_seconds
        }) {
            anyhow::bail!("spool shutdown deadline exceeded; memory-only observations may be lost");
        }
        if last_space_check.elapsed() >= Duration::from_millis(500) {
            let usage = spool::usage(&spool.dir)?;
            metrics.disk_bytes.store(usage, Relaxed);
            let available = fs2::available_space(&spool.dir)?;
            let total = fs2::total_space(&spool.dir)?;
            full = usage.saturating_add((spool::MAX_FRAME * 2) as u64)
                > config.spool_bytes
                || available
                    < config.reserve_bytes.max(total / 20)
                        + (spool::MAX_FRAME * 2) as u64;
            last_space_check = Instant::now();
        }
        if full {
            metrics.healthy.store(0, Relaxed);
            // Reserve headroom is for flushing the one bounded memory frame,
            // making its segment replayable, and allowing the sink to drain.
            if let Some(s) = segment.as_mut() {
                if !frame.is_empty() {
                    if let Err(e) = s.append(&frame, frame_rows) {
                        log::error!(
                            "clickhouse-out disk full; retaining frame: {e}"
                        );
                        std::thread::sleep(Duration::from_millis(250));
                        continue;
                    }
                    frame.clear();
                    frame_rows = 0;
                }
            }
            if let Some(s) = segment.take() {
                s.seal()?;
                seen.clear();
            }
            std::thread::sleep(Duration::from_millis(250));
            continue;
        }
        if current.is_none() && pending_event.is_none() && !first && !ended {
            current = rx.recv_timeout(Duration::from_millis(100)).ok();
        }
        let idle = current.is_none() && pending_event.is_none();
        let done = idle && stop.load(Relaxed);
        let event = if pending_event.is_some() {
            pending_event.take()
        } else if first {
            first = false;
            Some(Event { stream: spool.stream, epoch, received_ms: chrono::Utc::now().timestamp_millis(), kind: 7, identity: format!("{{\"collector\":{},\"coverage\":\"live observations; no initial snapshot\"}}", serde_json::to_string(&config.collector_id)?).into(), ..Default::default() })
        } else if let Some(q) = current.take() {
            Some(q.event)
        } else if done && !ended {
            ended = true;
            Some(Event {
                stream: spool.stream,
                epoch,
                received_ms: chrono::Utc::now().timestamp_millis(),
                kind: 8,
                ..Default::default()
            })
        } else {
            None
        };
        if let Some(mut event) = event {
            if segment.is_none() {
                match Segment::create(&spool.dir) {
                    Ok(s) => segment = Some(s),
                    Err(e) => {
                        log::error!("clickhouse-out cannot create segment; applying backpressure: {e}");
                        metrics.errors.fetch_add(1, Relaxed);
                        pending_event = Some(event);
                        std::thread::sleep(Duration::from_millis(250));
                        continue;
                    }
                }
                started = Instant::now();
            }
            event.expires = expiry(event.received_ms, config.retention_hours);
            // Self-contained identity in each segment, with the same event time
            // as its first reference. Refresh on identity revision as well.
            let identity_hash: [u8; 32] =
                Sha256::digest(event.identity.as_bytes()).into();
            if event.peer != [0; 16]
                && seen.insert((
                    event.peer,
                    identity_hash,
                    event.received_ms.div_euclid(3_600_000),
                ))
            {
                let identity = Event {
                    stream: event.stream,
                    epoch,
                    seq,
                    received_ms: event.received_ms,
                    expires: event.expires,
                    kind: 3,
                    peer: event.peer,
                    ingress: event.ingress,
                    identity: event.identity.clone(),
                    ..Default::default()
                };
                identity.encode(&mut frame);
                seq += 1;
                frame_rows += 1;
                if seen.len() >= 65536 {
                    seen.clear();
                }
            }
            if event.peer != [0; 16] {
                event.identity = Arc::from("");
            }
            event.seq = seq;
            seq += 1;
            event.encode(&mut frame);
            frame_rows += 1;
        }
        let seal = segment.as_ref().is_some_and(|s| {
            s.rows + frame_rows >= config.batch_rows
                || s.raw_bytes + frame.len() as u64 >= config.batch_bytes
                || started.elapsed().as_secs() >= config.flush_seconds
        }) || done;
        if !frame.is_empty()
            && (frame.len() >= 1 << 20
                || synced.elapsed() >= Duration::from_millis(500)
                || seal)
        {
            let s = segment.as_mut().expect("nonempty frame has a segment");
            // On a disk write error preserve this frame, stop admission, and
            // leave the unattempted segment recoverable for the next startup.
            if let Err(e) = s.append(&frame, frame_rows) {
                log::error!("clickhouse-out spool write failed; applying backpressure: {e}");
                metrics.errors.fetch_add(1, Relaxed);
                full = true;
                last_space_check = Instant::now();
                continue;
            }
            if synced.elapsed() >= Duration::from_millis(500) || seal {
                s.sync()?;
                synced = Instant::now();
            }
            frame.clear();
            frame_rows = 0;
            last_space_check = Instant::now() - Duration::from_secs(1);
        }
        // A frame may have flushed on size before the sync interval. Keep
        // syncing its file on time even when no new events arrive afterward.
        if synced.elapsed() >= Duration::from_millis(500) {
            if let Some(s) = segment.as_ref() {
                s.sync()?;
            }
            synced = Instant::now();
        }
        if seal {
            if let Some(s) = segment.take() {
                s.seal()?;
                seen.clear();
            }
            metrics.disk_bytes.store(spool::usage(&spool.dir)?, Relaxed);
        }
        if done && ended {
            return Ok(());
        }
    }
}

async fn uploader(spool: Arc<Spool>, config: Config, metrics: Arc<Metrics>) {
    let transport = match Transport::new(config) {
        Ok(t) => t,
        Err(e) => {
            log::error!("clickhouse-out client: {e}");
            return;
        }
    };
    let mut checked = false;
    let mut backoff = 1;
    loop {
        let result: anyhow::Result<()> = async {
            if !checked {
                transport.check().await?;
                checked = true;
            }
            let dir = spool.dir.clone();
            let files =
                tokio::task::spawn_blocking(move || spool::pending(&dir))
                    .await??;
            for path in files {
                let rows = transport.insert(path.clone()).await?;
                let dir = spool.dir.clone();
                let remaining = tokio::task::spawn_blocking(
                    move || -> std::io::Result<u64> {
                        std::fs::remove_file(&path)?;
                        spool::sync_dir(&dir)?;
                        spool::usage(&dir)
                    },
                )
                .await??;
                metrics.disk_bytes.store(remaining, Relaxed);
                metrics.inserted.fetch_add(rows as u64, Relaxed);
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                metrics.healthy.store(1, Relaxed);
                backoff = 1;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => {
                metrics.errors.fetch_add(1, Relaxed);
                metrics.healthy.store(0, Relaxed);
                log::error!(
                    "clickhouse-out replay failed; retaining segment: {e:#}"
                );
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
            }
        }
    }
}

impl ClickHouse {
    pub async fn run(
        mut self,
        mut component: Component,
        mut commands: mpsc::Receiver<TargetCommand>,
        waitpoint: WaitPoint,
    ) -> Result<(), Terminated> {
        let prepared = (|| -> anyhow::Result<Spool> {
            self.config.validate().map_err(anyhow::Error::msg)?;
            Spool::open(&self.config.spool_dir, &self.config.binding())
                .map_err(Into::into)
        })();
        let spool = match prepared {
            Ok(s) => Arc::new(s),
            Err(e) => {
                log::error!(
                    "{}: ClickHouse startup failed: {e:#}",
                    component.name()
                );
                waitpoint.running().await;
                return Err(Terminated);
            }
        };
        let metrics = Arc::new(Metrics::default());
        metrics
            .disk_bytes
            .store(spool::usage(&spool.dir).unwrap_or(0), Relaxed);
        component.register_metrics(metrics.clone());
        let (tx, rx) = blocking::channel();
        let epoch = *uuid::Uuid::new_v4().as_bytes();
        let receiver = Arc::new(Receiver {
            tx,
            budget: Arc::new(Semaphore::new(
                self.config.queue_bytes as usize,
            )),
            register: component.ingresses().clone(),
            identities: Mutex::default(),
            stream: spool.stream,
            epoch,
            collector: self.config.collector_id.clone(),
            metrics: metrics.clone(),
            anchor: (Instant::now(), chrono::Utc::now().timestamp_millis()),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let mut writer = {
            let (spool, config, stop, metrics, budget) = (
                spool.clone(),
                self.config.clone(),
                stop.clone(),
                metrics.clone(),
                receiver.budget.clone(),
            );
            tokio::task::spawn_blocking(move || {
                let result =
                    writer(spool, config, rx, stop, metrics.clone(), epoch);
                if result.is_err() {
                    metrics.errors.fetch_add(1, Relaxed);
                    metrics.healthy.store(0, Relaxed);
                }
                budget.close();
                result
            })
        };
        let uploader = tokio::spawn(uploader(
            spool.clone(),
            self.config.clone(),
            metrics,
        ));
        for source in self.sources.iter_mut() {
            if let Err(e) = source.connect(receiver.clone(), false).await {
                log::error!("clickhouse-out link failed: {e:?}");
            }
        }
        waitpoint.running().await;
        let mut writer_done = false;
        loop {
            tokio::select! {
                result = &mut writer, if !writer_done => { writer_done = true; log::error!("clickhouse-out writer stopped: {result:?}"); break; },
                command = commands.recv() => match command {
                    Some(TargetCommand::ReportLinks { report }) => report.set_sources(&self.sources),
                    Some(TargetCommand::Reconfigure { .. }) => log::warn!("clickhouse-out: configuration reload requires restart; retaining existing configuration and spool destination"),
                    Some(TargetCommand::Terminate) | None => break,
                }
            }
        }
        receiver.budget.close();
        stop.store(true, Relaxed);
        for source in self.sources.iter_mut() {
            source.disconnect().await;
        }
        if !writer_done {
            match writer.await {
                Ok(Ok(())) => {}
                result => log::error!("clickhouse-out shutdown: {result:?}"),
            }
        }
        // Spooling is the shutdown guarantee; database delivery resumes later.
        uploader.abort();
        let _ = uploader.await;
        Err(Terminated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::{register::IngressState, IngressType};

    fn receiver(
        register: Arc<Register>,
    ) -> (Receiver, blocking::Receiver<Queued>) {
        let (tx, rx) = blocking::channel();
        (
            Receiver {
                tx,
                budget: Arc::new(Semaphore::new(2 << 20)),
                register,
                identities: Mutex::default(),
                stream: [1; 16],
                epoch: [2; 16],
                collector: "test".into(),
                metrics: Arc::default(),
                anchor: (
                    Instant::now(),
                    chrono::Utc::now().timestamp_millis(),
                ),
            },
            rx,
        )
    }

    #[test]
    fn cache_eviction_does_not_change_keys_but_reconnect_does() {
        let reg = Arc::new(Register::new());
        reg.update_info(
            1,
            IngressInfo::default()
                .with_ingress_type(IngressType::Bgp)
                .with_state(IngressState::Connected),
        );
        reg.update_info(
            2,
            IngressInfo::default()
                .with_ingress_type(IngressType::BgpPath)
                .with_parent_ingress(1u32)
                .with_path_id(7u32),
        );
        let (r, _) = receiver(reg.clone());
        let first = r.identity(2, None);
        assert_eq!(first.1, Some(7));
        assert_eq!(first.0, r.identity(1, None).0);
        r.identities.lock().unwrap().entries.clear();
        assert_eq!(first.0, r.identity(2, None).0);
        reg.update_info(
            1,
            IngressInfo::default().with_state(IngressState::Disconnected),
        );
        reg.update_info(
            1,
            IngressInfo::default().with_state(IngressState::Connected),
        );
        assert_ne!(first.0, r.identity(2, None).0);
    }

    #[tokio::test]
    async fn shutdown_seals_memory_and_releases_all_queue_permits() {
        let dir = std::env::temp_dir()
            .join(format!("netom-ch-writer-{}", uuid::Uuid::new_v4()));
        let spool = Arc::new(Spool::open(&dir, "test").unwrap());
        let config = Config {
            spool_dir: dir.clone(),
            reserve_bytes: 0,
            batch_rows: 3,
            ..Default::default()
        };
        let (r, rx) = receiver(Arc::new(Register::new()));
        for _ in 0..10 {
            r.send(r.base(1, 4, None)).await;
        }
        assert!(r.metrics.queue_bytes.load(Relaxed) > 0);
        let metrics = r.metrics.clone();
        tokio::task::spawn_blocking(move || {
            writer(
                spool,
                config,
                rx,
                Arc::new(AtomicBool::new(true)),
                metrics,
                [2; 16],
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(r.metrics.queue_bytes.load(Relaxed), 0);
        assert_eq!(r.budget.available_permits(), 2 << 20);
        let paths = spool::pending(&dir).unwrap();
        let count: u32 =
            paths.iter().map(|p| spool::validate(p).unwrap().1).sum();
        assert!(
            count >= 13,
            "ten controls, start/end, and repeated segment identities"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn full_spool_backpressures_until_shutdown_deadline() {
        let dir = std::env::temp_dir()
            .join(format!("netom-ch-full-{}", uuid::Uuid::new_v4()));
        let spool = Arc::new(Spool::open(&dir, "test").unwrap());
        let config = Config {
            spool_dir: dir.clone(),
            spool_bytes: 1,
            reserve_bytes: 0,
            shutdown_seconds: 1,
            ..Default::default()
        };
        let (r, rx) = receiver(Arc::new(Register::new()));
        r.send(r.base(1, 4, None)).await;
        let metrics = r.metrics.clone();
        let result = tokio::task::spawn_blocking(move || {
            writer(
                spool,
                config,
                rx,
                Arc::new(AtomicBool::new(true)),
                metrics,
                [2; 16],
            )
        })
        .await
        .unwrap();
        assert!(result.is_err());
        assert_eq!(r.metrics.queue_bytes.load(Relaxed), 0);
        assert_eq!(r.budget.available_permits(), 2 << 20);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
