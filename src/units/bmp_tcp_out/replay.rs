//! Owned, bounded provenance for delayed BMP replay. No snapshot owns a RIB,
//! input handler, client or mutable registration. A shared Arc pins only the
//! metadata needed to encode the original session's messages.
use super::client_state::INGRESS_CACHE_CAPACITY;
use crate::{
    ingress::{register::Register, IngressId, IngressInfo},
    payload::Update,
};
use smallvec::SmallVec;
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};

pub(crate) trait IngressLookup: Send + Sync {
    fn get(&self, id: IngressId) -> Option<IngressInfo>;
    fn session_identity(&self, id: IngressId) -> Option<(IngressId, u64)> {
        let source = self.get(id)?;
        let emit = if source.ingress_type
            == Some(crate::ingress::IngressType::BgpPath)
        {
            source.parent_ingress?
        } else {
            id
        };
        Some((emit, self.get(emit)?.history_generation))
    }
}
impl IngressLookup for Register {
    fn get(&self, id: IngressId) -> Option<IngressInfo> {
        Register::get(self, id)
    }
    fn session_identity(&self, id: IngressId) -> Option<(IngressId, u64)> {
        Register::session_identity(self, id)
    }
}
impl<T: IngressLookup> IngressLookup for Arc<T> {
    fn get(&self, id: IngressId) -> Option<IngressInfo> {
        (**self).get(id)
    }
    fn session_identity(&self, id: IngressId) -> Option<(IngressId, u64)> {
        (**self).session_identity(id)
    }
}

pub(crate) struct Snapshot {
    entries: Vec<(IngressId, IngressInfo)>,
    bytes: usize,
}
#[derive(Default)]
pub(crate) struct ReplayIdentities {
    snapshots: SmallVec<[Arc<Snapshot>; 1]>,
}
impl IngressLookup for ReplayIdentities {
    fn get(&self, id: IngressId) -> Option<IngressInfo> {
        self.snapshots.iter().find_map(|s| {
            s.entries
                .iter()
                .find(|(key, _)| *key == id)
                .map(|(_, info)| info.clone())
        })
    }
}
impl ReplayIdentities {
    // Conservative accounting intentionally charges shared provenance to each
    // queued event. It bounds retention even if every event has a unique peer.
    pub(crate) fn bytes(&self) -> usize {
        self.snapshots.iter().map(|s| s.bytes).sum()
    }
}

#[derive(Default)]
pub(crate) struct SnapshotCache(HashMap<IngressId, Weak<Snapshot>>);
impl SnapshotCache {
    pub(crate) fn capture(
        &mut self,
        update: &Update,
        registry: &Register,
    ) -> Option<ReplayIdentities> {
        let mut sources: SmallVec<
            [(IngressId, Option<&IngressInfo>, bool); 1],
        > = SmallVec::new();
        match update {
            Update::Single(p) => sources.push((p.ingress_id, None, false)),
            Update::Bulk(ps) => {
                sources.extend(ps.iter().map(|p| (p.ingress_id, None, false)))
            }
            Update::Withdraw(id, _) => sources.push((*id, None, true)),
            Update::WithdrawBulk(entries) => sources.extend(
                entries.iter().map(|(id, info)| (*id, info.as_ref(), true)),
            ),
            Update::IngressReappeared(id)
            | Update::PeerStats { ingress_id: id, .. }
            | Update::RouteMonitoringRaw { ingress_id: id, .. } => {
                sources.push((*id, None, false))
            }
            _ => {}
        }
        let mut result = ReplayIdentities::default();
        for (id, inline, down) in sources {
            if result.get(id).is_some() {
                continue;
            }
            let cached = self.0.get(&id).and_then(Weak::upgrade);
            // A queued teardown belongs to the generation preceding it, even
            // if the mutable registry has already been claimed by a reconnect.
            let snapshot = if inline.is_none() && down && cached.is_some() {
                cached.unwrap()
            } else if let Some(cached) = cached.filter(|s| {
                inline.is_none() && registry.snapshot_matches(&s.entries)
            }) {
                cached
            } else {
                let entries = match registry.snapshot_lineage(id, inline) {
                    Some(entries) => entries,
                    // A known peer's cached wire header is sufficient for
                    // Peer Down. send_peer_down must fail closed otherwise.
                    None if down => continue,
                    None => return None,
                };
                let bytes = entries
                    .iter()
                    .map(|(_, info)| {
                        std::mem::size_of::<IngressInfo>()
                            + serde_json::to_vec(info)
                                .map(|s| s.len())
                                .unwrap_or(0)
                    })
                    .sum::<usize>()
                    + std::mem::size_of::<Snapshot>();
                Arc::new(Snapshot { entries, bytes })
            };
            if self.0.len() >= INGRESS_CACHE_CAPACITY
                && !self.0.contains_key(&id)
            {
                self.0.clear();
            }
            self.0.insert(id, Arc::downgrade(&snapshot));
            result.snapshots.push(snapshot);
        }
        Some(result)
    }
}

pub(crate) struct BufferedUpdate {
    pub(crate) update: Update,
    pub(crate) identities: ReplayIdentities,
}

#[cfg(test)]
mod tests {
    use super::super::{
        client_handler::send_update_to_client, client_state::ClientState,
        unit::FanInPeerDistinguisher,
    };
    use super::*;
    use crate::{
        ingress::{register::IngressState, IngressType},
        payload::{Payload, RotondaPaMap, RotondaRoute},
    };
    use inetnum::asn::Asn;
    use rotonda_store::prefix_record::RouteStatus;
    use tokio::sync::mpsc;

    fn peer(asn: u32) -> IngressInfo {
        IngressInfo::new()
            .with_ingress_type(IngressType::BgpViaBmp)
            .with_remote_addr(
                "192.0.2.1".parse::<std::net::IpAddr>().unwrap(),
            )
            .with_remote_asn(Asn::from_u32(asn))
            .with_state(IngressState::Connected)
    }
    fn route(id: u32) -> Update {
        let prefix: inetnum::addr::Prefix = "203.0.113.0/24".parse().unwrap();
        Update::Single(Payload::new(
            RotondaRoute::Ipv4Unicast(
                prefix.try_into().unwrap(),
                RotondaPaMap::empty_path_attributes(),
            ),
            None,
            id,
            RouteStatus::Active,
        ))
    }
    #[tokio::test]
    async fn replay_keeps_original_headers_across_retirement_and_same_id_reconnect(
    ) {
        let registry = Register::default();
        registry.update_info(7, peer(65001));
        let (tx, mut rx) = mpsc::channel(16);
        let client = Arc::new(ClientState::new(
            "127.0.0.1:1234".parse().unwrap(),
            tx,
            100,
            1_000_000,
        ));
        assert!(matches!(
            client.buffer_update_if_dumping(route(7), &registry).await,
            super::super::client_state::BufferUpdateResult::Buffered
        ));
        registry.mark_disconnected(7);
        client
            .buffer_update_if_dumping(Update::Withdraw(7, None), &registry)
            .await;
        registry.update_info(7, peer(65002));
        client
            .buffer_update_if_dumping(Update::IngressReappeared(7), &registry)
            .await;
        client.buffer_update_if_dumping(route(7), &registry).await;
        registry.remove(7); // faster GC may run before a slow client replays
        let queued = client.take_buffered_updates().await;
        for item in queued {
            assert!(
                send_update_to_client(
                    &client,
                    &item.update,
                    &item.identities,
                    false,
                    FanInPeerDistinguisher::default(),
                    false
                )
                .await
            );
        }
        let mut messages = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            messages.push(msg);
        }
        assert_eq!(
            messages.iter().map(|m| m[5]).collect::<Vec<_>>(),
            vec![3, 0, 2, 3, 0]
        );
        for (msg, asn) in
            messages.iter().zip([65001u32, 65001, 65001, 65002, 65002])
        {
            assert_eq!(
                u32::from_be_bytes(msg[32..36].try_into().unwrap()),
                asn
            );
        }
        assert!(!client
            .disconnect_pending
            .load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test]
    async fn child_snapshot_retains_parent_and_is_released_after_cancellation(
    ) {
        let registry = Register::default();
        registry.update_info(7, peer(65001));
        registry.update_info(
            8,
            IngressInfo::new()
                .with_ingress_type(IngressType::BgpPath)
                .with_parent_ingress(7u32)
                .with_path_id(33u32),
        );
        let mut cache = SnapshotCache::default();
        let identities = cache.capture(&route(8), &registry).unwrap();
        let weak = Arc::downgrade(&identities.snapshots[0]);
        registry.remove(8);
        registry.remove(7);
        assert_eq!(identities.session_identity(8), Some((7, 0)));
        assert_eq!(identities.get(8).unwrap().path_id, Some(33));
        assert_eq!(
            identities.get(7).unwrap().remote_asn,
            Some(Asn::from_u32(65001))
        );
        drop(identities);
        assert!(
            weak.upgrade().is_none(),
            "the weak cache must not pin retired session metadata"
        );
    }

    #[tokio::test]
    async fn missing_peer_down_identity_disconnects_instead_of_using_default_header(
    ) {
        let registry = Arc::new(Register::default());
        let (tx, mut rx) = mpsc::channel(4);
        let client = Arc::new(ClientState::new(
            "127.0.0.1:1234".parse().unwrap(),
            tx,
            10,
            10000,
        ));
        client.add_known_peer(7).await;
        assert!(
            !send_update_to_client(
                &client,
                &Update::Withdraw(7, None),
                &registry,
                false,
                FanInPeerDistinguisher::default(),
                false
            )
            .await
        );
        assert!(rx.try_recv().is_err());
        assert!(client
            .disconnect_pending
            .load(std::sync::atomic::Ordering::Relaxed));
    }
    #[tokio::test]
    async fn older_generation_cannot_reopen_peer_after_new_session() {
        let registry = Register::default();
        registry.update_info(7, peer(65001));
        let mut cache = SnapshotCache::default();
        let old = cache.capture(&route(7), &registry).unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        let client = Arc::new(ClientState::new(
            "127.0.0.1:1234".parse().unwrap(),
            tx,
            100,
            1_000_000,
        ));
        assert!(
            send_update_to_client(
                &client,
                &route(7),
                &old,
                false,
                FanInPeerDistinguisher::Off,
                false
            )
            .await
        );
        registry.mark_disconnected(7);
        registry.update_info(7, peer(65002));
        let new = cache.capture(&route(7), &registry).unwrap();
        assert!(
            send_update_to_client(
                &client,
                &route(7),
                &new,
                false,
                FanInPeerDistinguisher::Off,
                false
            )
            .await
        );
        while rx.try_recv().is_ok() {}
        assert!(
            !send_update_to_client(
                &client,
                &route(7),
                &old,
                false,
                FanInPeerDistinguisher::Off,
                false
            )
            .await
        );
        assert!(
            rx.try_recv().is_err(),
            "no stale Peer Up or announcement may escape"
        );
    }
}
