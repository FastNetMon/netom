//! Serialize per-peer counters into a BMP Statistics Report body.
//!
//! The body is the bytes following the BMP common + per-peer headers
//! in an RFC 7854 §4.8 Statistics Report message. Layout:
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Stats Count                            |
//! +---------------------------------------------------------------+
//! |        Stat Type              |        Stat Len               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Stat Data                             |
//! ~                              ...                              ~
//! ```
//!
//! Per RFC 7854 §4.8, stat data is 4 bytes (counter) for stat types
//! 0–6 and 11–13, 8 bytes (gauge) for 7 and 8, and 11 bytes
//! (AFI:2 + SAFI:1 + gauge:8) for 9 and 10.
//!
//! Netom does not compute most counters (loop checks, RFC 7606
//! treat-as-withdraw, Loc-RIB totals); per the RFC the Stat Data
//! field is just a value, so reporting zero is well-formed and lets
//! receivers consume a stable TLV set across vendors.
use bytes::{BufMut, Bytes, BytesMut};

use crate::ingress::peer_stats::BgpPeerStatsSnapshot;

// RFC 7854 §4.8 stat types.
const STAT_PREFIXES_REJECTED: u16 = 0;
const STAT_DUP_PREFIX_ADV: u16 = 1;
const STAT_DUP_WITHDRAWS: u16 = 2;
const STAT_INVALID_CLUSTER_LIST_LOOPS: u16 = 3;
const STAT_INVALID_AS_PATH_LOOPS: u16 = 4;
const STAT_INVALID_ORIGINATOR_ID: u16 = 5;
const STAT_INVALID_AS_CONFED_LOOPS: u16 = 6;
const STAT_ADJ_RIB_IN: u16 = 7;
const STAT_LOC_RIB: u16 = 8;
const STAT_ADJ_RIB_IN_PER_AFI_SAFI: u16 = 9;
const STAT_LOC_RIB_PER_AFI_SAFI: u16 = 10;
const STAT_UPDATES_TREAT_AS_WITHDRAW: u16 = 11;
const STAT_PREFIXES_TREAT_AS_WITHDRAW: u16 = 12;
const STAT_DUP_UPDATES: u16 = 13;

fn put_counter_tlv(buf: &mut BytesMut, stat_type: u16, value: u64) {
    let v = u32::try_from(value).unwrap_or(u32::MAX);
    buf.put_u16(stat_type);
    buf.put_u16(4);
    buf.put_u32(v);
}

fn put_gauge_tlv(buf: &mut BytesMut, stat_type: u16, value: u64) {
    buf.put_u16(stat_type);
    buf.put_u16(8);
    buf.put_u64(value);
}

fn put_per_afi_safi_tlv(
    buf: &mut BytesMut,
    stat_type: u16,
    afi: u16,
    safi: u8,
    value: u64,
) {
    buf.put_u16(stat_type);
    buf.put_u16(11);
    buf.put_u16(afi);
    buf.put_u8(safi);
    buf.put_u64(value);
}

/// Serialize a [`BgpPeerStatsSnapshot`] into a BMP Statistics Report
/// body — the bytes that go after the per-peer header. The full TLV
/// set from RFC 7854 §4.8 is always emitted; counters Netom does
/// not track are reported as zero.
pub fn build_stats_body(snap: &BgpPeerStatsSnapshot) -> Bytes {
    // Per-AFI/SAFI TLVs are variable in count; everything else is a
    // fixed set of 13 single-valued TLVs.
    let mut buf = BytesMut::with_capacity(256);

    // Stats Count placeholder; patched after we know the final count.
    let count_pos = buf.len();
    buf.put_u32(0);
    let mut count: u32 = 0;

    put_counter_tlv(&mut buf, STAT_PREFIXES_REJECTED, snap.prefixes_rejected);
    put_counter_tlv(
        &mut buf,
        STAT_DUP_PREFIX_ADV,
        snap.dup_prefix_advertisements,
    );
    put_counter_tlv(&mut buf, STAT_DUP_WITHDRAWS, snap.dup_withdraws);
    put_counter_tlv(
        &mut buf,
        STAT_INVALID_CLUSTER_LIST_LOOPS,
        snap.invalid_cluster_list_loops,
    );
    put_counter_tlv(
        &mut buf,
        STAT_INVALID_AS_PATH_LOOPS,
        snap.invalid_as_path_loops,
    );
    put_counter_tlv(
        &mut buf,
        STAT_INVALID_ORIGINATOR_ID,
        snap.invalid_originator_id,
    );
    put_counter_tlv(
        &mut buf,
        STAT_INVALID_AS_CONFED_LOOPS,
        snap.invalid_as_confed_loops,
    );
    put_gauge_tlv(&mut buf, STAT_ADJ_RIB_IN, snap.adj_rib_in_routes);
    put_gauge_tlv(&mut buf, STAT_LOC_RIB, snap.loc_rib_routes);
    count += 9;

    for ((afi, safi), v) in &snap.adj_rib_in_per_afi_safi {
        put_per_afi_safi_tlv(
            &mut buf,
            STAT_ADJ_RIB_IN_PER_AFI_SAFI,
            *afi,
            *safi,
            *v,
        );
        count += 1;
    }
    for ((afi, safi), v) in &snap.loc_rib_per_afi_safi {
        put_per_afi_safi_tlv(
            &mut buf,
            STAT_LOC_RIB_PER_AFI_SAFI,
            *afi,
            *safi,
            *v,
        );
        count += 1;
    }

    put_counter_tlv(
        &mut buf,
        STAT_UPDATES_TREAT_AS_WITHDRAW,
        snap.updates_treat_as_withdraw,
    );
    put_counter_tlv(
        &mut buf,
        STAT_PREFIXES_TREAT_AS_WITHDRAW,
        snap.prefixes_treat_as_withdraw,
    );
    put_counter_tlv(&mut buf, STAT_DUP_UPDATES, snap.dup_updates);
    count += 3;

    // Patch Stats Count.
    buf[count_pos..count_pos + 4].copy_from_slice(&count.to_be_bytes());

    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap_zero() -> BgpPeerStatsSnapshot {
        BgpPeerStatsSnapshot::default()
    }

    #[test]
    fn empty_per_afi_safi_yields_12_tlvs() {
        // 9 fixed before per-AFI + 3 fixed after = 12.
        let body = build_stats_body(&snap_zero());
        let count = u32::from_be_bytes(body[0..4].try_into().unwrap());
        assert_eq!(count, 12);
        // 4 bytes count + 12 TLVs:
        // - 11 fixed-size scalar TLVs (9 counter @ 8 bytes + 2 gauge @ 12 bytes) = 9*8 + 2*12 = 96
        // - 1 dup_updates counter @ 8 bytes after = part of the 9
        // Recount exactly from layout:
        //   counter TLV total = 4 (header) + 4 (data) = 8 bytes each, 10 of them
        //   gauge TLV total   = 4 (header) + 8 (data) = 12 bytes each, 2 of them
        // 10 counters + 2 gauges = 80 + 24 = 104, plus 4 byte stats count = 108.
        assert_eq!(body.len(), 108);
    }

    #[test]
    fn per_afi_safi_tlv_layout() {
        let mut snap = snap_zero();
        snap.adj_rib_in_per_afi_safi = vec![((1, 1), 0xdead_beef_cafe_babe)];
        let body = build_stats_body(&snap);
        let count = u32::from_be_bytes(body[0..4].try_into().unwrap());
        assert_eq!(count, 13);

        // Find the per-AFI/SAFI TLV by stat type 9. Walk from offset 4.
        let mut off = 4usize;
        let mut found = false;
        while off + 4 <= body.len() {
            let stype =
                u16::from_be_bytes(body[off..off + 2].try_into().unwrap());
            let slen = u16::from_be_bytes(
                body[off + 2..off + 4].try_into().unwrap(),
            ) as usize;
            if stype == STAT_ADJ_RIB_IN_PER_AFI_SAFI {
                assert_eq!(slen, 11);
                let afi = u16::from_be_bytes(
                    body[off + 4..off + 6].try_into().unwrap(),
                );
                let safi = body[off + 6];
                let val = u64::from_be_bytes(
                    body[off + 7..off + 15].try_into().unwrap(),
                );
                assert_eq!(afi, 1);
                assert_eq!(safi, 1);
                assert_eq!(val, 0xdead_beef_cafe_babe);
                found = true;
                break;
            }
            off += 4 + slen;
        }
        assert!(found, "stat type 9 TLV not found");
    }

    #[test]
    fn counter_saturates_at_u32_max() {
        let mut snap = snap_zero();
        snap.prefixes_rejected = u64::from(u32::MAX) + 1;
        let body = build_stats_body(&snap);

        // First TLV (right after the 4-byte stats count) is
        // STAT_PREFIXES_REJECTED.
        let stype = u16::from_be_bytes(body[4..6].try_into().unwrap());
        let slen = u16::from_be_bytes(body[6..8].try_into().unwrap());
        let val = u32::from_be_bytes(body[8..12].try_into().unwrap());
        assert_eq!(stype, STAT_PREFIXES_REJECTED);
        assert_eq!(slen, 4);
        assert_eq!(val, u32::MAX);
    }

    #[test]
    fn gauge_value_round_trip() {
        let mut snap = snap_zero();
        snap.adj_rib_in_routes = 0x0102_0304_0506_0708;
        let body = build_stats_body(&snap);

        // Find stat type 7 (Adj-RIB-In gauge).
        let mut off = 4usize;
        loop {
            let stype =
                u16::from_be_bytes(body[off..off + 2].try_into().unwrap());
            let slen = u16::from_be_bytes(
                body[off + 2..off + 4].try_into().unwrap(),
            ) as usize;
            if stype == STAT_ADJ_RIB_IN {
                assert_eq!(slen, 8);
                let v = u64::from_be_bytes(
                    body[off + 4..off + 12].try_into().unwrap(),
                );
                assert_eq!(v, 0x0102_0304_0506_0708);
                return;
            }
            off += 4 + slen;
            if off >= body.len() {
                break;
            }
        }
        panic!("Adj-RIB-In gauge TLV not found");
    }
}
