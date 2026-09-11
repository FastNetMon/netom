-- Schema v1. Run manually with the intended database selected.
-- Tested topology: local MergeTree. Retention is encoded per row by Netom.
CREATE TABLE events
(
    schema_version UInt16,
    stream_id FixedString(16),
    epoch FixedString(16),
    event_seq UInt64 CODEC(ZSTD(1)),
    received_at DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    expires_at DateTime CODEC(Delta, ZSTD(1)),
    event_class UInt8,
    event_kind UInt8,
    peer_key FixedString(16),
    ingress_id UInt32,
    path_id Nullable(UInt32),
    afi UInt16,
    safi UInt8,
    prefix_addr IPv6,
    prefix_len UInt8,
    rpki UInt8,
    asn_width UInt8,
    raw_attrs String CODEC(ZSTD(1)),
    as_path Array(UInt32) CODEC(ZSTD(1)),
    as4_path Array(UInt32) CODEC(ZSTD(1)),
    communities Array(UInt32) CODEC(ZSTD(1)),
    large_communities Array(FixedString(12)) CODEC(ZSTD(1)),
    extended_communities Array(FixedString(8)) CODEC(ZSTD(1)),
    next_hop Nullable(IPv6),
    med Nullable(UInt32),
    local_pref Nullable(UInt32),
    attrs_parse_ok UInt8,
    identity String CODEC(ZSTD(1)),
    PROJECTION by_peer
    (
        SELECT peer_key, event_class, received_at, afi, safi, prefix_addr,
               prefix_len, event_kind, _part_offset
        ORDER BY (peer_key, event_class, received_at)
    )
)
ENGINE = MergeTree
PARTITION BY toStartOfHour(received_at)
PRIMARY KEY (event_class, afi, safi, prefix_addr, prefix_len, received_at)
ORDER BY (event_class, afi, safi, prefix_addr, prefix_len, received_at,
          peer_key, stream_id, epoch, event_seq)
TTL expires_at DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1,
         non_replicated_deduplication_window = 10000;

CREATE VIEW route_events AS SELECT * FROM events WHERE event_class = 1;
CREATE VIEW peer_events AS SELECT * FROM events WHERE event_class = 0;
