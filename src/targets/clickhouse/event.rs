//! Versioned RowBinary contract. Keep COLUMN_NAMES and schema.sql in lockstep.
use std::{net::IpAddr, sync::Arc};

pub const COLUMN_NAMES: &str = "schema_version,stream_id,epoch,event_seq,received_at,expires_at,event_class,event_kind,peer_key,ingress_id,path_id,afi,safi,prefix_addr,prefix_len,rpki,asn_width,raw_attrs,as_path,as4_path,communities,large_communities,extended_communities,next_hop,med,local_pref,attrs_parse_ok,identity";

#[derive(Debug, Default)]
pub struct Event {
    pub stream: [u8; 16],
    pub epoch: [u8; 16],
    pub seq: u64,
    pub received_ms: i64,
    pub expires: u32,
    // class: 0 = control/identity, 1 = route
    pub class: u8,
    // 1 announcement, 2 withdrawal, 3 identity, 4 peer invalidation,
    // 5 family invalidation, 6 reappearance, 7 history start, 8 history end.
    pub kind: u8,
    pub peer: [u8; 16],
    pub ingress: u32,
    pub path_id: Option<u32>,
    pub afi: u16,
    pub safi: u8,
    pub prefix: [u8; 16],
    pub prefix_len: u8,
    // RotondaPaMap's shared buffer: RPKI byte, parse-info byte, wire attributes.
    pub attrs: Arc<[u8]>,
    pub identity: Arc<str>,
}

pub fn ip_bytes(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(v) => v.to_ipv6_mapped().octets(),
        IpAddr::V6(v) => v.octets(),
    }
}

fn varint(out: &mut Vec<u8>, mut n: usize) {
    while n >= 128 {
        out.push((n as u8) | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
fn string(out: &mut Vec<u8>, value: &[u8]) {
    varint(out, value.len());
    out.extend_from_slice(value);
}
fn nullable_u32(out: &mut Vec<u8>, value: Option<u32>) {
    out.push(u8::from(value.is_none()));
    if let Some(v) = value {
        out.extend_from_slice(&v.to_le_bytes());
    }
}
fn array_u32(out: &mut Vec<u8>, values: &[u32]) {
    varint(out, values.len());
    for v in values {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

impl Event {
    pub fn encode(&self, out: &mut Vec<u8>) {
        let raw = self.attrs.get(2..).unwrap_or_default();
        let width = if self.attrs.get(1) == Some(&0) { 2 } else { 4 };
        let derived = Derived::parse(raw, width).unwrap_or_default();
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&self.stream);
        out.extend_from_slice(&self.epoch);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.received_ms.to_le_bytes());
        out.extend_from_slice(&self.expires.to_le_bytes());
        out.extend_from_slice(&[self.class, self.kind]);
        out.extend_from_slice(&self.peer);
        out.extend_from_slice(&self.ingress.to_le_bytes());
        nullable_u32(out, self.path_id);
        out.extend_from_slice(&self.afi.to_le_bytes());
        out.push(self.safi);
        out.extend_from_slice(&self.prefix);
        out.extend_from_slice(&[
            self.prefix_len,
            self.attrs.first().copied().unwrap_or(0),
            width as u8,
        ]);
        string(out, raw);
        array_u32(out, &derived.path);
        array_u32(out, &derived.as4_path);
        array_u32(out, &derived.communities);
        varint(out, derived.large.len());
        for c in &derived.large {
            out.extend_from_slice(c);
        }
        varint(out, derived.extended.len());
        for c in &derived.extended {
            out.extend_from_slice(c);
        }
        out.push(u8::from(derived.next_hop.is_none()));
        if let Some(ip) = derived.next_hop {
            out.extend_from_slice(&ip);
        }
        nullable_u32(out, derived.med);
        nullable_u32(out, derived.local_pref);
        out.push(u8::from(derived.ok));
        string(out, self.identity.as_bytes());
    }
}

// These arrays expose wire AS membership, including sets/confederations. They
// deliberately do not reconstruct an RFC 6793 effective path. Raw attributes
// retain segment types and AS4_PATH; queries must not infer origin from last().
#[derive(Default)]
struct Derived {
    path: Vec<u32>,
    as4_path: Vec<u32>,
    communities: Vec<u32>,
    large: Vec<[u8; 12]>,
    extended: Vec<[u8; 8]>,
    next_hop: Option<[u8; 16]>,
    med: Option<u32>,
    local_pref: Option<u32>,
    ok: bool,
}
impl Derived {
    fn parse(mut raw: &[u8], width: usize) -> Option<Self> {
        let mut d = Self::default();
        while !raw.is_empty() {
            let flags = *raw.first()?;
            let typ = *raw.get(1)?;
            let (len, header) = if flags & 16 != 0 {
                (
                    u16::from_be_bytes(raw.get(2..4)?.try_into().ok()?)
                        as usize,
                    4,
                )
            } else {
                (*raw.get(2)? as usize, 3)
            };
            let value = raw.get(header..header + len)?;
            raw = raw.get(header + len..)?;
            match typ {
                2 => d.path = Self::path(value, width)?,
                17 => d.as4_path = Self::path(value, 4)?,
                3 if len == 4 => {
                    d.next_hop = Some(ip_bytes(IpAddr::V4(
                        <[u8; 4]>::try_from(value).ok()?.into(),
                    )))
                }
                4 => d.med = Some(u32::from_be_bytes(value.try_into().ok()?)),
                5 => {
                    d.local_pref =
                        Some(u32::from_be_bytes(value.try_into().ok()?))
                }
                8 if len % 4 == 0 => {
                    d.communities = value
                        .chunks_exact(4)
                        .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
                        .collect()
                }
                16 if len % 8 == 0 => {
                    d.extended = value
                        .chunks_exact(8)
                        .map(|c| c.try_into().unwrap())
                        .collect()
                }
                32 if len % 12 == 0 => {
                    d.large = value
                        .chunks_exact(12)
                        .map(|c| c.try_into().unwrap())
                        .collect()
                }
                14 => {
                    let nhlen = *value.get(3)? as usize;
                    let nh = value.get(4..4 + nhlen)?;
                    d.next_hop = match (value.get(..3)?, nhlen) {
                        ([0, 1, 1], 4) => Some(ip_bytes(IpAddr::V4(
                            <[u8; 4]>::try_from(nh).ok()?.into(),
                        ))),
                        ([0, 2, 1], 16 | 32) => {
                            Some(nh[..16].try_into().ok()?)
                        }
                        _ => d.next_hop,
                    };
                }
                3 | 8 | 16 | 32 => return None,
                _ => {}
            }
        }
        d.ok = true;
        Some(d)
    }
    fn path(mut raw: &[u8], width: usize) -> Option<Vec<u32>> {
        let mut out = Vec::new();
        while !raw.is_empty() {
            if !(1..=4).contains(raw.first()?) {
                return None;
            }
            let n = *raw.get(1)? as usize;
            let segment = raw.get(2..2 + n * width)?;
            for a in segment.chunks_exact(width) {
                out.push(if width == 2 {
                    u16::from_be_bytes(a.try_into().ok()?) as u32
                } else {
                    u32::from_be_bytes(a.try_into().ok()?)
                });
            }
            raw = &raw[2 + n * width..];
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_as_path_and_unknown_attribute_are_preserved() {
        let raw = [
            0, 0, 64, 2, 6, 2, 2, 0xfd, 0xe8, 0xfd, 0xe9, 128, 99, 3, 0, 255,
            128,
        ];
        let e = Event {
            attrs: Arc::from(raw),
            ..Default::default()
        };
        let d = Derived::parse(&raw[2..], 2).unwrap();
        assert_eq!(d.path, [65000, 65001]);
        let mut bytes = Vec::new();
        e.encode(&mut bytes);
        assert!(bytes.windows(raw.len() - 2).any(|v| v == &raw[2..]));
    }
    #[test]
    fn malformed_attributes_never_panic_or_publish_partial_derivations() {
        let raw = [64, 5, 4, 0, 0, 0, 100, 128, 99, 255];
        assert!(Derived::parse(&raw, 4).is_none());
        for i in 0..raw.len() {
            let _ = Derived::parse(&raw[..i], 4);
        }
    }
    #[test]
    fn rowbinary_lengths_and_nulls() {
        let mut out = Vec::new();
        string(&mut out, &[42; 128]);
        assert_eq!(&out[..2], &[128, 1]);
        out.clear();
        nullable_u32(&mut out, None);
        nullable_u32(&mut out, Some(0x12345678));
        assert_eq!(out, [1, 0, 0x78, 0x56, 0x34, 0x12]);
    }
}
