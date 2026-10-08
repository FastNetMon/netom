//! EVPN monitoring records. Route identity includes the RD and never uses
//! the tenant IP prefix as a global unicast key.
use inetnum::addr::Prefix;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvpnNlri {
    pub route_type: u8,
    pub rd: String,
    pub ethernet_tag: Option<u32>,
    pub esi: Option<String>,
    pub mac: Option<String>,
    pub prefix: Option<Prefix>,
    pub gateway: Option<IpAddr>,
    /// Raw 24-bit label fields: VXLAN interprets these as VNIs.
    pub labels: Vec<u32>,
    pub raw: Vec<u8>,
    #[serde(skip)]
    pub(crate) key: Vec<u8>,
}

fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
fn ip(raw: &[u8]) -> Result<IpAddr, ()> {
    match raw.len() {
        4 => {
            Ok(Ipv4Addr::from(<[u8; 4]>::try_from(raw).map_err(|_| ())?)
                .into())
        }
        16 => {
            Ok(Ipv6Addr::from(<[u8; 16]>::try_from(raw).map_err(|_| ())?)
                .into())
        }
        _ => Err(()),
    }
}

impl EvpnNlri {
    pub fn parse(raw: &[u8]) -> Result<Self, ()> {
        if raw.len() < 10 || raw[1] as usize + 2 != raw.len() {
            return Err(());
        }
        let b = &raw[2..];
        let rd = match u16::from_be_bytes([b[0], b[1]]) {
            0 => format!(
                "{}:{}",
                u16::from_be_bytes([b[2], b[3]]),
                u32::from_be_bytes(b[4..8].try_into().unwrap())
            ),
            1 => format!(
                "{}:{}",
                Ipv4Addr::from(<[u8; 4]>::try_from(&b[2..6]).unwrap()),
                u16::from_be_bytes([b[6], b[7]])
            ),
            2 => format!(
                "{}:{}",
                u32::from_be_bytes(b[2..6].try_into().unwrap()),
                u16::from_be_bytes([b[6], b[7]])
            ),
            _ => hex(&b[..8]),
        };
        let mut n = Self {
            route_type: raw[0],
            rd,
            ethernet_tag: None,
            esi: None,
            mac: None,
            prefix: None,
            gateway: None,
            labels: vec![],
            raw: raw.to_vec(),
            key: raw.to_vec(),
        };
        match n.route_type {
            1 => {
                if b.len() != 25 {
                    return Err(());
                }
                n.esi = Some(hex(&b[8..18]));
                n.ethernet_tag =
                    Some(u32::from_be_bytes(b[18..22].try_into().unwrap()));
                n.labels.push(u32::from_be_bytes([0, b[22], b[23], b[24]]));
                n.key = vec![1];
                n.key.extend_from_slice(&b[..22]);
            }
            3 => {
                if b.len() < 13
                    || !matches!((b[12], b.len()), (32, 17) | (128, 29))
                {
                    return Err(());
                }
                n.ethernet_tag =
                    Some(u32::from_be_bytes(b[8..12].try_into().unwrap()));
            }
            4 => {
                if b.len() < 19
                    || !matches!((b[18], b.len()), (32, 23) | (128, 35))
                {
                    return Err(());
                }
                n.esi = Some(hex(&b[8..18]));
            }
            _ => (),
        }
        if matches!(n.route_type, 2 | 5) {
            if b.len() < 25 {
                return Err(());
            }
            n.esi = Some(hex(&b[8..18]));
            n.ethernet_tag =
                Some(u32::from_be_bytes(b[18..22].try_into().unwrap()));
            n.key = vec![n.route_type];
            n.key.extend_from_slice(&b[..8]);
            n.key.extend_from_slice(&b[18..22]);
            let labels_at;
            if n.route_type == 2 {
                if b.len() < 33 || b[22] != 48 {
                    return Err(());
                }
                let ip_len = match b[29] {
                    0 => 0,
                    32 => 4,
                    128 => 16,
                    _ => return Err(()),
                };
                labels_at = 30 + ip_len;
                if b.len() != labels_at + 3 && b.len() != labels_at + 6 {
                    return Err(());
                }
                n.mac = Some(
                    b[23..29]
                        .iter()
                        .map(|v| format!("{v:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                );
                if ip_len != 0 {
                    n.prefix = Some(
                        Prefix::new(ip(&b[30..labels_at])?, b[29])
                            .map_err(|_| ())?,
                    );
                }
                n.key.extend_from_slice(&b[22..labels_at]);
            } else {
                // RFC 9136 carries a full 4/16-octet address, regardless of prefix length.
                let size = match b.len() {
                    34 => 4,
                    58 => 16,
                    _ => return Err(()),
                };
                let prefix = Prefix::new(ip(&b[23..23 + size])?, b[22])
                    .map_err(|_| ())?;
                n.prefix = Some(prefix);
                n.gateway = Some(ip(&b[23 + size..23 + 2 * size])?);
                labels_at = 23 + 2 * size;
                n.key.extend_from_slice(prefix.to_string().as_bytes());
            }
            for l in b[labels_at..].chunks_exact(3) {
                n.labels.push(u32::from_be_bytes([0, l[0], l[1], l[2]]));
            }
        }
        Ok(n)
    }
}

#[derive(Clone, Serialize)]
pub struct EvpnRecord {
    pub ingress_id: crate::ingress::IngressId,
    pub ltime: u64,
    pub active: bool,
    pub nlri: EvpnNlri,
    pub attributes: crate::payload::RotondaPaMap,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn type5(rd: u8, label: u8) -> Vec<u8> {
        let mut b = vec![5, 34];
        b.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, rd]);
        b.extend_from_slice(&[0; 14]);
        b.push(24);
        b.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 0, 0, 0, label]);
        b
    }
    #[test]
    fn tenant_identity_and_label_changes() {
        let a = EvpnNlri::parse(&type5(1, 10)).unwrap();
        let b = EvpnNlri::parse(&type5(2, 10)).unwrap();
        let c = EvpnNlri::parse(&type5(1, 20)).unwrap();
        assert_eq!(a.prefix, b.prefix);
        assert_ne!(a.key, b.key);
        assert_eq!(a.key, c.key);
        assert_eq!(a.labels, vec![10]);
    }
    #[test]
    fn evpn_mac_ip_two_vnis_and_ipv6_prefix() {
        let mut raw = vec![2, 52];
        raw.extend_from_slice(&[0; 22]);
        raw.push(48);
        raw.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        raw.push(128);
        raw.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        raw.extend_from_slice(&[0, 0, 10, 0, 0, 20]);
        let route = EvpnNlri::parse(&raw).unwrap();
        assert_eq!(route.labels, vec![10, 20]);
        assert_eq!(route.mac.as_deref(), Some("00:01:02:03:04:05"));
        assert_eq!(route.prefix.unwrap().to_string(), "::1/128");
        raw[10] = 1; // ESI is not part of RT-2 route identity.
        raw[53] = 30;
        assert_eq!(route.key, EvpnNlri::parse(&raw).unwrap().key);

        let mut raw = vec![5, 58];
        raw.extend_from_slice(&[0; 22]);
        raw.push(64);
        raw.extend_from_slice(
            &"2001:db8::".parse::<Ipv6Addr>().unwrap().octets(),
        );
        raw.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        raw.extend_from_slice(&[0, 1, 0]);
        let route = EvpnNlri::parse(&raw).unwrap();
        assert_eq!(route.prefix.unwrap().to_string(), "2001:db8::/64");
        assert_eq!(route.labels, vec![256]);
    }

    #[test]
    fn evpn_overlay_metadata() {
        use routecore::bgp::{
            message::update::PduParseInfo,
            path_attributes::OwnedPathAttributes,
        };
        let attrs =
            crate::payload::RotondaPaMap::new(OwnedPathAttributes::new(
                PduParseInfo::modern(),
                vec![
                    0xc0, 16, 24, 0, 2, 0xfd, 0xe8, 0, 0, 0, 10, 2, 2, 0, 1,
                    0, 0, 0, 20, 6, 3, 0, 1, 2, 3, 4, 5,
                ],
            ));
        let overlay = EvpnAttributes::decode(&attrs);
        assert_eq!(overlay.route_targets, vec!["65000:10", "65536:20"]);
        assert_eq!(overlay.router_mac.as_deref(), Some("00:01:02:03:04:05"));
    }

    #[test]
    fn truncated_routes_are_rejected() {
        let b = type5(1, 10);
        for len in 0..b.len() {
            assert!(EvpnNlri::parse(&b[..len]).is_err());
        }
    }
}

/// Extended communities used when correlating MAC-VRF and IP-VRF routes.
#[derive(Default, Serialize)]
pub struct EvpnAttributes {
    pub route_targets: Vec<String>,
    pub router_mac: Option<String>,
    pub next_hop: Option<IpAddr>,
}
impl EvpnAttributes {
    pub fn decode(attributes: &crate::payload::RotondaPaMap) -> Self {
        let mut out = Self::default();
        let raw = attributes.as_ref();
        let mut b = raw.get(2..).unwrap_or_default();
        while b.len() >= 3 {
            let (header, len) = if b[0] & 0x10 != 0 {
                if b.len() < 4 {
                    break;
                }
                (4, u16::from_be_bytes([b[2], b[3]]) as usize)
            } else {
                (3, b[2] as usize)
            };
            if b.len() < header + len {
                break;
            }
            let v = &b[header..header + len];
            match b[1] {
                16 => {
                    for c in v.chunks_exact(8) {
                        if c[1] == 2 && c[0] <= 2 {
                            let rt = match c[0] {
                                0 => format!(
                                    "{}:{}",
                                    u16::from_be_bytes([c[2], c[3]]),
                                    u32::from_be_bytes(
                                        c[4..8].try_into().unwrap()
                                    )
                                ),
                                1 => format!(
                                    "{}:{}",
                                    Ipv4Addr::from(
                                        <[u8; 4]>::try_from(&c[2..6])
                                            .unwrap()
                                    ),
                                    u16::from_be_bytes([c[6], c[7]])
                                ),
                                _ => format!(
                                    "{}:{}",
                                    u32::from_be_bytes(
                                        c[2..6].try_into().unwrap()
                                    ),
                                    u16::from_be_bytes([c[6], c[7]])
                                ),
                            };
                            out.route_targets.push(rt);
                        }
                        if c[0..2] == [6, 3] {
                            out.router_mac = Some(
                                c[2..]
                                    .iter()
                                    .map(|v| format!("{v:02x}"))
                                    .collect::<Vec<_>>()
                                    .join(":"),
                            );
                        }
                    }
                }
                14 if v.len() >= 4 && v[..3] == [0, 25, 70] => {
                    if let Some(nh) = v.get(4..4 + v[3] as usize) {
                        out.next_hop = ip(nh).ok();
                    }
                }
                _ => (),
            }
            b = &b[header + len..];
        }
        out
    }
}
