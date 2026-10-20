use anyhow::{Result, bail, ensure};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

pub type Families = HashSet<(u16, u8)>;
pub const BMP_NAMES: [&str; 7] = [
    "route-monitoring",
    "statistics",
    "peer-down",
    "peer-up",
    "initiation",
    "termination",
    "route-mirroring",
];

pub fn bmp_name(kind: u8) -> &'static str {
    BMP_NAMES.get(kind as usize).copied().unwrap_or("unknown")
}
fn bgp_name(kind: u8) -> &'static str {
    match kind {
        1 => "OPEN",
        2 => "UPDATE",
        3 => "NOTIFICATION",
        4 => "KEEPALIVE",
        5 => "ROUTE-REFRESH",
        _ => "unknown",
    }
}
pub fn array(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}
pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn colon_hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
fn integer(data: &[u8]) -> u64 {
    data.iter().fold(0, |a, b| (a << 8) | u64::from(*b))
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn len(&self) -> usize {
        self.data.len() - self.pos
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        ensure!(
            count <= self.len(),
            "truncated protocol field: need {count} bytes, have {}",
            self.len()
        );
        let data = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(data)
    }
    fn uint(&mut self, count: usize) -> Result<u64> {
        Ok(integer(self.take(count)?))
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.uint(1)? as u8)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(self.uint(2)? as u16)
    }
    fn sized(&mut self, width: usize) -> Result<&'a [u8]> {
        let size = self.uint(width)? as usize;
        self.take(size)
    }
    fn rest(&mut self) -> &'a [u8] {
        let data = &self.data[self.pos..];
        self.pos = self.data.len();
        data
    }
    fn done(&self) -> Result<()> {
        ensure!(
            self.len() == 0,
            "unexpected {} trailing protocol bytes",
            self.len()
        );
        Ok(())
    }
}

fn address(raw: &[u8]) -> Result<String> {
    match raw.len() {
        4 => {
            Ok(Ipv4Addr::from(<[u8; 4]>::try_from(raw).unwrap()).to_string())
        }
        16 => Ok(
            Ipv6Addr::from(<[u8; 16]>::try_from(raw).unwrap()).to_string()
        ),
        n => bail!("invalid IP address length {n}"),
    }
}
fn rd(raw: &[u8]) -> Result<String> {
    let mut r = Reader::new(raw);
    Ok(match r.u16()? {
        0 => format!("{}:{}", r.uint(2)?, r.uint(4)?),
        1 => format!("{}:{}", address(r.take(4)?)?, r.uint(2)?),
        2 => format!("{}:{}", r.uint(4)?, r.uint(2)?),
        _ => hex(raw),
    })
}
fn tlvs(data: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut r = Reader::new(data);
    let mut result = Vec::new();
    while r.len() != 0 {
        let kind = r.u16()?;
        result.push((kind, r.sized(2)?));
    }
    Ok(result)
}
fn information(data: &[u8], names: &[(u16, &str)]) -> Result<Value> {
    let mut result = Vec::new();
    for (kind, value) in tlvs(data)? {
        let name = names.iter().find(|(k, _)| *k == kind).map(|(_, n)| *n);
        result.push(json!({"type": kind, "name": name.unwrap_or("unknown"),
            "value": if name.is_some() { String::from_utf8_lossy(value).into_owned() } else { hex(value) }}));
    }
    Ok(json!(result))
}
fn network(mut raw: Vec<u8>, bits: u8) -> Result<String> {
    ensure!(
        usize::from(bits) <= raw.len() * 8,
        "invalid IP prefix length {bits}"
    );
    let full = usize::from(bits) / 8;
    let partial = bits % 8;
    if partial != 0 {
        raw[full] &= 0xff << (8 - partial);
    }
    let start = full + usize::from(partial != 0);
    raw[start..].fill(0);
    Ok(format!("{}/{bits}", address(&raw)?))
}
fn prefix(r: &mut Reader<'_>, afi: u16) -> Result<String> {
    let bits = r.u8()?;
    let width = if afi == 1 { 4 } else { 16 };
    ensure!(
        usize::from(bits) <= width * 8,
        "invalid IPv{} prefix length {bits}",
        if afi == 1 { 4 } else { 6 }
    );
    let mut raw = r.take(usize::from(bits).div_ceil(8))?.to_vec();
    raw.resize(width, 0);
    network(raw, bits)
}

pub fn evpn_route(kind: u8, data: &[u8]) -> Result<Value> {
    let name = match kind {
        1 => "ethernet-auto-discovery",
        2 => "mac-ip",
        3 => "inclusive-multicast",
        4 => "ethernet-segment",
        5 => "ip-prefix",
        _ => "unknown",
    };
    let mut result = json!({"route_type":kind, "route_name":name});
    if !(1..=5).contains(&kind) {
        result["raw"] = json!(hex(data));
        return Ok(result);
    }
    let mut r = Reader::new(data);
    result["rd"] = json!(rd(r.take(8)?)?);
    if matches!(kind, 1 | 2 | 4 | 5) {
        result["esi"] = json!(colon_hex(r.take(10)?));
    }
    if matches!(kind, 1 | 2 | 3 | 5) {
        result["ethernet_tag"] = json!(r.uint(4)?);
    }
    match kind {
        2 => {
            ensure!(r.u8()? == 48, "EVPN MAC length is not 48 bits");
            result["mac"] = json!(colon_hex(r.take(6)?));
            let bits = r.u8()?;
            ensure!(
                matches!(bits, 0 | 32 | 128),
                "invalid EVPN IP length {bits}"
            );
            if bits != 0 {
                result["ip"] =
                    json!(address(r.take(usize::from(bits) / 8)?)?);
            }
        }
        3 | 4 => {
            let bits = r.u8()?;
            ensure!(
                matches!(bits, 32 | 128),
                "invalid EVPN originator IP length {bits}"
            );
            result["originator"] =
                json!(address(r.take(usize::from(bits) / 8)?)?);
        }
        5 => {
            let bits = r.u8()?;
            let width = match data.len() {
                34 => 4,
                58 => 16,
                _ => bail!("invalid EVPN IP-prefix route length"),
            };
            ensure!(
                usize::from(bits) <= width * 8,
                "invalid EVPN IP-prefix route length"
            );
            result["prefix"] = json!(network(r.take(width)?.to_vec(), bits)?);
            result["gateway"] = json!(address(r.take(width)?)?);
        }
        _ => {}
    }
    if matches!(kind, 1 | 2 | 5) {
        ensure!(
            r.len() == 3 || (kind == 2 && r.len() == 6),
            "invalid EVPN label field length"
        );
        let mut labels = Vec::new();
        while r.len() != 0 {
            labels.push(r.uint(3)?);
        }
        result["label_raw"] = json!(labels);
    }
    r.done()?;
    Ok(result)
}

fn nlri(
    data: &[u8],
    afi: u16,
    safi: u8,
    action: &str,
    add_paths: &Families,
) -> Result<Vec<Value>> {
    if !matches!((afi, safi), (1 | 2, 1 | 2) | (25, 70)) {
        return Ok(if data.is_empty() {
            vec![]
        } else {
            vec![
                json!({"afi":afi, "safi":safi, "action":action, "unsupported":true, "raw":hex(data)}),
            ]
        });
    }
    let mut r = Reader::new(data);
    let mut routes = Vec::new();
    while r.len() != 0 {
        let path_id = if add_paths.contains(&(afi, safi)) {
            Some(r.uint(4)?)
        } else {
            None
        };
        let mut entry = if (afi, safi) == (25, 70) {
            let kind = r.u8()?;
            evpn_route(kind, r.sized(1)?)?
        } else {
            json!({"prefix":prefix(&mut r, afi)?})
        };
        entry["afi"] = json!(afi);
        entry["safi"] = json!(safi);
        entry["action"] = json!(action);
        if let Some(id) = path_id {
            entry["path_id"] = json!(id);
        }
        routes.push(entry);
    }
    Ok(routes)
}

fn extended_community(raw: &[u8]) -> Result<Value> {
    let (kind, sub) = (raw[0], raw[1]);
    let mut result = json!({"type":kind, "subtype":sub, "raw":hex(raw)});
    if matches!(kind, 0 | 1 | 2 | 0x40 | 0x41 | 0x42) && matches!(sub, 2 | 3)
    {
        let value = match kind & 0x3f {
            0 => format!("{}:{}", integer(&raw[2..4]), integer(&raw[4..])),
            1 => format!("{}:{}", address(&raw[2..6])?, integer(&raw[6..])),
            _ => format!("{}:{}", integer(&raw[2..6]), integer(&raw[6..])),
        };
        result["name"] = json!(if sub == 2 {
            "route-target"
        } else {
            "route-origin"
        });
        result["value"] = json!(value);
    } else {
        match (kind, sub) {
            (3, 12) => {
                let tunnel = integer(&raw[6..]);
                result["name"] = json!("encapsulation");
                result["tunnel_type"] = json!(tunnel);
                result["value"] = json!(match tunnel {
                    8 => "VXLAN".to_owned(),
                    9 => "NVGRE".to_owned(),
                    19 => "GENEVE".to_owned(),
                    _ => tunnel.to_string(),
                });
            }
            (3, 13) => {
                result["name"] = json!("default-gateway");
                result["value"] = json!(true);
            }
            (6, 0) => {
                result["name"] = json!("mac-mobility");
                result["sequence"] = json!(integer(&raw[4..]));
                result["sticky"] = json!(raw[2] & 1 != 0);
            }
            (6, 3) => {
                result["name"] = json!("router-mac");
                result["value"] = json!(colon_hex(&raw[2..]));
            }
            _ => {
                result["name"] = json!("unknown");
            }
        }
    }
    Ok(result)
}

fn parse_open(r: &mut Reader<'_>) -> Result<Value> {
    let mut result = json!({"version":r.u8()?, "asn":r.uint(2)?, "hold_time":r.uint(2)?,
                            "router_id":address(r.take(4)?)?});
    let size = r.u8()?;
    ensure!(
        size != 255,
        "extended BGP OPEN optional-parameter encoding is not supported"
    );
    let mut params = Reader::new(r.take(size as usize)?);
    let mut capabilities = Vec::new();
    while params.len() != 0 {
        let kind = params.u8()?;
        let value = params.sized(1)?;
        if kind != 2 {
            continue;
        }
        let mut caps = Reader::new(value);
        while caps.len() != 0 {
            let code = caps.u8()?;
            let mut c = Reader::new(caps.sized(1)?);
            let mut cap = json!({"code":code, "raw":hex(c.data)});
            match code {
                1 => {
                    cap["afi"] = json!(c.u16()?);
                    c.u8()?;
                    cap["safi"] = json!(c.u8()?);
                    c.done()?;
                }
                65 => {
                    cap["asn"] = json!(c.uint(4)?);
                    c.done()?;
                }
                69 => {
                    let mut families = Vec::new();
                    while c.len() != 0 {
                        families.push(json!({"afi":c.u16()?, "safi":c.u8()?, "mode":c.u8()?}));
                    }
                    cap["families"] = json!(families);
                }
                _ => {}
            }
            capabilities.push(cap);
        }
    }
    r.done()?;
    result["capabilities"] = json!(capabilities);
    Ok(result)
}

pub fn parse_bgp(
    data: &[u8],
    asn_size: usize,
    add_paths: &Families,
) -> Result<Value> {
    let mut r = Reader::new(data);
    ensure!(r.take(16)? == [0xff; 16], "invalid BGP marker");
    let size = r.u16()? as usize;
    let kind = r.u8()?;
    ensure!(
        size == data.len() && size >= 19,
        "invalid BGP message length"
    );
    let mut result =
        json!({"type":kind, "name":bgp_name(kind), "length":size});
    match kind {
        1 => {
            result["open"] = parse_open(&mut r)?;
        }
        2 => {
            let withdrawn = r.sized(2)?;
            let mut attrs = Reader::new(r.sized(2)?);
            let announced = r.rest();
            let mut routes = nlri(withdrawn, 1, 1, "withdraw", add_paths)?;
            routes.extend(nlri(announced, 1, 1, "announce", add_paths)?);
            let mut attributes = Vec::new();
            let mut communities = Vec::new();
            let mut mp = Vec::new();
            while attrs.len() != 0 {
                let flags = attrs.u8()?;
                let code = attrs.u8()?;
                let mut a = Reader::new(attrs.sized(if flags & 16 != 0 {
                    2
                } else {
                    1
                })?);
                let mut item = json!({"type":code, "flags":flags});
                match code {
                    1 => {
                        item["name"] = json!("origin");
                        item["value"] = json!(a.u8()?);
                    }
                    2 | 17 => {
                        item["name"] = json!(if code == 2 {
                            "as-path"
                        } else {
                            "as4-path"
                        });
                        let mut segments = Vec::new();
                        while a.len() != 0 {
                            let segment_type = a.u8()?;
                            let count = a.u8()?;
                            ensure!(
                                (1..=4).contains(&segment_type),
                                "invalid AS_PATH segment type"
                            );
                            let mut asns = Vec::new();
                            for _ in 0..count {
                                asns.push(a.uint(if code == 17 {
                                    4
                                } else {
                                    asn_size
                                })?);
                            }
                            segments.push(
                                json!({"type":segment_type, "asns":asns}),
                            );
                        }
                        item["segments"] = json!(segments);
                    }
                    3 | 9 => {
                        item["name"] = json!(if code == 3 {
                            "next-hop"
                        } else {
                            "originator-id"
                        });
                        item["value"] = json!(address(a.take(4)?)?);
                    }
                    4 | 5 => {
                        item["name"] = json!(if code == 4 {
                            "med"
                        } else {
                            "local-pref"
                        });
                        item["value"] = json!(a.uint(4)?);
                    }
                    6 => {
                        item["name"] = json!("atomic-aggregate");
                        item["value"] = json!(true);
                    }
                    7 | 18 => {
                        item["name"] = json!(if code == 7 {
                            "aggregator"
                        } else {
                            "as4-aggregator"
                        });
                        item["asn"] = json!(a.uint(if code == 18 {
                            4
                        } else {
                            asn_size
                        })?);
                        item["address"] = json!(address(a.take(4)?)?);
                    }
                    8 => {
                        item["name"] = json!("communities");
                        let mut values = Vec::new();
                        while a.len() != 0 {
                            values.push(format!("{}:{}", a.u16()?, a.u16()?));
                        }
                        item["values"] = json!(values);
                    }
                    10 => {
                        item["name"] = json!("cluster-list");
                        let mut values = Vec::new();
                        while a.len() != 0 {
                            values.push(address(a.take(4)?)?);
                        }
                        item["values"] = json!(values);
                    }
                    14 | 15 => {
                        let (afi, safi) = (a.u16()?, a.u8()?);
                        item["name"] = json!(if code == 14 {
                            "mp-reach"
                        } else {
                            "mp-unreach"
                        });
                        item["afi"] = json!(afi);
                        item["safi"] = json!(safi);
                        if code == 14 {
                            let hop = a.sized(1)?;
                            match hop.len() {
                                4 | 16 => {
                                    item["next_hop"] = json!([address(hop)?]);
                                }
                                32 => {
                                    item["next_hop"] = json!([
                                        address(&hop[..16])?,
                                        address(&hop[16..])?
                                    ]);
                                }
                                _ => {
                                    item["next_hop_raw"] = json!(hex(hop));
                                }
                            }
                            a.u8()?;
                        }
                        mp.push((
                            afi,
                            safi,
                            if code == 14 { "announce" } else { "withdraw" },
                            a.rest(),
                            item.clone(),
                        ));
                    }
                    16 => {
                        item["name"] = json!("extended-communities");
                        let mut values = Vec::new();
                        while a.len() != 0 {
                            let c = extended_community(a.take(8)?)?;
                            communities.push(c.clone());
                            values.push(c);
                        }
                        item["values"] = json!(values);
                    }
                    22 => {
                        item["name"] = json!("pmsi-tunnel");
                        item["tunnel_flags"] = json!(a.u8()?);
                        item["tunnel_type"] = json!(a.u8()?);
                        item["label_raw"] = json!(a.uint(3)?);
                        item["tunnel_id"] = json!(hex(a.rest()));
                    }
                    32 => {
                        item["name"] = json!("large-communities");
                        let mut values = Vec::new();
                        while a.len() != 0 {
                            values.push(format!(
                                "{}:{}:{}",
                                a.uint(4)?,
                                a.uint(4)?,
                                a.uint(4)?
                            ));
                        }
                        item["values"] = json!(values);
                    }
                    _ => {
                        item["name"] = json!("unknown");
                        item["raw"] = json!(hex(a.rest()));
                    }
                }
                a.done()?;
                attributes.push(item);
            }
            let mut end_of_rib = Vec::new();
            if withdrawn.is_empty()
                && announced.is_empty()
                && attributes.is_empty()
            {
                end_of_rib.push(json!({"afi":1,"safi":1}));
            }
            for (afi, safi, action, raw, item) in mp {
                let mut decoded = nlri(raw, afi, safi, action, add_paths)?;
                for route in &mut decoded {
                    if let Some(hop) = item.get("next_hop") {
                        route["next_hop"] = hop.clone();
                    }
                }
                routes.extend(decoded);
                if action == "withdraw" && raw.is_empty() {
                    end_of_rib.push(json!({"afi":afi,"safi":safi}));
                }
            }
            let overlay = communities.iter().any(|c| {
                matches!(c["tunnel_type"].as_u64(), Some(8 | 9 | 19))
            });
            for route in &mut routes {
                if let Some(raw) = route.get("label_raw") {
                    let values = if overlay {
                        raw.clone()
                    } else {
                        json!(
                            array(raw)
                                .iter()
                                .map(|v| v.as_u64().unwrap() >> 4)
                                .collect::<Vec<_>>()
                        )
                    };
                    route[if overlay { "vni" } else { "mpls_labels" }] =
                        values;
                }
            }
            for item in &mut attributes {
                if item["type"] == 22 {
                    item[if overlay { "vni" } else { "mpls_label" }] = json!(
                        item["label_raw"].as_u64().unwrap()
                            >> if overlay { 0 } else { 4 }
                    );
                }
            }
            result["routes"] = json!(routes);
            result["attributes"] = json!(attributes);
            result["end_of_rib"] = json!(end_of_rib);
        }
        3 => {
            result["error_code"] = json!(r.u8()?);
            result["error_subcode"] = json!(r.u8()?);
            result["data"] = json!(hex(r.rest()));
        }
        4 => {
            r.done()?;
        }
        5 => {
            result["afi"] = json!(r.u16()?);
            result["subtype"] = json!(r.u8()?);
            result["safi"] = json!(r.u8()?);
            result["data"] = json!(hex(r.rest()));
        }
        _ => {
            result["raw"] = json!(hex(r.rest()));
        }
    }
    Ok(result)
}

fn bgp_from_reader(
    r: &mut Reader<'_>,
    asn_size: usize,
    add_paths: &Families,
    preserve_error: bool,
) -> Result<Value> {
    ensure!(r.len() >= 19, "truncated BGP header");
    let size = integer(&r.data[r.pos + 16..r.pos + 18]) as usize;
    ensure!(size >= 19, "BGP message shorter than header");
    let raw = r.take(size)?;
    match parse_bgp(raw, asn_size, add_paths) {
        Ok(message) => Ok(message),
        Err(error) if preserve_error => {
            Ok(json!({"type":raw[18],"name":bgp_name(raw[18]),
            "length":size,"error":error.to_string(),"raw":hex(raw)}))
        }
        Err(error) => Err(error),
    }
}
fn add_path_families(message: &Value) -> HashMap<(u16, u8), u8> {
    let mut families = HashMap::new();
    for cap in array(&message["open"]["capabilities"]) {
        if cap["code"] == 69 {
            for f in array(&cap["families"]) {
                families.insert(
                    (
                        f["afi"].as_u64().unwrap() as u16,
                        f["safi"].as_u64().unwrap() as u8,
                    ),
                    f["mode"].as_u64().unwrap() as u8,
                );
            }
        }
    }
    families
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct PeerKey(u8, Vec<u8>, Vec<u8>);
struct PeerState {
    incoming: Families,
    outgoing: Families,
}
pub struct BmpDecoder {
    peers: HashMap<PeerKey, PeerState>,
    force_add_path: bool,
}
impl BmpDecoder {
    pub fn new(force_add_path: bool) -> Self {
        Self {
            peers: HashMap::new(),
            force_add_path,
        }
    }
    pub fn decode(&mut self, data: &[u8]) -> Result<Value> {
        let mut r = Reader::new(data);
        let (version, length, kind) = (r.u8()?, r.uint(4)? as usize, r.u8()?);
        ensure!(
            version == 3 && length == data.len(),
            "invalid BMP version or length"
        );
        let mut result = json!({"version":version,"length":length,"type":kind,"name":bmp_name(kind)});
        let (mut peer_type, mut flags, mut asn_size) = (0, 0, 4);
        let mut key = PeerKey(0, vec![], vec![]);
        let mut add_paths = Families::new();
        if matches!(kind, 0 | 1 | 2 | 3 | 6) {
            peer_type = r.u8()?;
            flags = r.u8()?;
            let distinguisher = r.take(8)?;
            let peer_address = r.take(16)?;
            let mut peer = json!({"type":peer_type,"flags":flags,
                "distinguisher":rd(distinguisher)?,
                "address":address(if flags & 128 != 0 && peer_type != 3 { peer_address } else { &peer_address[12..] })?,
                "asn":r.uint(4)?,"router_id":address(r.take(4)?)?,
                "timestamp_seconds":r.uint(4)?,"timestamp_microseconds":r.uint(4)?});
            if peer_type == 3 {
                peer["rib"] = json!("loc-rib");
                peer["filtered"] = json!(flags & 128 != 0);
            } else {
                peer["rib"] = json!(if flags & 16 != 0 {
                    "adj-rib-out"
                } else {
                    "adj-rib-in"
                });
                peer["policy"] =
                    json!(if flags & 64 != 0 { "post" } else { "pre" });
            }
            result["peer"] = peer;
            key = PeerKey(
                peer_type,
                distinguisher.to_vec(),
                peer_address.to_vec(),
            );
            asn_size = if peer_type == 3 || flags & 32 == 0 {
                4
            } else {
                2
            };
            if let Some(state) = self.peers.get(&key) {
                add_paths = if flags & 16 != 0 {
                    state.outgoing.clone()
                } else {
                    state.incoming.clone()
                };
            }
            if self.force_add_path {
                add_paths = [(1, 1), (1, 2), (2, 1), (2, 2), (25, 70)].into();
            }
        }
        match kind {
            0 => {
                let bgp =
                    bgp_from_reader(&mut r, asn_size, &add_paths, false)?;
                ensure!(
                    bgp["type"] == 2,
                    "BMP Route Monitoring does not contain a BGP UPDATE"
                );
                result["bgp"] = json!([bgp]);
            }
            1 => {
                let count = r.uint(4)?;
                let mut stats = Vec::new();
                for _ in 0..count {
                    let code = r.u16()?;
                    let raw = r.sized(2)?;
                    let mut stat = json!({"type":code,"raw":hex(raw)});
                    if matches!(code, 9 | 10) && raw.len() == 11 {
                        stat["afi"] = json!(integer(&raw[..2]));
                        stat["safi"] = json!(raw[2]);
                        stat["value"] = json!(integer(&raw[3..]));
                    } else if matches!(raw.len(), 4 | 8) {
                        stat["value"] = json!(integer(raw));
                    }
                    stats.push(stat);
                }
                result["statistics"] = json!(stats);
            }
            2 => {
                let reason = r.u8()?;
                result["reason"] = json!(reason);
                match reason {
                    1 | 3 => {
                        result["bgp"] = json!([bgp_from_reader(
                            &mut r, asn_size, &add_paths, false
                        )?]);
                    }
                    2 => {
                        result["fsm_event"] = json!(r.u16()?);
                    }
                    6 => {
                        result["information"] =
                            information(r.rest(), &[(3, "vrf-table-name")])?;
                    }
                    _ => {
                        result["data"] = json!(hex(r.rest()));
                    }
                }
                self.peers.remove(&key);
            }
            3 => {
                let local = r.take(16)?;
                result["local_address"] =
                    json!(address(if flags & 128 != 0 && peer_type != 3 {
                        local
                    } else {
                        &local[12..]
                    })?);
                result["local_port"] = json!(r.u16()?);
                result["remote_port"] = json!(r.u16()?);
                let empty = Families::new();
                let sent = bgp_from_reader(&mut r, 4, &empty, true)?;
                let received = bgp_from_reader(&mut r, 4, &empty, true)?;
                ensure!(
                    sent["type"] == 1 && received["type"] == 1,
                    "BMP Peer Up must contain two BGP OPENs"
                );
                let errors: Vec<_> = [&sent, &received]
                    .iter()
                    .filter_map(|b| {
                        b.get("error").map(|e| {
                            format!(
                                "malformed BGP OPEN: {}",
                                e.as_str().unwrap()
                            )
                        })
                    })
                    .collect();
                if !errors.is_empty() {
                    result["errors"] = json!(errors);
                    self.peers.remove(&key);
                } else {
                    let (a, b) = (
                        add_path_families(&sent),
                        add_path_families(&received),
                    );
                    let mut incoming: Families = b
                        .iter()
                        .filter(|(f, m)| {
                            **m & 2 != 0 && a.get(f).unwrap_or(&0) & 1 != 0
                        })
                        .map(|(f, _)| *f)
                        .collect();
                    let mut outgoing: Families = a
                        .iter()
                        .filter(|(f, m)| {
                            **m & 2 != 0 && b.get(f).unwrap_or(&0) & 1 != 0
                        })
                        .map(|(f, _)| *f)
                        .collect();
                    if peer_type == 3 {
                        incoming = a.keys().copied().collect();
                        outgoing = incoming.clone();
                    }
                    ensure!(
                        self.peers.contains_key(&key)
                            || self.peers.len() < 4096,
                        "BMP peer state limit exceeded"
                    );
                    self.peers.insert(key, PeerState { incoming, outgoing });
                }
                result["bgp"] = json!([sent, received]);
                result["information"] = information(
                    r.rest(),
                    &[
                        (0, "string"),
                        (1, "sys-descr"),
                        (2, "sys-name"),
                        (3, "vrf-table-name"),
                        (4, "admin-label"),
                    ],
                )?;
            }
            4 => {
                result["information"] = information(
                    r.rest(),
                    &[(0, "string"), (1, "sys-descr"), (2, "sys-name")],
                )?;
            }
            5 => {
                let mut info = Vec::new();
                for (code, raw) in tlvs(r.rest())? {
                    let value = if code == 0 {
                        json!(String::from_utf8_lossy(raw))
                    } else if code == 1 && raw.len() == 2 {
                        json!(integer(raw))
                    } else {
                        json!(hex(raw))
                    };
                    info.push(json!({"type":code,"value":value}));
                }
                result["information"] = json!(info);
            }
            6 => {
                let (mut bgps, mut mirror) = (Vec::new(), Vec::new());
                for (code, raw) in tlvs(r.rest())? {
                    if code == 0 {
                        bgps.push(parse_bgp(raw, asn_size, &add_paths)?);
                    } else {
                        mirror.push(json!({"type":code,"raw":hex(raw)}));
                    }
                }
                result["bgp"] = json!(bgps);
                result["mirroring"] = json!(mirror);
            }
            _ => {
                result["raw"] = json!(hex(r.rest()));
            }
        }
        r.done()?;
        Ok(result)
    }
}
