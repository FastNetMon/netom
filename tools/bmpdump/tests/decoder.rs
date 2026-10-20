use bmpdump::capture::{Capture, Packet, tcp_segment};
use bmpdump::protocol::{BmpDecoder, Families, evpn_route, parse_bgp};
use bmpdump::stream::Stream;
use serde_json::{Value, json};
use std::io::{Cursor, Write};
use std::net::Ipv6Addr;
use std::process::{Command, Output, Stdio};

fn bmp(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![3];
    out.extend(((body.len() + 6) as u32).to_be_bytes());
    out.push(kind);
    out.extend(body);
    out
}
fn bgp(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![255; 16];
    out.extend(((body.len() + 19) as u16).to_be_bytes());
    out.push(kind);
    out.extend(body);
    out
}
fn attr(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x90, kind];
    out.extend((body.len() as u16).to_be_bytes());
    out.extend(body);
    out
}
fn update(attrs: &[u8], withdrawn: &[u8], announced: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend((withdrawn.len() as u16).to_be_bytes());
    out.extend(withdrawn);
    out.extend((attrs.len() as u16).to_be_bytes());
    out.extend(attrs);
    out.extend(announced);
    bgp(2, &out)
}
fn peer(flags: u8, kind: u8) -> Vec<u8> {
    let mut out = vec![kind, flags];
    out.extend([0; 20]);
    out.extend([192, 0, 2, 1]);
    out.extend(65000u32.to_be_bytes());
    out.extend([192, 0, 2, 2]);
    out.extend(1u32.to_be_bytes());
    out.extend(123456u32.to_be_bytes());
    out
}
fn open(caps: &[u8]) -> Vec<u8> {
    let params = if caps.is_empty() {
        vec![]
    } else {
        [vec![2, caps.len() as u8], caps.to_vec()].concat()
    };
    let mut out = vec![4];
    out.extend(65000u16.to_be_bytes());
    out.extend(90u16.to_be_bytes());
    out.extend([192, 0, 2, 2]);
    out.push(params.len() as u8);
    out.extend(params);
    bgp(1, &out)
}
fn ip_packet(payload: &[u8], ipv6: bool, seq: u32, flags: u8) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend(12345u16.to_be_bytes());
    tcp.extend(11019u16.to_be_bytes());
    tcp.extend(seq.to_be_bytes());
    tcp.extend([0; 4]);
    tcp.extend([0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    tcp.extend(payload);
    if ipv6 {
        let mut out = vec![0x60, 0, 0, 0];
        out.extend((tcp.len() as u16).to_be_bytes());
        out.extend([6, 64]);
        out.extend("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        out.extend("2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        out.extend(tcp);
        out
    } else {
        let mut out = vec![0x45, 0];
        out.extend(((tcp.len() + 20) as u16).to_be_bytes());
        out.extend([0, 1, 0x40, 0, 64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
        out.extend(tcp);
        out
    }
}
fn ethernet(payload: &[u8]) -> Vec<u8> {
    [vec![0; 12], vec![8, 0], ip_packet(payload, false, 1, 0x18)].concat()
}
fn word(value: u32, little: bool) -> [u8; 4] {
    if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    }
}
fn half(value: u16, little: bool) -> [u8; 2] {
    if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    }
}
fn pcap(packets: &[Vec<u8>], little: bool, nano: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(word(if nano { 0xa1b23c4d } else { 0xa1b2c3d4 }, little));
    out.extend(half(2, little));
    out.extend(half(4, little));
    for v in [0, 0, 65535, 1] {
        out.extend(word(v, little));
    }
    for packet in packets {
        for v in [100, 123, packet.len() as u32, packet.len() as u32] {
            out.extend(word(v, little));
        }
        out.extend(packet);
    }
    out
}
fn block(kind: u32, mut body: Vec<u8>, little: bool) -> Vec<u8> {
    body.resize(body.len().next_multiple_of(4), 0);
    let size = (body.len() + 12) as u32;
    [
        word(kind, little).to_vec(),
        word(size, little).to_vec(),
        body,
        word(size, little).to_vec(),
    ]
    .concat()
}
fn pcapng(data: &[u8], little: bool, resolution: u8) -> Vec<u8> {
    let mut h = word(0x1a2b3c4d, little).to_vec();
    h.extend(half(1, little));
    h.extend(half(0, little));
    h.extend([255; 8]);
    let mut iface = half(1, little).to_vec();
    iface.extend(half(0, little));
    iface.extend(word(65535, little));
    iface.extend(half(9, little));
    iface.extend(half(1, little));
    iface.extend([resolution, 0, 0, 0]);
    iface.extend(half(14, little));
    iface.extend(half(8, little));
    iface.extend(if little {
        2i64.to_le_bytes()
    } else {
        2i64.to_be_bytes()
    });
    let mut packet = Vec::new();
    for v in [0, 0, 1024, data.len() as u32, data.len() as u32] {
        packet.extend(word(v, little));
    }
    packet.extend(data);
    [
        block(0x0a0d0d0a, h, little),
        block(1, iface, little),
        block(6, packet, little),
    ]
    .concat()
}
fn packets(data: Vec<u8>) -> anyhow::Result<Vec<Packet>> {
    let mut capture = Capture::new(Cursor::new(data))?;
    let mut out = Vec::new();
    while let Some(p) = capture.next_packet()? {
        out.push(p);
    }
    Ok(out)
}
fn parse(data: &[u8]) -> Value {
    parse_bgp(data, 4, &Families::new()).unwrap()
}
fn invoke(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_netom-bmpdump"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("TERM", "xterm-256color")
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn pcap_endian_and_precision() {
    for little in [false, true] {
        for nano in [false, true] {
            let p = packets(pcap(&[ethernet(&bmp(4, &[]))], little, nano))
                .unwrap();
            assert_eq!(
                p[0].timestamp_ns,
                Some(100_000_000_000 + 123 * if nano { 1 } else { 1000 })
            );
            assert_eq!(
                tcp_segment(&p[0]).unwrap().unwrap().payload,
                bmp(4, &[])
            );
        }
    }
}
#[test]
fn pcapng_sections_and_timestamps() {
    let data = ethernet(&bmp(4, &[]));
    let p = packets(
        [pcapng(&data, true, 9), pcapng(&data, false, 0x8a)].concat(),
    )
    .unwrap();
    assert_eq!((p[0].section, p[1].section), (0, 1));
    assert_eq!(
        (p[0].timestamp_ns, p[1].timestamp_ns),
        (Some(2_000_001_024), Some(3_000_000_000))
    );
}
#[test]
fn pcapng_simple_and_obsolete_blocks() {
    let data = ethernet(&bmp(4, &[]));
    let mut section = pcapng(&data, true, 9);
    section.extend(block(
        3,
        [word(data.len() as u32, true).to_vec(), data.clone()].concat(),
        true,
    ));
    let mut old = vec![0; 4];
    for n in [0, 1024, data.len() as u32, data.len() as u32] {
        old.extend(word(n, true));
    }
    old.extend(&data);
    section.extend(block(2, old, true));
    let p = packets(section).unwrap();
    assert_eq!(p.len(), 3);
    assert_eq!(p[1].timestamp_ns, None);
    assert_eq!(p[1].data, data);
    assert_eq!(p[2].timestamp_ns, Some(2_000_001_024));
}
#[test]
fn extreme_timestamp_resolution_does_not_overflow() {
    let p = packets(pcapng(&ethernet(&bmp(4, &[])), true, 127)).unwrap();
    assert_eq!(p[0].timestamp_ns, Some(2_000_000_000));
}
#[test]
fn corrupt_capture_lengths() {
    let mut p = pcap(&[ethernet(&bmp(4, &[]))], true, false);
    p.pop();
    let mut ng = pcapng(&ethernet(&bmp(4, &[])), true, 9);
    ng.pop();
    let mut mismatch = pcapng(&ethernet(&bmp(4, &[])), true, 9);
    let len = mismatch.len();
    mismatch[len - 4..].fill(0);
    for raw in [vec![], b"nope".to_vec(), p, ng, mismatch] {
        assert!(packets(raw).is_err());
    }
}
#[test]
fn link_types_ipv6_and_vlan() {
    let raw = ip_packet(&bmp(4, &[]), false, 1, 0x18);
    let fixtures = [
        (
            1,
            [vec![0; 12], vec![0x81, 0, 0, 100, 8, 0], raw.clone()].concat(),
        ),
        (101, raw.clone()),
        (113, [vec![0; 14], vec![8, 0], raw.clone()].concat()),
        (276, [vec![8, 0], vec![0; 18], raw.clone()].concat()),
        (101, ip_packet(&bmp(4, &[]), true, 1, 0x18)),
        (0, [vec![2, 0, 0, 0], raw.clone()].concat()),
        (108, [vec![0, 0, 0, 2], raw].concat()),
    ];
    for (linktype, data) in fixtures {
        let p = Packet {
            number: 1,
            timestamp_ns: Some(0),
            linktype,
            original_length: data.len(),
            data,
            section: 0,
            interface: 0,
        };
        assert_eq!(tcp_segment(&p).unwrap().unwrap().payload, bmp(4, &[]));
    }
}
#[test]
fn fragments_and_truncated_tcp() {
    let mut raw = ip_packet(&bmp(4, &[]), false, 1, 0x18);
    raw[6..8].copy_from_slice(&[0x20, 0]);
    let mut short = ip_packet(&bmp(4, &[]), false, 1, 0x18);
    short.pop();
    for data in [raw, short] {
        let p = Packet {
            number: 1,
            timestamp_ns: None,
            linktype: 101,
            original_length: data.len(),
            data,
            section: 0,
            interface: 0,
        };
        assert!(tcp_segment(&p).is_err());
    }
}
#[test]
fn split_coalesced_and_duplicate_messages() {
    let m = bmp(4, &[]);
    let mut s = Stream::new(Some(10));
    assert!(s.feed(10, &m[..3]).unwrap().is_empty());
    assert_eq!(
        s.feed(13, &[m[3..].to_vec(), m.clone()].concat()).unwrap(),
        vec![m.clone(), m.clone()]
    );
    assert!(s.feed(10, &m).unwrap().is_empty());
    assert!(s.unfinished().is_none());
}
#[test]
fn out_of_order_and_overlap() {
    let m = bmp(4, &[]);
    let mut s = Stream::new(Some(100));
    assert!(s.feed(103, &m[3..]).unwrap().is_empty());
    assert_eq!(s.feed(100, &m[..3]).unwrap(), vec![m.clone()]);
    let mut s = Stream::new(Some(1));
    assert!(s.feed(1, &m[..4]).unwrap().is_empty());
    assert_eq!(
        s.feed(3, &[m[2..].to_vec(), m.clone()].concat()).unwrap(),
        vec![m.clone(), m]
    );
}
#[test]
fn sequence_wrap_gaps_and_midstream() {
    let m = bmp(4, &[]);
    let mut s = Stream::new(Some(0xfffffffd));
    assert!(s.feed(0xfffffffd, &m[..3]).unwrap().is_empty());
    assert_eq!(s.feed(0, &m[3..]).unwrap(), vec![m.clone()]);
    let mut s = Stream::new(Some(10));
    s.feed(11, &m).unwrap();
    assert!(s.unfinished().unwrap().contains("TCP gap"));
    let mut s = Stream::new(None);
    assert_eq!(
        s.feed(10, &[b"junk".to_vec(), m.clone()].concat()).unwrap(),
        vec![m]
    );
    assert_eq!(s.skipped, 4);
}
#[test]
fn invalid_framing_and_conflicting_retransmission() {
    assert!(
        Stream::new(Some(1))
            .feed(1, &[3, 255, 255, 255, 255, 4])
            .is_err()
    );
    let mut s = Stream::new(Some(1));
    s.feed(2, &[1, 2, 3]).unwrap();
    assert!(s.feed(2, &[1, 2, 4]).is_err());
}
#[test]
fn bmp_initiation_and_unknown() {
    let mut decoder = BmpDecoder::new(false);
    assert_eq!(
        decoder
            .decode(&bmp(4, &[0, 2, 0, 3, b'r', b'0', b'1']))
            .unwrap()["information"][0]["value"],
        "r01"
    );
    assert_eq!(
        decoder.decode(&bmp(222, b"test")).unwrap()["raw"],
        "74657374"
    );
}
#[test]
fn unicast_withdrawals_and_eor() {
    let m = parse(&update(&[], &[8, 10], &[24, 192, 0, 2]));
    assert_eq!(m["routes"][0]["prefix"], "10.0.0.0/8");
    assert_eq!(m["routes"][0]["action"], "withdraw");
    assert_eq!(m["routes"][1]["prefix"], "192.0.2.0/24");
    assert_eq!(
        parse(&update(&[], &[], &[]))["end_of_rib"],
        json!([{"afi":1,"safi":1}])
    );
    assert_eq!(
        parse(&update(&attr(15, &[0, 2, 1]), &[], &[]))["end_of_rib"],
        json!([{"afi":2,"safi":1}])
    );
}
#[test]
fn ipv6_mp_reach() {
    let mut value = vec![0, 2, 1, 16];
    value.extend("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
    value.extend([0, 32, 0x20, 1, 0xd, 0xb8]);
    let m = parse(&update(&attr(14, &value), &[], &[]));
    assert_eq!(m["routes"][0]["prefix"], "2001:db8::/32");
    assert_eq!(m["routes"][0]["next_hop"], json!(["2001:db8::1"]));
}
#[test]
fn two_and_four_byte_asns() {
    for (flags, width) in [(0, 4), (32, 2)] {
        let mut path = vec![1, 2];
        for asn in [65000u32, 65001] {
            path.extend(&asn.to_be_bytes()[4 - width..]);
        }
        let m = BmpDecoder::new(false)
            .decode(&bmp(
                0,
                &[peer(flags, 0), update(&attr(2, &path), &[], &[])].concat(),
            ))
            .unwrap();
        assert_eq!(
            m["bgp"][0]["attributes"][0]["segments"],
            json!([{"type":1,"asns":[65000,65001]}])
        );
    }
}
fn evpn_bodies() -> Vec<Vec<u8>> {
    let rd = vec![0, 0, 0xfd, 0xe8, 0, 0, 0, 1];
    let esi = vec![0; 10];
    let tag = vec![0; 4];
    let label = vec![1, 0x8a, 0x88];
    vec![
        [rd.clone(), esi.clone(), tag.clone(), label.clone()].concat(),
        [
            rd.clone(),
            esi.clone(),
            tag.clone(),
            vec![48, 2, 3, 4, 5, 6, 7, 32, 192, 0, 2, 1],
            label.clone(),
        ]
        .concat(),
        [rd.clone(), tag.clone(), vec![32, 192, 0, 2, 2]].concat(),
        [rd.clone(), esi.clone(), vec![32, 192, 0, 2, 2]].concat(),
        [rd, esi, tag, vec![24, 192, 0, 2, 0, 192, 0, 2, 1], label].concat(),
    ]
}
#[test]
fn evpn_types_one_through_five() {
    let bodies = evpn_bodies();
    for (i, body) in bodies.iter().enumerate() {
        assert_eq!(evpn_route(i as u8 + 1, body).unwrap()["rd"], "65000:1");
    }
    assert_eq!(evpn_route(5, &bodies[4]).unwrap()["prefix"], "192.0.2.0/24");
    let mut v6 = bodies[4][..22].to_vec();
    v6.push(64);
    v6.extend("2001:db8::".parse::<Ipv6Addr>().unwrap().octets());
    v6.extend([0; 16]);
    v6.extend([1, 0x8a, 0x88]);
    assert_eq!(evpn_route(5, &v6).unwrap()["prefix"], "2001:db8::/64");
}
#[test]
fn evpn_vni_and_withdrawal_raw_labels() {
    let bodies = evpn_bodies();
    let encoded =
        [vec![2, bodies[1].len() as u8], bodies[1].clone()].concat();
    let mp = attr(
        14,
        &[vec![0, 25, 70, 4, 192, 0, 2, 2, 0], encoded.clone()].concat(),
    );
    let vxlan = attr(
        16,
        &[3, 12, 0, 0, 0, 0, 0, 8, 0, 2, 0xfd, 0xe8, 0, 0, 3, 0xe8],
    );
    let m = parse(&update(&[mp, vxlan].concat(), &[], &[]));
    assert_eq!(m["routes"][0]["vni"], json!([101000]));
    assert!(m["routes"][0].get("mpls_labels").is_none());
    let m = parse(&update(
        &attr(15, &[vec![0, 25, 70], encoded].concat()),
        &[],
        &[],
    ));
    assert_eq!(m["routes"][0]["action"], "withdraw");
    assert_eq!(m["routes"][0]["label_raw"], json!([101000]));
}
#[test]
fn add_path_negotiation() {
    let mut decoder = BmpDecoder::new(false);
    decoder
        .decode(&bmp(
            3,
            &[
                peer(0, 0),
                vec![0; 20],
                open(&[69, 4, 0, 1, 1, 1]),
                open(&[69, 4, 0, 1, 1, 2]),
            ]
            .concat(),
        ))
        .unwrap();
    let m = decoder
        .decode(&bmp(
            0,
            &[peer(0, 0), update(&[], &[], &[0, 0, 0, 7, 24, 192, 0, 2])]
                .concat(),
        ))
        .unwrap();
    assert_eq!(m["bgp"][0]["routes"][0]["path_id"], 7);
}
#[test]
fn loc_rib_flags_and_malformed_open() {
    let m = BmpDecoder::new(false)
        .decode(&bmp(0, &[peer(128, 3), update(&[], &[], &[])].concat()))
        .unwrap();
    assert_eq!(m["peer"]["address"], "192.0.2.1");
    assert_eq!(m["peer"]["filtered"], true);
    let m = BmpDecoder::new(false)
        .decode(&bmp(
            3,
            &[peer(0, 0), vec![0; 20], open(&[]), bgp(1, &[])].concat(),
        ))
        .unwrap();
    assert_eq!(m["peer"]["asn"], 65000);
    assert!(m["errors"].is_array());
    assert_eq!(m["bgp"][1]["length"], 19);
}
#[test]
fn unknown_attributes_families_and_truncation() {
    let m = parse(&update(
        &[attr(240, b"xyz"), attr(15, &[0, 1, 128, 255])].concat(),
        &[],
        &[],
    ));
    assert_eq!(m["attributes"][0]["raw"], "78797a");
    assert_eq!(m["routes"][0]["unsupported"], true);
    for data in [
        bgp(1, &[]),
        update(&attr(2, &[2, 1]), &[], &[]),
        update(&[], &[], &[33]),
        update(&attr(16, &[0]), &[], &[]),
        bgp(4, b"x"),
    ] {
        assert!(parse_bgp(&data, 4, &Families::new()).is_err());
    }
}
#[test]
fn cli_stdin_json_and_count() {
    let raw = pcap(
        &[ethernet(&[bmp(4, &[]), bmp(4, &[])].concat())],
        true,
        false,
    );
    let out = invoke(&["-r", "-", "-j", "-c", "1"], &raw);
    assert!(out.status.success(), "{:?}", out);
    let m: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(m["name"], "initiation");
}
#[test]
fn cli_filters_and_invalid_input() {
    let raw = pcap(
        &[ethernet(
            &[
                bmp(0, &[peer(0, 0), update(&[], &[], &[])].concat()),
                bmp(4, &[]),
            ]
            .concat(),
        )],
        true,
        false,
    );
    let out = invoke(
        &[
            "-r",
            "-",
            "--type",
            "route-monitoring",
            "--peer",
            "192.0.2.1",
            "-j",
        ],
        &raw,
    );
    assert!(out.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["name"],
        "route-monitoring"
    );
    let out = invoke(&["-r", "-"], b"bad!");
    assert_eq!(out.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}
#[test]
fn cli_colors_pipes_and_json() {
    let raw = pcap(&[ethernet(&bmp(4, &[]))], true, false);
    for args in [
        vec!["-r", "-", "-v"],
        vec!["-r", "-", "--color", "never"],
        vec!["-r", "-", "--color", "always", "-j"],
    ] {
        let out = invoke(&args, &raw);
        assert!(out.status.success());
        assert!(!out.stdout.contains(&27));
    }
    let out = invoke(&["-r", "-", "-v", "--color", "always"], &raw);
    assert!(out.status.success());
    assert!(out.stdout.contains(&27));
}

#[test]
fn closed_output_pipe_exits_cleanly() {
    let raw = pcap(&[ethernet(&bmp(4, &[]).repeat(4000))], true, false);
    for extra in [vec![], vec!["-j"]] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_netom-bmpdump"))
            .args(["-r", "-"])
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let _ = child.stdin.take().unwrap().write_all(&raw);
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty());
    }
}
#[test]
fn supplied_capture_regression() {
    let Some(path) = std::env::var_os("NETOM_BMPDUMP_TEST_CAPTURE") else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    assert!(
        path.is_file(),
        "reference capture does not exist: {}",
        path.display()
    );
    let out = invoke(&["-r", path.to_str().unwrap(), "--summary", "-j"], &[]);
    assert_eq!(out.status.code(), Some(2));
    let m: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(m["packets"], 7513);
    assert_eq!(m["bmp_messages"], 44398);
    assert_eq!(m["matched_messages"], 44398);
    assert_eq!(m["decode_errors"], 6);
    assert_eq!(m["diagnostics"], 6);
    assert_eq!(m["message_types"]["peer-up"], 96);
    assert_eq!(
        m["evpn_route_types"],
        json!({"1":78,"2":28576,"3":14916,"4":52,"5":30})
    );
}
#[test]
fn truncated_valid_messages_never_panic() {
    let data =
        bmp(3, &[peer(0, 0), vec![0; 20], open(&[]), open(&[])].concat());
    for n in 0..data.len() {
        assert!(BmpDecoder::new(false).decode(&data[..n]).is_err());
    }
    let bgp =
        update(&attr(16, &[3, 12, 0, 0, 0, 0, 0, 8]), &[], &[24, 192, 0, 2]);
    for n in 0..bgp.len() {
        assert!(parse_bgp(&bgp[..n], 4, &Families::new()).is_err());
    }
}
