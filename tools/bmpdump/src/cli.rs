use crate::capture::{Capture, Flow, tcp_segment};
use crate::display::{Palette, display_message, safe};
use crate::protocol::{BMP_NAMES, BmpDecoder, array, bmp_name, hex};
use crate::stream::Stream;
use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser, ValueEnum};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU64};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum Color {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Standalone offline BMP/BGP/EVPN decoder for PCAP and PCAPNG"
)]
pub struct Args {
    /// Capture file, or - for stdin
    #[arg(short = 'r', long = "read", value_name = "FILE")]
    pub read: PathBuf,
    /// BMP TCP port; repeatable (default: 11019, 1790)
    #[arg(short = 'p', long = "port")]
    pub port: Vec<NonZeroU16>,
    /// Stop after N matching BMP messages
    #[arg(short = 'c', long = "count")]
    pub count: Option<NonZeroU64>,
    /// Readable message blocks; -vv also adds full decoded JSON
    #[arg(short='v', long="verbose", action=ArgAction::Count)]
    pub verbose: u8,
    /// Numeric addresses (always enabled)
    #[arg(short = 'n')]
    pub numeric: bool,
    /// Newline-delimited JSON (always plain)
    #[arg(short = 'j', long = "json")]
    pub json: bool,
    /// ANSI colors for text output; auto honors NO_COLOR
    #[arg(long, value_enum, default_value = "auto")]
    pub color: Color,
    /// Only print aggregate counts (JSON with -j)
    #[arg(long)]
    pub summary: bool,
    /// Filter by BMP exporter source address
    #[arg(long)]
    pub router: Option<IpAddr>,
    /// Filter by monitored BGP peer address
    #[arg(long)]
    pub peer: Option<IpAddr>,
    /// BMP message type
    #[arg(long="type", value_parser=BMP_NAMES)]
    pub message_type: Option<String>,
    /// Only messages containing EVPN NLRI
    #[arg(long)]
    pub evpn: bool,
    /// Only messages containing this EVPN route type
    #[arg(long, value_parser=clap::value_parser!(u8).range(1..=5))]
    pub route_type: Option<u8>,
    /// Force ADD-PATH for supported families when Peer Up is missing
    #[arg(long)]
    pub add_path: bool,
}

pub fn routes_of(message: &Value) -> impl Iterator<Item = &Value> {
    array(&message["bgp"])
        .iter()
        .flat_map(|b| array(&b["routes"]).iter())
}
fn matches(message: &Value, args: &Args) -> bool {
    args.router.is_none_or(|ip| {
        message["source"]["address"].as_str() == Some(ip.to_string().as_str())
    }) && args.peer.is_none_or(|ip| {
        message["peer"]["address"].as_str() == Some(ip.to_string().as_str())
    }) && args
        .message_type
        .as_ref()
        .is_none_or(|kind| message["name"].as_str() == Some(kind.as_str()))
        && (!args.evpn
            || routes_of(message).any(|r| r["afi"] == 25 && r["safi"] == 70))
        && args.route_type.is_none_or(|kind| {
            routes_of(message).any(|r| r["route_type"] == kind)
        })
}

struct Connection {
    stream: Stream,
    decoder: BmpDecoder,
}
struct Diagnostics {
    count: u64,
    colors: Palette,
}
impl Diagnostics {
    fn warn(&mut self, message: &str) -> Result<()> {
        self.count += 1;
        if self.count <= 20 {
            writeln!(
                io::stderr().lock(),
                "{}",
                self.colors.paint(
                    &format!("netom-bmpdump: {}", safe(message)),
                    "warning"
                )
            )?;
        } else if self.count == 21 {
            writeln!(
                io::stderr().lock(),
                "netom-bmpdump: further diagnostics suppressed; see final count"
            )?;
        }
        Ok(())
    }
}
fn increment(counts: &mut BTreeMap<String, u64>, name: impl Into<String>) {
    *counts.entry(name.into()).or_default() += 1;
}

pub fn run(args: &Args) -> Result<i32> {
    let ports: Vec<u16> = if args.port.is_empty() {
        vec![11019, 1790]
    } else {
        args.port.iter().map(|p| p.get()).collect()
    };
    let mut connections: HashMap<Flow, Connection> = HashMap::new();
    let colors = Palette::new(
        if args.json { Color::Never } else { args.color },
        false,
    );
    let mut diagnostics = Diagnostics {
        count: 0,
        colors: Palette::new(args.color, true),
    };
    let (
        mut packets,
        mut tcp_packets,
        mut bmp_messages,
        mut matched_messages,
        mut decode_errors,
    ) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut types, mut route_types, mut actions, mut exporters) = (
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let source: Box<dyn Read> = if args.read.as_os_str() == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(&args.read).with_context(|| {
            format!("cannot open capture '{}'", args.read.display())
        })?)
    };
    let mut capture = Capture::new(BufReader::new(source))?;
    let mut out = BufWriter::new(io::stdout().lock());
    let mut stopped = false;
    while let Some(packet) = capture.next_packet()? {
        packets += 1;
        let segment = match tcp_segment(&packet) {
            Ok(Some(s)) => s,
            Ok(None) => continue,
            Err(error) => {
                diagnostics
                    .warn(&format!("frame {}: {error}", packet.number))?;
                continue;
            }
        };
        if !ports.contains(&segment.flow.sport)
            && !ports.contains(&segment.flow.dport)
        {
            continue;
        }
        tcp_packets += 1;
        let key = segment.flow;
        let syn = segment.flags & 2 != 0;
        if syn
            && connections
                .get(&key)
                .is_none_or(|s| s.stream.syn_seq != Some(segment.seq))
        {
            if let Some(old) = connections.get(&key)
                && let Some(problem) = old.stream.unfinished()
            {
                diagnostics.warn(&format!(
                    "frame {}: connection restarted with {problem}",
                    packet.number
                ))?;
            }
            let mut stream = Stream::new(Some(segment.seq.wrapping_add(1)));
            stream.syn_seq = Some(segment.seq);
            connections.insert(
                key.clone(),
                Connection {
                    stream,
                    decoder: BmpDecoder::new(args.add_path),
                },
            );
        }
        if !connections.contains_key(&key) {
            if segment.payload.is_empty() {
                continue;
            }
            connections.insert(
                key.clone(),
                Connection {
                    stream: Stream::new(None),
                    decoder: BmpDecoder::new(args.add_path),
                },
            );
        }
        if connections.len() > 256 {
            bail!(
                "more than 256 TCP directions; split the capture into smaller files"
            );
        }
        let conn = connections.get_mut(&key).unwrap();
        let before = conn.stream.skipped;
        let messages = conn
            .stream
            .feed(segment.seq.wrapping_add(u32::from(syn)), segment.payload)
            .map_err(|e| {
                anyhow::anyhow!(
                    "frame {}, {}:{}: {e}",
                    packet.number,
                    key.src,
                    key.sport
                )
            })?;
        if conn.stream.skipped != before {
            diagnostics.warn(&format!(
                "frame {}: skipped {} bytes searching for BMP at capture start",
                packet.number,
                conn.stream.skipped - before
            ))?;
        }
        if connections
            .values()
            .map(|s| s.stream.buffered())
            .sum::<usize>()
            > 64 * 1024 * 1024
        {
            bail!("global TCP buffer limit exceeded");
        }
        for (frame_message, raw) in messages.into_iter().enumerate() {
            bmp_messages += 1;
            let mut message = match connections
                .get_mut(&key)
                .unwrap()
                .decoder
                .decode(&raw)
            {
                Ok(message) => {
                    let errors = array(&message["errors"]);
                    if !errors.is_empty() {
                        decode_errors += 1;
                        for error in errors {
                            diagnostics.warn(&format!(
                                "frame {}: {}",
                                packet.number,
                                error.as_str().unwrap()
                            ))?;
                        }
                    }
                    message
                }
                Err(error) => {
                    decode_errors += 1;
                    diagnostics.warn(&format!(
                        "frame {}: BMP type {}: {error}",
                        packet.number, raw[5]
                    ))?;
                    json!({"type":raw[5],"name":bmp_name(raw[5]),"length":raw.len(),
                           "errors":[error.to_string()],"raw":hex(&raw)})
                }
            };
            message["frame"] = json!(packet.number);
            message["frame_message"] = json!(frame_message + 1);
            message["timestamp_ns"] = json!(packet.timestamp_ns);
            message["source"] =
                json!({"address":key.src.to_string(),"port":key.sport});
            message["destination"] =
                json!({"address":key.dst.to_string(),"port":key.dport});
            if !matches(&message, args) {
                continue;
            }
            matched_messages += 1;
            increment(&mut types, message["name"].as_str().unwrap());
            increment(&mut exporters, key.src.to_string());
            for route in routes_of(&message) {
                increment(&mut actions, route["action"].as_str().unwrap());
                if let Some(kind) = route.get("route_type") {
                    increment(&mut route_types, kind.to_string());
                }
            }
            if !args.summary {
                if args.json {
                    serde_json::to_writer(&mut out, &message)?;
                    writeln!(out)?;
                } else {
                    out.write_all(
                        display_message(&message, args.verbose, colors)
                            .as_bytes(),
                    )?;
                }
            }
            if args.count.is_some_and(|n| matched_messages >= n.get()) {
                stopped = true;
                break;
            }
        }
        if stopped {
            break;
        }
    }
    if !stopped {
        for (key, conn) in &connections {
            if let Some(problem) = conn.stream.unfinished() {
                diagnostics
                    .warn(&format!("{}:{}: {problem}", key.src, key.sport))?;
            }
        }
    }
    if args.summary {
        let result = json!({"packets":packets,"tcp_packets":tcp_packets,"bmp_messages":bmp_messages,
            "matched_messages":matched_messages,"decode_errors":decode_errors,"tcp_directions":connections.len(),
            "diagnostics":diagnostics.count,"stopped_early":stopped,"message_types":types,
            "evpn_route_types":route_types,"route_actions":actions,"exporters":exporters});
        if args.json {
            serde_json::to_writer_pretty(&mut out, &result)?;
            writeln!(out)?;
        } else {
            writeln!(
                out,
                "{packets} packets, {} TCP directions, {bmp_messages} BMP messages, {matched_messages} matched",
                connections.len()
            )?;
            for (title, counts) in [
                ("BMP messages", &types),
                ("EVPN routes", &route_types),
                ("Route actions", &actions),
                ("Exporters", &exporters),
            ] {
                writeln!(
                    out,
                    "{title}: {}",
                    counts
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )?;
            }
            writeln!(
                out,
                "Decode errors: {decode_errors}; diagnostics: {}",
                diagnostics.count
            )?;
            if stopped {
                writeln!(
                    out,
                    "Stopped at the requested message count; counts cover only the scanned portion."
                )?;
            }
        }
    }
    out.flush()?;
    if diagnostics.count != 0 {
        writeln!(
            io::stderr().lock(),
            "netom-bmpdump: {} diagnostic(s); output may be incomplete",
            diagnostics.count
        )?;
    }
    Ok(if diagnostics.count != 0 { 2 } else { 0 })
}
