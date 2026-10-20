use anyhow::{Result, bail, ensure};
use std::io::{ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_BLOCK: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, data: &[u8]) -> u16 {
        let bytes = [data[0], data[1]];
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }
    fn u32(self, data: &[u8]) -> u32 {
        let bytes = [data[0], data[1], data[2], data[3]];
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }
    fn i64(self, data: &[u8]) -> i64 {
        let bytes = data[..8].try_into().unwrap();
        match self {
            Self::Little => i64::from_le_bytes(bytes),
            Self::Big => i64::from_be_bytes(bytes),
        }
    }
}

pub struct Packet {
    pub number: u64,
    pub timestamp_ns: Option<i128>,
    pub linktype: u16,
    pub data: Vec<u8>,
    pub original_length: usize,
    pub section: u64,
    pub interface: u32,
}

struct Interface {
    linktype: u16,
    snaplen: usize,
    resolution: Option<u128>,
    offset: i64,
}

enum Format {
    Pcap {
        endian: Endian,
        scale: u32,
        snaplen: usize,
        linktype: u16,
    },
    Pcapng {
        endian: Endian,
        first: bool,
    },
}

pub struct Capture<R> {
    reader: R,
    format: Format,
    interfaces: Vec<Interface>,
    number: u64,
    section: u64,
}

fn exact(reader: &mut impl Read, size: usize) -> Result<Vec<u8>> {
    let mut data = vec![0; size];
    reader.read_exact(&mut data).map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            anyhow::anyhow!("truncated capture: expected {size} bytes")
        } else {
            e.into()
        }
    })?;
    Ok(data)
}

fn optional_exact(
    reader: &mut impl Read,
    size: usize,
) -> Result<Option<Vec<u8>>> {
    let mut first = [0];
    loop {
        match reader.read(&mut first) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let mut data = vec![first[0]];
    data.extend(exact(reader, size - 1)?);
    Ok(Some(data))
}

impl<R: Read> Capture<R> {
    pub fn new(mut reader: R) -> Result<Self> {
        let magic = exact(&mut reader, 4)?;
        let encoding = match magic.as_slice() {
            [0xd4, 0xc3, 0xb2, 0xa1] => Some((Endian::Little, 1000)),
            [0xa1, 0xb2, 0xc3, 0xd4] => Some((Endian::Big, 1000)),
            [0x4d, 0x3c, 0xb2, 0xa1] => Some((Endian::Little, 1)),
            [0xa1, 0xb2, 0x3c, 0x4d] => Some((Endian::Big, 1)),
            [0x0a, 0x0d, 0x0d, 0x0a] => None,
            _ => bail!("not a PCAP or PCAPNG file"),
        };
        let format = if let Some((endian, scale)) = encoding {
            let header = exact(&mut reader, 20)?;
            ensure!(
                endian.u16(&header) == 2 && endian.u16(&header[2..]) == 4,
                "unsupported PCAP version"
            );
            Format::Pcap {
                endian,
                scale,
                snaplen: endian.u32(&header[12..]) as usize,
                linktype: endian.u32(&header[16..]) as u16,
            }
        } else {
            Format::Pcapng {
                endian: Endian::Little,
                first: true,
            }
        };
        Ok(Self {
            reader,
            format,
            interfaces: Vec::new(),
            number: 0,
            section: 0,
        })
    }

    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        if let Format::Pcap {
            endian,
            scale,
            snaplen,
            linktype,
        } = self.format
        {
            let Some(h) = optional_exact(&mut self.reader, 16)? else {
                return Ok(None);
            };
            let sec = endian.u32(&h);
            let frac = endian.u32(&h[4..]);
            let size = endian.u32(&h[8..]) as usize;
            let original = endian.u32(&h[12..]) as usize;
            ensure!(
                size <= MAX_BLOCK
                    && size <= original
                    && (snaplen == 0 || size <= snaplen),
                "invalid PCAP captured length"
            );
            ensure!(
                frac < 1_000_000_000 / scale,
                "invalid PCAP timestamp fraction"
            );
            self.number += 1;
            return Ok(Some(Packet {
                number: self.number,
                timestamp_ns: Some(
                    i128::from(sec) * 1_000_000_000
                        + i128::from(frac) * i128::from(scale),
                ),
                linktype,
                data: exact(&mut self.reader, size)?,
                original_length: original,
                section: 0,
                interface: 0,
            }));
        }
        loop {
            let Format::Pcapng { mut endian, first } = self.format else {
                unreachable!()
            };
            let magic = if first {
                vec![0x0a, 0x0d, 0x0d, 0x0a]
            } else if let Some(magic) = optional_exact(&mut self.reader, 4)? {
                magic
            } else {
                return Ok(None);
            };
            let length = exact(&mut self.reader, 4)?;
            let section_header = magic == [0x0a, 0x0d, 0x0d, 0x0a];
            let prefix = if section_header {
                exact(&mut self.reader, 4)?
            } else {
                vec![]
            };
            if section_header {
                endian = match prefix.as_slice() {
                    [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
                    [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
                    _ => bail!("invalid PCAPNG byte-order magic"),
                };
            }
            let size = endian.u32(&length) as usize;
            ensure!(
                size >= 12 + prefix.len()
                    && size.is_multiple_of(4)
                    && size <= MAX_BLOCK,
                "invalid or oversized PCAPNG block: {size}"
            );
            let rest = exact(&mut self.reader, size - 8 - prefix.len())?;
            ensure!(
                endian.u32(&rest[rest.len() - 4..]) as usize == size,
                "PCAPNG block lengths disagree"
            );
            let mut body = prefix;
            body.extend_from_slice(&rest[..rest.len() - 4]);
            self.format = Format::Pcapng {
                endian,
                first: false,
            };
            let kind = endian.u32(&magic);
            match kind {
                0x0a0d0d0a => {
                    ensure!(
                        body.len() >= 16 && endian.u16(&body[4..]) == 1,
                        "unsupported PCAPNG section"
                    );
                    if !first {
                        self.section += 1;
                    }
                    self.interfaces.clear();
                }
                1 => {
                    ensure!(body.len() >= 8, "short PCAPNG interface block");
                    let mut iface = Interface {
                        linktype: endian.u16(&body),
                        snaplen: endian.u32(&body[4..]) as usize,
                        resolution: Some(1_000_000),
                        offset: 0,
                    };
                    let mut pos = 8;
                    while pos < body.len() {
                        ensure!(
                            body.len() - pos >= 4,
                            "truncated PCAPNG option"
                        );
                        let code = endian.u16(&body[pos..]);
                        let size = endian.u16(&body[pos + 2..]) as usize;
                        pos += 4;
                        if code == 0 {
                            ensure!(
                                size == 0,
                                "invalid PCAPNG end-of-options"
                            );
                            break;
                        }
                        let padded = (size + 3) & !3;
                        ensure!(
                            padded <= body.len() - pos,
                            "PCAPNG option exceeds block"
                        );
                        let value = &body[pos..pos + size];
                        match code {
                            9 => {
                                ensure!(size == 1, "invalid if_tsresol");
                                let exponent = value[0];
                                iface.resolution = if exponent & 128 != 0 {
                                    2u128.checked_pow(u32::from(
                                        exponent & 127,
                                    ))
                                } else {
                                    10u128.checked_pow(u32::from(exponent))
                                };
                            }
                            14 => {
                                ensure!(size == 8, "invalid if_tsoffset");
                                iface.offset = endian.i64(value);
                            }
                            _ => {}
                        }
                        pos += padded;
                    }
                    self.interfaces.push(iface);
                }
                2 | 3 | 6 => {
                    let (interface, captured, original, start, ticks) =
                        if kind == 3 {
                            ensure!(
                                body.len() >= 4
                                    && !self.interfaces.is_empty(),
                                "invalid PCAPNG simple packet block"
                            );
                            let original = endian.u32(&body) as usize;
                            let snaplen = self.interfaces[0].snaplen;
                            (
                                0,
                                original.min(if snaplen == 0 {
                                    original
                                } else {
                                    snaplen
                                }),
                                original,
                                4,
                                None,
                            )
                        } else {
                            ensure!(
                                body.len() >= 20,
                                "short PCAPNG packet block"
                            );
                            let iface = if kind == 6 {
                                endian.u32(&body)
                            } else {
                                u32::from(endian.u16(&body))
                            };
                            let ticks = (u64::from(endian.u32(&body[4..]))
                                << 32)
                                | u64::from(endian.u32(&body[8..]));
                            (
                                iface,
                                endian.u32(&body[12..]) as usize,
                                endian.u32(&body[16..]) as usize,
                                20,
                                Some(ticks),
                            )
                        };
                    let iface = self
                        .interfaces
                        .get(interface as usize)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "unknown PCAPNG interface {interface}"
                            )
                        })?;
                    ensure!(
                        captured <= original
                            && (iface.snaplen == 0
                                || captured <= iface.snaplen)
                            && captured <= MAX_BLOCK
                            && start + ((captured + 3) & !3) <= body.len(),
                        "invalid PCAPNG packet length"
                    );
                    let timestamp_ns = ticks.map(|t| {
                        let fraction = iface
                            .resolution
                            .map_or(0, |d| u128::from(t) * 1_000_000_000 / d);
                        fraction as i128
                            + i128::from(iface.offset) * 1_000_000_000
                    });
                    self.number += 1;
                    return Ok(Some(Packet {
                        number: self.number,
                        timestamp_ns,
                        linktype: iface.linktype,
                        data: body[start..start + captured].to_vec(),
                        original_length: original,
                        section: self.section,
                        interface,
                    }));
                }
                _ => {}
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Flow {
    pub section: u64,
    pub interface: u32,
    pub tags: Vec<u32>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
}

pub struct Segment<'a> {
    pub flow: Flow,
    pub seq: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

fn slice(data: &[u8], start: usize, count: usize) -> Result<&[u8]> {
    data.get(start..start + count)
        .ok_or_else(|| anyhow::anyhow!("truncated network packet"))
}

pub fn tcp_segment(packet: &Packet) -> Result<Option<Segment<'_>>> {
    let d = &packet.data;
    let mut tags = Vec::new();
    let (mut proto, mut start) = match packet.linktype {
        1 => (Endian::Big.u16(slice(d, 12, 2)?), 14),
        113 => (Endian::Big.u16(slice(d, 14, 2)?), 16),
        276 => {
            slice(d, 0, 20)?;
            tags.push(Endian::Big.u32(&d[4..]));
            (Endian::Big.u16(d), 20)
        }
        101 | 228 | 229 => (
            match slice(d, 0, 1)?[0] >> 4 {
                4 => 0x800,
                6 => 0x86dd,
                _ => 0,
            },
            0,
        ),
        0 | 108 => (
            match slice(d, 4, 1)?[0] >> 4 {
                4 => 0x800,
                6 => 0x86dd,
                _ => 0,
            },
            4,
        ),
        other => bail!("unsupported link type {other}"),
    };
    if packet.linktype == 1 {
        while matches!(proto, 0x8100 | 0x88a8 | 0x9100) {
            let h = slice(d, start, 4)?;
            tags.push(u32::from(Endian::Big.u16(h) & 4095));
            proto = Endian::Big.u16(&h[2..]);
            start += 4;
        }
    }
    let (src, dst, end) = if proto == 0x800 {
        let h = slice(d, start, 20)?;
        let ihl = usize::from(h[0] & 15) * 4;
        let total = Endian::Big.u16(&h[2..]) as usize;
        ensure!(
            h[0] >> 4 == 4 && ihl >= 20 && total >= ihl,
            "invalid IPv4 header"
        );
        slice(d, start, total)?;
        ensure!(
            Endian::Big.u16(&h[6..]) & 0x3fff == 0,
            "fragmented IPv4 packet (IP reassembly is not implemented)"
        );
        if h[9] != 6 {
            return Ok(None);
        }
        let src = IpAddr::V4(Ipv4Addr::new(h[12], h[13], h[14], h[15]));
        let dst = IpAddr::V4(Ipv4Addr::new(h[16], h[17], h[18], h[19]));
        let end = start + total;
        start += ihl;
        (src, dst, end)
    } else if proto == 0x86dd {
        let h = slice(d, start, 40)?;
        ensure!(h[0] >> 4 == 6, "invalid IPv6 version");
        let length = Endian::Big.u16(&h[4..]) as usize;
        ensure!(length != 0, "IPv6 jumbogram");
        let end = start + 40 + length;
        slice(d, start, 40 + length)?;
        let src = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&h[8..24]).unwrap(),
        ));
        let dst = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&h[24..40]).unwrap(),
        ));
        proto = u16::from(h[6]);
        start += 40;
        while matches!(proto, 0 | 43 | 44 | 51 | 60) {
            ensure!(start + 2 <= end, "truncated IPv6 extension");
            let size = if proto == 44 {
                ensure!(start + 8 <= end, "truncated IPv6 fragment header");
                ensure!(
                    Endian::Big.u16(&d[start + 2..]) & 0xfff9 == 0,
                    "fragmented IPv6 packet (IP reassembly is not implemented)"
                );
                8
            } else if proto == 51 {
                (usize::from(d[start + 1]) + 2) * 4
            } else {
                (usize::from(d[start + 1]) + 1) * 8
            };
            proto = u16::from(d[start]);
            start += size;
            ensure!(start <= end, "IPv6 extension exceeds packet");
        }
        if proto != 6 {
            return Ok(None);
        }
        (src, dst, end)
    } else {
        return Ok(None);
    };
    ensure!(start + 20 <= end, "truncated TCP header");
    let h = &d[start..end];
    let hlen = usize::from(h[12] >> 4) * 4;
    ensure!(hlen >= 20 && hlen <= h.len(), "invalid TCP header length");
    Ok(Some(Segment {
        flow: Flow {
            section: packet.section,
            interface: packet.interface,
            tags,
            src,
            dst,
            sport: Endian::Big.u16(h),
            dport: Endian::Big.u16(&h[2..]),
        },
        seq: Endian::Big.u32(&h[4..]),
        flags: h[13],
        payload: &h[hlen..],
    }))
}
