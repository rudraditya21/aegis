use dataplane::{RssConfig, RssHashField};
use packet_parser::{
    EtherType, IpProtocol, ParseError, parse_ethernet_frame, parse_ipv4_packet,
    parse_ipv6_packet, parse_tcp_segment, parse_udp_datagram,
};
use std::cmp::Ordering;

const DEFAULT_RSS_KEY_LEN: usize = 40;

#[derive(Debug, Clone)]
pub struct FlowHasher {
    key: Vec<u8>,
    symmetric: bool,
    hash_ipv4: bool,
    hash_ipv6: bool,
    hash_tcp: bool,
    hash_udp: bool,
}

impl FlowHasher {
    pub fn from_rss(rss: &RssConfig) -> Self {
        let mut hasher = FlowHasher {
            key: build_rss_key(rss.seed, DEFAULT_RSS_KEY_LEN),
            symmetric: rss.symmetric,
            hash_ipv4: false,
            hash_ipv6: false,
            hash_tcp: false,
            hash_udp: false,
        };
        for field in &rss.hash_fields {
            match field {
                RssHashField::Ipv4 => hasher.hash_ipv4 = true,
                RssHashField::Ipv6 => hasher.hash_ipv6 = true,
                RssHashField::Tcp => hasher.hash_tcp = true,
                RssHashField::Udp => hasher.hash_udp = true,
            }
        }
        hasher
    }

    pub fn hash_packet(&self, bytes: &[u8]) -> Option<u32> {
        let tuple = parse_tuple(bytes).ok()?;
        let include_ports = match tuple.protocol {
            IpProtocol::Tcp => self.hash_tcp,
            IpProtocol::Udp => self.hash_udp,
            _ => false,
        };
        match tuple.ip_version {
            4 if !self.hash_ipv4 => return None,
            6 if !self.hash_ipv6 => return None,
            _ => {}
        }
        let (data, len) = build_tuple_bytes(&tuple, include_ports, self.symmetric);
        Some(toeplitz_hash(&self.key, &data[..len]))
    }
}

#[derive(Debug, Clone)]
pub struct FlowSharder {
    hasher: FlowHasher,
    queues: usize,
}

impl FlowSharder {
    pub fn new(rss: &RssConfig, queues: usize) -> Self {
        FlowSharder {
            hasher: FlowHasher::from_rss(rss),
            queues: queues.max(1),
        }
    }

    pub fn select_queue(&self, bytes: &[u8]) -> usize {
        let hash = self
            .hasher
            .hash_packet(bytes)
            .unwrap_or_else(|| fallback_hash(bytes));
        (hash as usize) % self.queues
    }
}

#[derive(Debug, Clone, Copy)]
struct ParsedTuple {
    ip_version: u8,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    ip_len: usize,
    src_port: u16,
    dst_port: u16,
    protocol: IpProtocol,
}

fn parse_tuple(bytes: &[u8]) -> Result<ParsedTuple, ParseError> {
    let eth = parse_ethernet_frame(bytes)?;
    match eth.ethertype {
        EtherType::Ipv4 => {
            let ip = parse_ipv4_packet(eth.payload)?;
            let mut src_ip = [0u8; 16];
            let mut dst_ip = [0u8; 16];
            src_ip[..4].copy_from_slice(&ip.source);
            dst_ip[..4].copy_from_slice(&ip.destination);
            let (src_port, dst_port) = match ip.protocol {
                IpProtocol::Tcp => {
                    let tcp = parse_tcp_segment(ip.payload)?;
                    (tcp.source_port, tcp.destination_port)
                }
                IpProtocol::Udp => {
                    let udp = parse_udp_datagram(ip.payload)?;
                    (udp.source_port, udp.destination_port)
                }
                _ => (0, 0),
            };
            Ok(ParsedTuple {
                ip_version: 4,
                src_ip,
                dst_ip,
                ip_len: 4,
                src_port,
                dst_port,
                protocol: ip.protocol,
            })
        }
        EtherType::Ipv6 => {
            let ip = parse_ipv6_packet(eth.payload)?;
            let mut src_ip = [0u8; 16];
            let mut dst_ip = [0u8; 16];
            src_ip.copy_from_slice(&ip.source);
            dst_ip.copy_from_slice(&ip.destination);
            let (src_port, dst_port) = match ip.next_header {
                IpProtocol::Tcp => {
                    let tcp = parse_tcp_segment(ip.payload)?;
                    (tcp.source_port, tcp.destination_port)
                }
                IpProtocol::Udp => {
                    let udp = parse_udp_datagram(ip.payload)?;
                    (udp.source_port, udp.destination_port)
                }
                _ => (0, 0),
            };
            Ok(ParsedTuple {
                ip_version: 6,
                src_ip,
                dst_ip,
                ip_len: 16,
                src_port,
                dst_port,
                protocol: ip.next_header,
            })
        }
        _ => Err(ParseError::Unsupported("non-ip ethertype")),
    }
}

fn build_tuple_bytes(
    tuple: &ParsedTuple,
    include_ports: bool,
    symmetric: bool,
) -> ([u8; 36], usize) {
    let mut src = &tuple.src_ip[..tuple.ip_len];
    let mut dst = &tuple.dst_ip[..tuple.ip_len];
    let mut src_port = tuple.src_port;
    let mut dst_port = tuple.dst_port;
    if symmetric && should_swap(src, dst, src_port, dst_port) {
        std::mem::swap(&mut src, &mut dst);
        std::mem::swap(&mut src_port, &mut dst_port);
    }

    let mut data = [0u8; 36];
    let mut len = 0usize;
    data[..src.len()].copy_from_slice(src);
    len += src.len();
    data[len..len + dst.len()].copy_from_slice(dst);
    len += dst.len();
    if include_ports {
        data[len..len + 2].copy_from_slice(&src_port.to_be_bytes());
        len += 2;
        data[len..len + 2].copy_from_slice(&dst_port.to_be_bytes());
        len += 2;
    }
    (data, len)
}

fn should_swap(src: &[u8], dst: &[u8], src_port: u16, dst_port: u16) -> bool {
    match src.cmp(dst) {
        Ordering::Less => false,
        Ordering::Greater => true,
        Ordering::Equal => src_port > dst_port,
    }
}

fn toeplitz_hash(key: &[u8], data: &[u8]) -> u32 {
    if key.len() < 4 {
        return 0;
    }
    let mut hash = 0u32;
    let mut v = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
    let mut key_idx = 4usize;
    let mut key_bit = 0x80u8;

    for byte in data {
        let mut bit = 0x80u8;
        while bit != 0 {
            if byte & bit != 0 {
                hash ^= v;
            }
            v <<= 1;
            if key_idx < key.len() {
                if key[key_idx] & key_bit != 0 {
                    v |= 1;
                }
                if key_bit == 1 {
                    key_bit = 0x80;
                    key_idx += 1;
                } else {
                    key_bit >>= 1;
                }
            }
            bit >>= 1;
        }
    }
    hash
}

fn build_rss_key(seed: Option<u64>, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = seed.unwrap_or(0x6a09e667f3bcc909);
    while out.len() < len {
        state = splitmix64(state);
        for byte in state.to_le_bytes() {
            if out.len() == len {
                break;
            }
            out.push(byte);
        }
    }
    out
}

fn splitmix64(mut state: u64) -> u64 {
    state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn fallback_hash(bytes: &[u8]) -> u32 {
    let mut hash = 2166136261u32;
    for byte in bytes {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(16777619);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toeplitz_hash_is_stable() {
        let key = build_rss_key(Some(42), DEFAULT_RSS_KEY_LEN);
        let data = [0x01u8, 0x02, 0x03, 0x04];
        let h1 = toeplitz_hash(&key, &data);
        let h2 = toeplitz_hash(&key, &data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn flow_sharder_selects_in_range() {
        let rss = RssConfig::default();
        let sharder = FlowSharder::new(&rss, 4);
        let data = [0u8; 64];
        let idx = sharder.select_queue(&data);
        assert!(idx < 4);
    }

    #[test]
    fn symmetric_tuple_swaps_ports() {
        let tuple = ParsedTuple {
            ip_version: 4,
            src_ip: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ip_len: 4,
            src_port: 2000,
            dst_port: 1000,
            protocol: IpProtocol::Tcp,
        };
        let (data, len) = build_tuple_bytes(&tuple, true, true);
        assert_eq!(len, 12);
        assert_eq!(&data[..4], &[10, 0, 0, 1]);
        assert_eq!(&data[4..8], &[10, 0, 0, 2]);
        assert_eq!(&data[8..10], &1000u16.to_be_bytes());
        assert_eq!(&data[10..12], &2000u16.to_be_bytes());
    }
}
