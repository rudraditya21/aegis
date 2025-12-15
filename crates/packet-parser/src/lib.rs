#![forbid(unsafe_code)]

/// Errors that can occur during parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Truncated(&'static str),
    Invalid(&'static str),
    Unsupported(&'static str),
}

/// Known EtherType values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Vlan8021Q,
    QinQ,
    Arp,
    Other(u16),
}

impl EtherType {
    pub fn from_raw(value: u16) -> Self {
        match value {
            0x0800 => EtherType::Ipv4,
            0x86DD => EtherType::Ipv6,
            0x8100 => EtherType::Vlan8021Q,
            0x88A8 => EtherType::QinQ,
            0x0806 => EtherType::Arp,
            other => EtherType::Other(other),
        }
    }

    pub fn as_u16(&self) -> u16 {
        match *self {
            EtherType::Ipv4 => 0x0800,
            EtherType::Ipv6 => 0x86DD,
            EtherType::Vlan8021Q => 0x8100,
            EtherType::QinQ => 0x88A8,
            EtherType::Arp => 0x0806,
            EtherType::Other(v) => v,
        }
    }
}

/// Identifies the payload protocol for IP packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpProtocol {
    Icmpv4,
    Tcp,
    Udp,
    Icmpv6,
    Other(u8),
}

impl IpProtocol {
    pub fn from_raw(value: u8) -> Self {
        match value {
            1 => IpProtocol::Icmpv4,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            58 => IpProtocol::Icmpv6,
            other => IpProtocol::Other(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlanTag {
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
    pub encapsulated_type: EtherType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ethertype: EtherType,
    pub vlan_stack: Vec<VlanTag>,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header<'a> {
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub header_checksum: u16,
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Header<'a> {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: IpProtocol,
    pub hop_limit: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub data_offset: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv4Packet<'a> {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest_of_header: u32,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6Packet<'a> {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest_of_header: u32,
    pub payload: &'a [u8],
}

/// Parse an Ethernet frame and any VLAN tags. Returns the remaining payload.
pub fn parse_ethernet_frame(data: &[u8]) -> Result<EthernetFrame<'_>, ParseError> {
    if data.len() < 14 {
        return Err(ParseError::Truncated("ethernet header"));
    }

    let destination = copy_array(data.get(0..6).ok_or(ParseError::Truncated("dst mac"))?);
    let source = copy_array(data.get(6..12).ok_or(ParseError::Truncated("src mac"))?);
    let mut ethertype = EtherType::from_raw(read_u16(
        data.get(12..14).ok_or(ParseError::Truncated("ethertype"))?,
    ));
    let mut cursor = &data[14..];

    let mut vlan_stack = Vec::new();
    while matches!(ethertype, EtherType::Vlan8021Q | EtherType::QinQ) {
        let tag_bytes = cursor
            .get(0..4)
            .ok_or(ParseError::Truncated("vlan tag header"))?;
        let tci = read_u16(&tag_bytes[0..2]);
        let encapsulated = EtherType::from_raw(read_u16(&tag_bytes[2..4]));
        let vlan_id = tci & 0x0FFF;
        let priority = ((tci & 0xE000) >> 13) as u8;
        let drop_eligible = (tci & 0x1000) != 0;
        vlan_stack.push(VlanTag {
            priority,
            drop_eligible,
            vlan_id,
            encapsulated_type: encapsulated.clone(),
        });
        cursor = cursor
            .get(4..)
            .ok_or(ParseError::Truncated("vlan payload after tag"))?;
        ethertype = encapsulated;
    }

    Ok(EthernetFrame {
        destination,
        source,
        ethertype,
        vlan_stack,
        payload: cursor,
    })
}

/// Parse an IPv4 packet, extracting header fields and payload slice.
pub fn parse_ipv4_packet(data: &[u8]) -> Result<Ipv4Header<'_>, ParseError> {
    if data.len() < 20 {
        return Err(ParseError::Truncated("ipv4 base header"));
    }
    let version = data[0] >> 4;
    if version != 4 {
        return Err(ParseError::Invalid("ipv4 version"));
    }
    let ihl = data[0] & 0x0F;
    let header_length = (ihl as usize) * 4;
    if header_length < 20 {
        return Err(ParseError::Invalid("ipv4 ihl too small"));
    }
    if data.len() < header_length {
        return Err(ParseError::Truncated("ipv4 header with options"));
    }
    let dscp = data[1] >> 2;
    let ecn = data[1] & 0x03;
    let total_length = read_u16(&data[2..4]);
    if total_length < header_length as u16 {
        return Err(ParseError::Invalid("ipv4 total length smaller than header"));
    }
    let total_len_usize = total_length as usize;
    if data.len() < total_len_usize {
        return Err(ParseError::Truncated("ipv4 total length"));
    }

    let identification = read_u16(&data[4..6]);
    let flags_fragment = read_u16(&data[6..8]);
    let flags = (flags_fragment >> 13) as u8;
    let fragment_offset = flags_fragment & 0x1FFF;
    // We currently do not support IPv4 fragmentation/reassembly; drop fragments early.
    if fragment_offset != 0 || (flags_fragment & 0x2000) != 0 {
        return Err(ParseError::Invalid("ipv4 fragments unsupported"));
    }
    let ttl = data[8];
    let protocol = IpProtocol::from_raw(data[9]);
    let header_checksum = read_u16(&data[10..12]);
    let source = copy_array(&data[12..16]);
    let destination = copy_array(&data[16..20]);
    let options = &data[20..header_length];
    let payload = &data[header_length..total_len_usize];

    Ok(Ipv4Header {
        dscp,
        ecn,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        header_checksum,
        source,
        destination,
        options,
        payload,
    })
}

/// Parse an IPv6 packet.
pub fn parse_ipv6_packet(data: &[u8]) -> Result<Ipv6Header<'_>, ParseError> {
    if data.len() < 40 {
        return Err(ParseError::Truncated("ipv6 base header"));
    }
    let version = data[0] >> 4;
    if version != 6 {
        return Err(ParseError::Invalid("ipv6 version"));
    }
    let traffic_class = ((data[0] & 0x0F) << 4) | (data[1] >> 4);
    let flow_label = ((data[1] as u32 & 0x0F) << 16) | ((data[2] as u32) << 8) | data[3] as u32;
    let payload_length = read_u16(&data[4..6]);
    let next_header = IpProtocol::from_raw(data[6]);
    // Drop fragmented IPv6 packets (Fragment header).
    if data[6] == 44 {
        return Err(ParseError::Invalid("ipv6 fragments unsupported"));
    }
    let hop_limit = data[7];
    let source = copy_array(data.get(8..24).ok_or(ParseError::Truncated("ipv6 src"))?);
    let destination = copy_array(data.get(24..40).ok_or(ParseError::Truncated("ipv6 dst"))?);

    let expected_total = 40usize
        .checked_add(payload_length as usize)
        .ok_or(ParseError::Invalid("ipv6 payload length overflow"))?;
    if data.len() < expected_total {
        return Err(ParseError::Truncated("ipv6 payload"));
    }
    let payload = &data[40..expected_total];

    Ok(Ipv6Header {
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        source,
        destination,
        payload,
    })
}

/// Parse a TCP segment.
pub fn parse_tcp_segment(data: &[u8]) -> Result<TcpHeader<'_>, ParseError> {
    if data.len() < 20 {
        return Err(ParseError::Truncated("tcp base header"));
    }
    let source_port = read_u16(&data[0..2]);
    let destination_port = read_u16(&data[2..4]);
    let sequence_number = read_u32(&data[4..8]);
    let acknowledgement_number = read_u32(&data[8..12]);
    let data_offset = data[12] >> 4;
    let header_length = (data_offset as usize) * 4;
    if header_length < 20 {
        return Err(ParseError::Invalid("tcp data offset too small"));
    }
    if data.len() < header_length {
        return Err(ParseError::Truncated("tcp header with options"));
    }
    let flags = ((data[12] as u16 & 0x01) << 8) | data[13] as u16;
    let window_size = read_u16(&data[14..16]);
    let checksum = read_u16(&data[16..18]);
    let urgent_pointer = read_u16(&data[18..20]);
    let options = &data[20..header_length];
    let payload = &data[header_length..];

    Ok(TcpHeader {
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        data_offset,
        flags,
        window_size,
        checksum,
        urgent_pointer,
        options,
        payload,
    })
}

/// Parse a UDP datagram.
pub fn parse_udp_datagram(data: &[u8]) -> Result<UdpDatagram<'_>, ParseError> {
    if data.len() < 8 {
        return Err(ParseError::Truncated("udp header"));
    }
    let source_port = read_u16(&data[0..2]);
    let destination_port = read_u16(&data[2..4]);
    let length = read_u16(&data[4..6]);
    if length < 8 {
        return Err(ParseError::Invalid("udp length too small"));
    }
    let expected_len = length as usize;
    if data.len() < expected_len {
        return Err(ParseError::Truncated("udp payload"));
    }
    let checksum = read_u16(&data[6..8]);
    let payload = &data[8..expected_len];
    Ok(UdpDatagram {
        source_port,
        destination_port,
        length,
        checksum,
        payload,
    })
}

/// Parse an ICMPv4 packet.
pub fn parse_icmpv4_packet(data: &[u8]) -> Result<Icmpv4Packet<'_>, ParseError> {
    if data.len() < 8 {
        return Err(ParseError::Truncated("icmpv4 header"));
    }
    let icmp_type = data[0];
    let code = data[1];
    let checksum = read_u16(&data[2..4]);
    let rest_of_header = read_u32(&data[4..8]);
    let payload = &data[8..];

    Ok(Icmpv4Packet {
        icmp_type,
        code,
        checksum,
        rest_of_header,
        payload,
    })
}

/// Parse an ICMPv6 packet.
pub fn parse_icmpv6_packet(data: &[u8]) -> Result<Icmpv6Packet<'_>, ParseError> {
    if data.len() < 8 {
        return Err(ParseError::Truncated("icmpv6 header"));
    }
    let icmp_type = data[0];
    let code = data[1];
    let checksum = read_u16(&data[2..4]);
    let rest_of_header = read_u32(&data[4..8]);
    let payload = &data[8..];

    Ok(Icmpv6Packet {
        icmp_type,
        code,
        checksum,
        rest_of_header,
        payload,
    })
}

fn read_u16(bytes: &[u8]) -> u16 {
    let mut array = [0u8; 2];
    array.copy_from_slice(bytes);
    u16::from_be_bytes(array)
}

fn read_u32(bytes: &[u8]) -> u32 {
    let mut array = [0u8; 4];
    array.copy_from_slice(bytes);
    u32::from_be_bytes(array)
}

fn copy_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipv4_tcp_payload() -> Vec<u8> {
        let mut buf = Vec::new();
        // IPv4 header
        buf.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, // version/ihl, dscp/ecn, total length (40 bytes)
            0x12, 0x34, 0x40, 0x00, // identification, flags/fragment offset
            0x40, 0x06, 0x00, 0x00, // ttl, protocol TCP, checksum placeholder
            192, 168, 1, 10, // src
            192, 168, 1, 1, // dst
        ]);
        // No options
        // TCP header (20 bytes)
        buf.extend_from_slice(&[
            0x00, 0x50, 0x01, 0xbb, // src port 80, dst port 443
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0x72, 0x10, // data offset 5, flags SYN, window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent
        ]);
        buf
    }

    #[test]
    fn parse_vlan_ipv4_tcp() {
        let mut payload = build_ipv4_tcp_payload();
        // Ethernet header
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // dst
        frame.extend_from_slice(&[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]); // src
        frame.extend_from_slice(&[0x81, 0x00]); // VLAN ethertype
        frame.extend_from_slice(&[0x80, 0x01, 0x08, 0x00]); // vlan tci (prio 4, id 1), next ethertype IPv4
        frame.append(&mut payload);

        let parsed = parse_ethernet_frame(&frame).expect("parse ethernet");
        assert_eq!(parsed.vlan_stack.len(), 1);
        assert_eq!(parsed.ethertype, EtherType::Ipv4);
        let vlan = &parsed.vlan_stack[0];
        assert_eq!(vlan.vlan_id, 1);
        assert_eq!(vlan.priority, 4);
        assert!(!vlan.drop_eligible);

        let ipv4 = parse_ipv4_packet(parsed.payload).expect("parse ipv4");
        assert_eq!(ipv4.protocol, IpProtocol::Tcp);
        assert_eq!(ipv4.payload.len(), 20);
        let tcp = parse_tcp_segment(ipv4.payload).expect("parse tcp");
        assert_eq!(tcp.source_port, 80);
        assert_eq!(tcp.destination_port, 443);
        assert_eq!(tcp.payload.len(), 0);
    }

    #[test]
    fn reject_ipv4_fragments() {
        let mut payload = build_ipv4_tcp_payload();
        // Set MF flag on IPv4 header (flags/frag offset bytes at 6-7 within IPv4 header).
        payload[6] = 0x20;
        payload[7] = 0x00;
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]); // dst
        frame.extend_from_slice(&[0x00; 6]); // src
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4 ethertype
        frame.append(&mut payload);

        let eth = parse_ethernet_frame(&frame).expect("ethernet");
        let err = parse_ipv4_packet(eth.payload).unwrap_err();
        assert!(matches!(err, ParseError::Invalid(_)));
    }

    #[test]
    fn reject_ipv6_fragments() {
        // Minimal IPv6 header with next_header = 44 (Fragment)
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60; // version 6
        packet[6] = 44; // fragment header
        let err = parse_ipv6_packet(&packet).unwrap_err();
        assert!(matches!(err, ParseError::Invalid(_)));
    }

    #[test]
    fn parse_ipv6_udp_icmp() {
        // IPv6 header
        let mut packet = Vec::new();
        packet.extend_from_slice(&[
            0x60, 0x00, 0x00, 0x00, // version 6, traffic class/flow label
            0x00, 0x14, // payload length 20 bytes
            0x11, // next header UDP
            0x40, // hop limit
        ]);
        packet.extend_from_slice(&[0; 16]); // src
        let mut dst = [0; 16];
        dst[15] = 1;
        packet.extend_from_slice(&dst); // dst

        // UDP payload with ICMPv6 message inside to exercise nested parsing
        packet.extend_from_slice(&[
            0x13, 0x89, 0x13, 0x89, // src/dst ports
            0x00, 0x14, // length 20
            0x00, 0x00, // checksum
        ]);
        packet.extend_from_slice(&[
            128, 0, 0, 0, // ICMPv6 echo request type/code/checksum placeholder
            0x00, 0x01, 0x00, 0x02, // identifier/sequence
        ]);
        packet.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload

        let ipv6 = parse_ipv6_packet(&packet).expect("parse ipv6");
        assert_eq!(ipv6.next_header, IpProtocol::Udp);
        let udp = parse_udp_datagram(ipv6.payload).expect("parse udp");
        let icmp6 = parse_icmpv6_packet(udp.payload).expect("parse icmpv6");
        assert_eq!(icmp6.icmp_type, 128);
        assert_eq!(icmp6.payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn detects_truncated_headers() {
        let frame = [0u8; 10];
        assert!(matches!(
            parse_ethernet_frame(&frame),
            Err(ParseError::Truncated(_))
        ));

        let ipv4 = [0x45u8; 10];
        assert!(matches!(
            parse_ipv4_packet(&ipv4),
            Err(ParseError::Truncated(_))
        ));

        let udp = [0u8; 6];
        assert!(matches!(
            parse_udp_datagram(&udp),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn rejects_invalid_ipv4_headers() {
        let mut ipv4 = [0u8; 20];
        ipv4[0] = 0x41; // version 4, ihl=1 (invalid < 5)
        assert!(matches!(
            parse_ipv4_packet(&ipv4),
            Err(ParseError::Invalid(_))
        ));

        let mut ipv4_len = [0u8; 20];
        ipv4_len[0] = 0x45;
        // total length smaller than header
        ipv4_len[2] = 0x00;
        ipv4_len[3] = 0x10;
        assert!(matches!(
            parse_ipv4_packet(&ipv4_len),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_invalid_ipv6_version() {
        let mut ipv6 = [0u8; 40];
        ipv6[0] = 0x40; // version 4
        assert!(matches!(
            parse_ipv6_packet(&ipv6),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_udp_length_too_small() {
        let udp = [0x00, 0x50, 0x00, 0x50, 0x00, 0x07, 0x00, 0x00]; // len=7 (<8)
        assert!(matches!(
            parse_udp_datagram(&udp),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn truncated_vlan_tag_is_error() {
        // Ethernet header + VLAN ethertype but only 2 bytes tag
        let mut frame = vec![0u8; 14];
        frame[12] = 0x81;
        frame[13] = 0x00;
        frame.extend_from_slice(&[0x12, 0x34]); // incomplete VLAN tag (needs 4 bytes)
        assert!(matches!(
            parse_ethernet_frame(&frame),
            Err(ParseError::Truncated(_))
        ));
    }

    #[test]
    fn short_icmp_headers_fail() {
        let icmpv4 = [0u8; 6];
        assert!(matches!(
            parse_icmpv4_packet(&icmpv4),
            Err(ParseError::Truncated(_))
        ));
        let icmpv6 = [0u8; 6];
        assert!(matches!(
            parse_icmpv6_packet(&icmpv6),
            Err(ParseError::Truncated(_))
        ));
    }
}
