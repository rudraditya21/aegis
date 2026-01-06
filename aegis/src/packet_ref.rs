use aegis_core::{ApplicationType, Direction, PacketMetadata, TlsMetadata};
use dataplane::FrameView;
use packet_parser::{
    EtherType, IpProtocol, ParseError, parse_ethernet_frame, parse_ipv4_packet, parse_ipv6_packet,
    parse_tcp_segment, parse_udp_datagram,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::SystemTime;
#[derive(Debug, Clone, Copy)]
pub struct FrameRef<'a> {
    bytes: &'a [u8],
}

impl<'a> FrameRef<'a> {
    pub fn from_view<F: FrameView + ?Sized>(frame: &'a F) -> Self {
        FrameRef {
            bytes: frame.bytes(),
        }
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

#[derive(Debug, Clone)]
pub struct SharedFrame {
    bytes: Arc<[u8]>,
    timestamp: Option<SystemTime>,
}

impl SharedFrame {
    pub fn from_view<F: FrameView + ?Sized>(frame: &F) -> Self {
        SharedFrame {
            bytes: Arc::from(frame.bytes()),
            timestamp: frame.timestamp(),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn timestamp(&self) -> Option<SystemTime> {
        self.timestamp
    }
}

impl FrameView for SharedFrame {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn timestamp(&self) -> Option<SystemTime> {
        self.timestamp
    }
}

#[derive(Debug, Clone)]
pub struct PacketRef<'a> {
    pub direction: Direction,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: IpProtocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub seq_number: Option<u32>,
    pub tcp_flags: Option<u16>,
    pub application: ApplicationType,
    pub payload: &'a [u8],
    pub tls: Option<TlsMetadata>,
}

impl<'a> PacketRef<'a> {
    pub fn parse(bytes: &'a [u8], direction: Direction) -> Result<Self, ParseError> {
        let eth = parse_ethernet_frame(bytes)?;
        match eth.ethertype {
            EtherType::Ipv4 => {
                let ip = parse_ipv4_packet(eth.payload)?;
                let src_ip = IpAddr::V4(Ipv4Addr::from(ip.source));
                let dst_ip = IpAddr::V4(Ipv4Addr::from(ip.destination));
                let (src_port, dst_port, tcp_flags, app, tls_meta, payload, seq) =
                    match ip.protocol {
                        IpProtocol::Tcp => {
                            let tcp = parse_tcp_segment(ip.payload)?;
                            let payload = tcp.payload;
                            (
                                Some(tcp.source_port),
                                Some(tcp.destination_port),
                                Some(tcp.flags),
                                crate::detect_application(
                                    IpProtocol::Tcp,
                                    tcp.source_port,
                                    tcp.destination_port,
                                    payload,
                                ),
                                crate::parse_tls_metadata(payload),
                                payload,
                                Some(tcp.sequence_number),
                            )
                        }
                        IpProtocol::Udp => {
                            let udp = parse_udp_datagram(ip.payload)?;
                            let payload = udp.payload;
                            (
                                Some(udp.source_port),
                                Some(udp.destination_port),
                                None,
                                crate::detect_application(
                                    IpProtocol::Udp,
                                    udp.source_port,
                                    udp.destination_port,
                                    payload,
                                ),
                                None,
                                payload,
                                None,
                            )
                        }
                        _ => (
                            None,
                            None,
                            None,
                            ApplicationType::Unknown,
                            None,
                            &[][..],
                            None,
                        ),
                    };
                Ok(PacketRef {
                    direction,
                    src_ip,
                    dst_ip,
                    protocol: ip.protocol,
                    src_port,
                    dst_port,
                    seq_number: seq,
                    tcp_flags,
                    application: app,
                    payload,
                    tls: tls_meta,
                })
            }
            EtherType::Ipv6 => {
                let ip = parse_ipv6_packet(eth.payload)?;
                let src_ip = IpAddr::V6(Ipv6Addr::from(ip.source));
                let dst_ip = IpAddr::V6(Ipv6Addr::from(ip.destination));
                let (src_port, dst_port, tcp_flags, app, tls_meta, payload, seq) =
                    match ip.next_header {
                        IpProtocol::Tcp => {
                            let tcp = parse_tcp_segment(ip.payload)?;
                            let payload = tcp.payload;
                            (
                                Some(tcp.source_port),
                                Some(tcp.destination_port),
                                Some(tcp.flags),
                                crate::detect_application(
                                    IpProtocol::Tcp,
                                    tcp.source_port,
                                    tcp.destination_port,
                                    payload,
                                ),
                                crate::parse_tls_metadata(payload),
                                payload,
                                Some(tcp.sequence_number),
                            )
                        }
                        IpProtocol::Udp => {
                            let udp = parse_udp_datagram(ip.payload)?;
                            let payload = udp.payload;
                            (
                                Some(udp.source_port),
                                Some(udp.destination_port),
                                None,
                                crate::detect_application(
                                    IpProtocol::Udp,
                                    udp.source_port,
                                    udp.destination_port,
                                    payload,
                                ),
                                None,
                                payload,
                                None,
                            )
                        }
                        _ => (
                            None,
                            None,
                            None,
                            ApplicationType::Unknown,
                            None,
                            &[][..],
                            None,
                        ),
                    };
                Ok(PacketRef {
                    direction,
                    src_ip,
                    dst_ip,
                    protocol: ip.next_header,
                    src_port,
                    dst_port,
                    seq_number: seq,
                    tcp_flags,
                    application: app,
                    payload,
                    tls: tls_meta,
                })
            }
            _ => Err(ParseError::Unsupported("non-ip ethertype")),
        }
    }

    pub fn materialize(self, capture_payload: bool) -> PacketMetadata {
        let payload = if capture_payload && !self.payload.is_empty() {
            self.payload.to_vec()
        } else {
            Vec::new()
        };
        PacketMetadata {
            direction: self.direction,
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            protocol: self.protocol,
            src_port: self.src_port,
            dst_port: self.dst_port,
            seq_number: self.seq_number,
            tcp_flags: self.tcp_flags,
            application: self.application,
            payload,
            signatures: Vec::new(),
            user: None,
            geo: None,
            tls: self.tls,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dataplane::FrameView;

    struct DummyFrame<'a> {
        data: &'a [u8],
        timestamp: Option<std::time::SystemTime>,
    }

    impl FrameView for DummyFrame<'_> {
        fn bytes(&self) -> &[u8] {
            self.data
        }

        fn timestamp(&self) -> Option<std::time::SystemTime> {
            self.timestamp
        }
    }

    fn build_ipv4_udp_frame(payload: &[u8], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0u8; 6]); // dst mac
        frame.extend_from_slice(&[1u8; 6]); // src mac
        frame.extend_from_slice(&[0x08, 0x00]); // ethertype ipv4

        let total_len = 20 + 8 + payload.len();
        let mut ipv4 = [0u8; 20];
        ipv4[0] = 0x45; // v4, ihl=5
        ipv4[1] = 0x00; // dscp/ecn
        ipv4[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        ipv4[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
        ipv4[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags (DF)
        ipv4[8] = 64; // ttl
        ipv4[9] = 17; // udp
        ipv4[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum
        ipv4[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ipv4[16..20].copy_from_slice(&[10, 0, 0, 2]);
        frame.extend_from_slice(&ipv4);

        let udp_len = 8 + payload.len();
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&src_port.to_be_bytes());
        udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp[6..8].copy_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&udp);
        frame.extend_from_slice(payload);
        frame
    }

    fn build_ipv6_tcp_frame(payload: &[u8], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0u8; 6]); // dst mac
        frame.extend_from_slice(&[1u8; 6]); // src mac
        frame.extend_from_slice(&[0x86, 0xDD]); // ethertype ipv6

        let payload_len = 20 + payload.len();
        let mut ipv6 = [0u8; 40];
        ipv6[0] = 0x60; // version 6
        ipv6[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        ipv6[6] = 6; // tcp
        ipv6[7] = 64; // hop limit
        ipv6[8..24].copy_from_slice(&[0u8; 16]); // src
        ipv6[24..40].copy_from_slice(&[1u8; 16]); // dst
        frame.extend_from_slice(&ipv6);

        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&1u32.to_be_bytes()); // seq
        tcp[8..12].copy_from_slice(&0u32.to_be_bytes()); // ack
        tcp[12] = 0x50; // data offset=5
        tcp[13] = 0x18; // psh+ack
        tcp[14..16].copy_from_slice(&1024u16.to_be_bytes()); // window
        tcp[16..18].copy_from_slice(&0u16.to_be_bytes()); // checksum
        tcp[18..20].copy_from_slice(&0u16.to_be_bytes()); // urg ptr
        frame.extend_from_slice(&tcp);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn parse_ipv4_udp_packet_ref() {
        let mut dns = [0u8; 12];
        dns[4] = 0;
        dns[5] = 1; // qdcount
        dns[6] = 0;
        dns[7] = 0; // ancount
        let frame = build_ipv4_udp_frame(&dns, 5353, 53);
        let packet = PacketRef::parse(&frame, Direction::Ingress).unwrap();
        assert_eq!(packet.protocol, IpProtocol::Udp);
        assert_eq!(packet.src_port, Some(5353));
        assert_eq!(packet.dst_port, Some(53));
        assert_eq!(packet.payload, dns);
        assert_eq!(packet.application, ApplicationType::Dns);
    }

    #[test]
    fn parse_ipv6_tcp_packet_ref() {
        let payload = b"GET / HTTP/1.1\r\n";
        let frame = build_ipv6_tcp_frame(payload, 12345, 80);
        let packet = PacketRef::parse(&frame, Direction::Ingress).unwrap();
        assert_eq!(packet.protocol, IpProtocol::Tcp);
        assert_eq!(packet.src_port, Some(12345));
        assert_eq!(packet.dst_port, Some(80));
        assert_eq!(packet.payload, payload);
        assert_eq!(packet.application, ApplicationType::Http);
    }

    #[test]
    fn materialize_payload_toggle() {
        let payload = b"payload";
        let frame = build_ipv4_udp_frame(payload, 1000, 2000);
        let packet = PacketRef::parse(&frame, Direction::Ingress).unwrap();
        let meta_no = packet.clone().materialize(false);
        let meta_yes = packet.materialize(true);
        assert!(meta_no.payload.is_empty());
        assert_eq!(meta_yes.payload, payload);
    }

    #[test]
    fn frameref_from_view() {
        let data = [1u8, 2, 3, 4];
        let frame = DummyFrame {
            data: &data,
            timestamp: None,
        };
        let view = FrameRef::from_view(&frame);
        assert_eq!(view.bytes(), &data);
    }

    #[test]
    fn shared_frame_from_view() {
        let data = [9u8, 8, 7, 6];
        let ts = std::time::SystemTime::UNIX_EPOCH;
        let frame = DummyFrame {
            data: &data,
            timestamp: Some(ts),
        };
        let shared = SharedFrame::from_view(&frame);
        assert_eq!(shared.bytes(), &data);
        assert_eq!(shared.timestamp(), Some(ts));
    }
}
