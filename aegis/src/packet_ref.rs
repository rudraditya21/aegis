use aegis_core::{ApplicationType, Direction, PacketMetadata, TlsMetadata};
use dataplane::FrameView;
use packet_parser::{
    EtherType, IpProtocol, ParseError, parse_ethernet_frame, parse_ipv4_packet, parse_ipv6_packet,
    parse_tcp_segment, parse_udp_datagram,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
