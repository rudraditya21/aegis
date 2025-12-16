#![forbid(unsafe_code)]

use crate::ApplicationType;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use packet_parser::IpProtocol;

#[derive(Debug, Clone)]
pub struct SignatureRule {
    pub application: ApplicationType,
    pub patterns: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct SignatureEngine {
    http: AhoCorasick,
    dns: AhoCorasick,
    file: AhoCorasick,
    exploits: AhoCorasick,
    exploit_labels: Vec<&'static str>,
}

impl SignatureEngine {
    pub fn with_default_rules() -> Self {
        let http_patterns = vec![
            b"GET ".to_vec(),
            b"POST ".to_vec(),
            b"HEAD ".to_vec(),
            b"PUT ".to_vec(),
            b"DELETE ".to_vec(),
            b"OPTIONS ".to_vec(),
            b"PATCH ".to_vec(),
            b"HTTP/1.1".to_vec(),
            b"Host:".to_vec(),
        ];
        let dns_patterns = vec![
            vec![0x01, 0x00, 0x00, 0x01],
            b"DNS".to_vec(),
        ];
        let file_patterns = vec![
            b"FTP ".to_vec(),
            b"STOR ".to_vec(),
            b"RETR ".to_vec(),
            b"SFTP".to_vec(),
            b"PK\x03\x04".to_vec(),
            b"%PDF-".to_vec(),
        ];

        let builder = || {
            let mut b = AhoCorasickBuilder::new();
            b.ascii_case_insensitive(true);
            b
        };
        let exploit_patterns: Vec<(&'static str, Vec<u8>)> = vec![
            ("sqli-or-1-eq-1", b"' OR 1=1".to_vec()),
            ("sqli-union-select", b"UNION SELECT".to_vec()),
            ("sqli-sleep", b"SLEEP(".to_vec()),
            ("xss-script-tag", b"<script>".to_vec()),
            ("xss-img-onerror", b"onerror=".to_vec()),
            ("path-traversal", b"../".to_vec()),
            ("path-traversal-win", b"..\\".to_vec()),
        ];
        let exploit_labels: Vec<&'static str> = exploit_patterns.iter().map(|(n, _)| *n).collect();
        SignatureEngine {
            http: builder().build(http_patterns).expect("http patterns"),
            dns: builder().build(dns_patterns).expect("dns patterns"),
            file: builder().build(file_patterns).expect("file patterns"),
            exploits: builder()
                .build(exploit_patterns.iter().map(|(_, p)| p).collect::<Vec<_>>())
                .expect("exploit patterns"),
            exploit_labels,
        }
    }

    pub fn detect_application(
        &self,
        proto: IpProtocol,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> ApplicationType {
        if payload.is_empty() {
            return ApplicationType::Unknown;
        }

        match proto {
            IpProtocol::Tcp => {
                if self.is_tls_client_hello(payload) {
                    return ApplicationType::TlsClientHello;
                }
                if self.http.is_match(payload) || self.looks_like_http(payload) {
                    return ApplicationType::Http;
                }
                if self.file.is_match(payload) {
                    return ApplicationType::FileTransfer;
                }
                if (src_port == 53 || dst_port == 53)
                    && (self.dns.is_match(payload) || self.looks_like_dns(payload))
                {
                    return ApplicationType::Dns;
                }
            }
            IpProtocol::Udp => {
                if (src_port == 53 || dst_port == 53)
                    && (self.dns.is_match(payload) || self.looks_like_dns(payload))
                {
                    return ApplicationType::Dns;
                }
                if self.http.is_match(payload) && self.looks_like_http(payload) {
                    return ApplicationType::Http;
                }
            }
            _ => {}
        }

        ApplicationType::Unknown
    }

    fn looks_like_http(&self, payload: &[u8]) -> bool {
        const METHODS: &[&[u8]] = &[
            b"GET ",
            b"POST ",
            b"HEAD ",
            b"PUT ",
            b"DELETE ",
            b"PATCH ",
            b"OPTIONS ",
        ];
        METHODS
            .iter()
            .any(|m| payload.len() >= m.len() && payload[..m.len()].eq_ignore_ascii_case(m))
            || payload.windows(5).any(|w| w.eq_ignore_ascii_case(b"HTTP/"))
    }

    fn looks_like_dns(&self, payload: &[u8]) -> bool {
        if payload.len() < 12 {
            return false;
        }
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);
        qdcount > 0 && ancount == 0
    }

    fn is_tls_client_hello(&self, payload: &[u8]) -> bool {
        if payload.len() < 6 {
            return false;
        }
        if payload[0] != 0x16 || payload[1] != 0x03 {
            return false;
        }
        if payload.len() > 5 && payload[5] == 0x01 {
            return true;
        }
        false
    }

    pub fn scan_exploits(&self, payload: &[u8]) -> Vec<String> {
        let mut hits = Vec::new();
        for mat in self.exploits.find_iter(payload) {
            if let Some(label) = self.exploit_labels.get(mat.pattern().as_usize())
                && !hits.iter().any(|h: &String| h == label)
            {
                hits.push((*label).to_string());
            }
        }
        hits
    }
}
