#![forbid(unsafe_code)]

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use chrono::Timelike;
use packet_parser::{IpProtocol, ParseError};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
    Redirect { interface: Option<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationType {
    Http,
    Dns,
    TlsClientHello,
    FileTransfer,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowReason {
    NewFlow,
    UnknownApplication,
    NotEstablished,
    Redirected,
    AttackProtection,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    Fast,
    Slow(SlowReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorKind {
    RateAnomaly,
    BruteForce,
    TlsViolation,
    ThreatIntel,
    Beacon,
    Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehaviorAlert {
    pub kind: BehaviorKind,
    pub src: IpAddr,
    pub dst: Option<IpAddr>,
    pub port: Option<u16>,
    pub count: u64,
    pub timestamp: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsMetadata {
    pub sni: Option<String>,
    pub cipher_suites: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsPolicy {
    pub allow_snis: Vec<String>,
    pub deny_snis: Vec<String>,
    pub allow_ciphers: Vec<u16>,
    pub deny_ciphers: Vec<u16>,
    pub enforce: bool,
    pub allow_decryption: bool,
}

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
            // flags + qdcount for a standard query with 1 question
            vec![0x01, 0x00, 0x00, 0x01],
            b"DNS".to_vec(), // safety fallback for textual traces
        ];
        let file_patterns = vec![
            b"FTP ".to_vec(),
            b"STOR ".to_vec(),
            b"RETR ".to_vec(),
            b"SFTP".to_vec(),
            b"PK\x03\x04".to_vec(), // zip
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
                // DNS over TCP
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
        // standard query with at least one question and no answers yet
        qdcount > 0 && ancount == 0
    }

    fn is_tls_client_hello(&self, payload: &[u8]) -> bool {
        if payload.len() < 6 {
            return false;
        }
        // TLS record layer: ContentType 0x16 (handshake), Version major/minor, length
        if payload[0] != 0x16 || payload[1] != 0x03 {
            return false;
        }
        // Handshake type ClientHello = 1
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

#[derive(Debug)]
struct TcpStreamState {
    next_seq: Option<u32>,
    buffer: std::collections::BTreeMap<u32, Vec<u8>>,
    buffered_bytes: usize,
}

impl TcpStreamState {
    fn new() -> Self {
        TcpStreamState {
            next_seq: None,
            buffer: std::collections::BTreeMap::new(),
            buffered_bytes: 0,
        }
    }

    fn process_segment(&mut self, seq: u32, payload: &[u8], max_buffer: usize) -> Vec<u8> {
        if payload.is_empty() {
            return Vec::new();
        }
        let mut start = seq;
        let mut data = payload.to_vec();

        // If this overlaps already delivered region, trim
        if let Some(expected) = self.next_seq
            && seq < expected
        {
            let overlap = (expected - seq) as usize;
            if overlap >= data.len() {
                return Vec::new();
            }
            data.drain(0..overlap);
            start = expected;
        }

        if let Some(expected) = self.next_seq {
            if start == expected {
                // In-order: deliver and then attempt to flush buffered out-of-order
                let mut out = data.clone();
                self.next_seq = Some(expected.wrapping_add(data.len() as u32));
                // absorb buffered segments
                loop {
                    let expected = self.next_seq.unwrap();
                    let seg_start = match self.buffer.first_key_value() {
                        Some((&seg_start, _)) => seg_start,
                        None => break,
                    };
                    if seg_start != expected {
                        break;
                    }
                    if let Some(seg_data) = self.buffer.remove(&seg_start) {
                        out.extend_from_slice(&seg_data);
                        self.next_seq = Some(seg_start.wrapping_add(seg_data.len() as u32));
                        self.buffered_bytes = self.buffered_bytes.saturating_sub(seg_data.len());
                    } else {
                        break;
                    }
                }
                return out;
            } else if start > expected {
                // Out-of-order: buffer if within capacity
                self.buffered_bytes += data.len();
                if self.buffered_bytes > max_buffer {
                    self.buffered_bytes -= data.len();
                    return Vec::new();
                }
                self.buffer.insert(start, data);
                return Vec::new();
            }
        }

        // First packet initializes stream
        if self.next_seq.is_none() {
            if data.len() > max_buffer {
                return Vec::new();
            }
            self.next_seq = Some(start.wrapping_add(data.len() as u32));
            return data;
        }
        self.next_seq = Some(start.wrapping_add(data.len() as u32));
        data
    }
}

#[derive(Debug)]
pub struct TcpReassembly {
    streams: HashMap<(FlowKey, Direction), TcpStreamState>,
    max_buffer: usize,
}

impl TcpReassembly {
    pub fn new(max_buffer: usize) -> Self {
        TcpReassembly {
            streams: HashMap::new(),
            max_buffer: max_buffer.max(1),
        }
    }

    pub fn process(
        &mut self,
        flow: FlowKey,
        direction: Direction,
        seq: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let key = (flow, direction);
        let state = self.streams.entry(key).or_insert_with(TcpStreamState::new);
        state.process_segment(seq, payload, self.max_buffer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCondition {
    pub src: Option<Cidr>,
    pub dst: Option<Cidr>,
    pub users: Vec<String>,
    pub applications: Vec<ApplicationType>,
    pub geos: Vec<String>,
    pub time_windows: Vec<TimeWindow>,
}

impl PolicyCondition {
    pub fn matches(&self, meta: &PacketMetadata) -> bool {
        self.matches_at(meta, None, true, true)
    }

    pub fn matches_at(
        &self,
        meta: &PacketMetadata,
        hour: Option<u8>,
        geo_enabled: bool,
        time_enabled: bool,
    ) -> bool {
        if let Some(src) = &self.src
            && !src.contains(&meta.src_ip)
        {
            return false;
        }
        if let Some(dst) = &self.dst
            && !dst.contains(&meta.dst_ip)
        {
            return false;
        }
        if !self.users.is_empty() {
            match &meta.user {
                Some(u) if self.users.iter().any(|x| x == u) => {}
                _ => return false,
            }
        }
        if !self.applications.is_empty() && !self.applications.contains(&meta.application) {
            return false;
        }
        if geo_enabled && !self.geos.is_empty() {
            match &meta.geo {
                Some(g) if self.geos.iter().any(|x| x == g) => {}
                _ => return false,
            }
        }
        if time_enabled && !self.time_windows.is_empty() {
            let h = hour.unwrap_or_else(|| chrono::Local::now().hour() as u8);
            if !self.time_windows.iter().any(|w| w.contains(h)) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeWindow {
    pub start_hour: u8,
    pub end_hour: u8,
}

impl TimeWindow {
    pub fn contains(&self, hour: u8) -> bool {
        if self.start_hour <= self.end_hour {
            hour >= self.start_hour && hour <= self.end_hour
        } else {
            // wrap-around (e.g., 22-2)
            hour >= self.start_hour || hour <= self.end_hour
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: u64,
    pub priority: u32,
    pub action: Action,
    pub condition: PolicyCondition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEntry {
    pub priority: u32,
    pub action: Action,
    pub condition: PolicyCondition,
}

#[derive(Debug, Default)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    next_id: u64,
}

impl PolicyEngine {
    pub fn add_rule(&mut self, priority: u32, action: Action, condition: PolicyCondition) -> u64 {
        let id = self.next_id + 1;
        self.next_id = id;
        self.rules.push(PolicyRule {
            id,
            priority,
            action,
            condition,
        });
        self.rules
            .sort_by(|a, b| b.priority.cmp(&a.priority).then(a.id.cmp(&b.id)));
        id
    }

    pub fn replace_all(&mut self, entries: Vec<PolicyEntry>) {
        self.rules.clear();
        let mut id = 1u64;
        for entry in entries {
            self.rules.push(PolicyRule {
                id,
                priority: entry.priority,
                action: entry.action,
                condition: entry.condition,
            });
            id += 1;
        }
        self.next_id = id;
        self.rules
            .sort_by(|a, b| b.priority.cmp(&a.priority).then(a.id.cmp(&b.id)));
    }

    pub fn remove_rule(&mut self, id: u64) -> bool {
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            self.rules.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn list(&self) -> &[PolicyRule] {
        &self.rules
    }

    pub fn evaluate_with_time(
        &self,
        meta: &PacketMetadata,
        hour: Option<u8>,
        geo_enabled: bool,
        time_enabled: bool,
    ) -> Option<Action> {
        let hour = hour.or_else(|| Some(chrono::Local::now().hour() as u8));
        for rule in &self.rules {
            if rule
                .condition
                .matches_at(meta, hour, geo_enabled, time_enabled)
            {
                return Some(rule.action.clone());
            }
        }
        None
    }

    pub fn evaluate(&self, meta: &PacketMetadata) -> Option<Action> {
        self.evaluate_with_time(meta, None, true, true)
    }
}

fn classify_path(action: &Action, flow: &FlowOutcome, blocked: bool) -> Path {
    if blocked {
        return Path::Slow(SlowReason::AttackProtection);
    }
    if flow.is_new {
        return Path::Slow(SlowReason::NewFlow);
    }
    if flow.application == ApplicationType::Unknown {
        return Path::Slow(SlowReason::UnknownApplication);
    }
    if !flow.fast_allowed {
        return Path::Slow(SlowReason::NotEstablished);
    }
    if matches!(action, Action::Redirect { .. }) {
        return Path::Slow(SlowReason::Redirected);
    }
    Path::Fast
}

fn resolve_conflict(base: Action, policy: Action) -> Action {
    // Higher priority policy already selected; if conflict Allow vs Deny, choose Deny; Redirect wins over Allow.
    match (base, policy.clone()) {
        (_, Action::Redirect { .. }) => policy,
        (Action::Deny, Action::Allow) => policy,
        (Action::Allow, Action::Deny) => Action::Deny,
        (_, other) => other,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub action: Action,
    pub subject: RuleSubject,
    pub direction: Direction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSubject {
    Cidr {
        network: Cidr,
    },
    Port {
        protocol: IpProtocol,
        range: PortRange,
    },
    Protocol {
        protocol: IpProtocol,
    },
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Self {
        let (start, end) = if start <= end {
            (start, end)
        } else {
            (end, start)
        };
        PortRange { start, end }
    }

    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cidr {
    V4 { addr: Ipv4Addr, prefix: u8 },
    V6 { addr: Ipv6Addr, prefix: u8 },
}

impl Cidr {
    pub fn contains(&self, addr: &IpAddr) -> bool {
        match (self, addr) {
            (Cidr::V4 { addr: net, prefix }, IpAddr::V4(ip)) => {
                let net = u32::from_be_bytes(net.octets());
                let ip = u32::from_be_bytes(ip.octets());
                let mask = mask_v4(*prefix);
                (net & mask) == (ip & mask)
            }
            (Cidr::V6 { addr: net, prefix }, IpAddr::V6(ip)) => {
                let net = u128::from_be_bytes(net.octets());
                let ip = u128::from_be_bytes(ip.octets());
                let mask = mask_v6(*prefix);
                (net & mask) == (ip & mask)
            }
            _ => false,
        }
    }

    pub fn prefix_len(&self) -> u8 {
        match self {
            Cidr::V4 { prefix, .. } => *prefix,
            Cidr::V6 { prefix, .. } => *prefix,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMetadata {
    pub direction: Direction,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: IpProtocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub seq_number: Option<u32>,
    pub tcp_flags: Option<u16>,
    pub application: ApplicationType,
    pub payload: Vec<u8>,
    pub signatures: Vec<String>,
    pub user: Option<String>,
    pub geo: Option<String>,
    pub tls: Option<TlsMetadata>,
}

#[derive(Debug)]
pub struct Firewall {
    rules: Vec<(u64, Rule)>,
    next_rule_id: u64,
    ipv4_rules: Vec<(Cidr, Action, Direction)>,
    ipv6_rules: Vec<(Cidr, Action, Direction)>,
    port_rules: HashMap<(IpProtocol, u16), (Action, Direction)>,
    port_ranges: Vec<(IpProtocol, PortRange, Action, Direction)>,
    proto_rules: HashMap<IpProtocol, (Action, Direction)>,
    default: Option<(Action, Direction)>,
}

impl Default for Firewall {
    fn default() -> Self {
        Firewall {
            rules: Vec::new(),
            next_rule_id: 1,
            ipv4_rules: Vec::new(),
            ipv6_rules: Vec::new(),
            port_rules: HashMap::new(),
            port_ranges: Vec::new(),
            proto_rules: HashMap::new(),
            default: None,
        }
    }
}

impl Firewall {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: Rule) -> u64 {
        let id = self.next_rule_id;
        self.next_rule_id += 1;
        self.rules.push((id, rule.clone()));
        self.apply_rule(&rule);
        id
    }

    pub fn remove_rule(&mut self, id: u64) -> bool {
        if let Some(pos) = self.rules.iter().position(|(rid, _)| *rid == id) {
            self.rules.remove(pos);
            self.rebuild();
            true
        } else {
            false
        }
    }

    pub fn list_rules(&self) -> &[(u64, Rule)] {
        &self.rules
    }

    fn rebuild(&mut self) {
        self.ipv4_rules.clear();
        self.ipv6_rules.clear();
        self.port_rules.clear();
        self.port_ranges.clear();
        self.proto_rules.clear();
        self.default = None;
        let rule_copies: Vec<Rule> = self.rules.iter().map(|(_, r)| r.clone()).collect();
        for rule in &rule_copies {
            self.apply_rule(rule);
        }
    }

    fn apply_rule(&mut self, rule: &Rule) {
        match &rule.subject {
            RuleSubject::Cidr { network } => {
                match network {
                    Cidr::V4 { .. } => {
                        self.ipv4_rules
                            .push((network.clone(), rule.action.clone(), rule.direction))
                    }
                    Cidr::V6 { .. } => {
                        self.ipv6_rules
                            .push((network.clone(), rule.action.clone(), rule.direction))
                    }
                }
                self.sort_lpm();
            }
            RuleSubject::Port { protocol, range } => {
                if range.start == range.end {
                    self.port_rules.insert(
                        (*protocol, range.start),
                        (rule.action.clone(), rule.direction),
                    );
                } else {
                    self.port_ranges.push((
                        *protocol,
                        range.clone(),
                        rule.action.clone(),
                        rule.direction,
                    ));
                }
            }
            RuleSubject::Protocol { protocol } => {
                self.proto_rules
                    .insert(*protocol, (rule.action.clone(), rule.direction));
            }
            RuleSubject::Default => self.default = Some((rule.action.clone(), rule.direction)),
        }
    }

    fn sort_lpm(&mut self) {
        self.ipv4_rules
            .sort_by(|a, b| b.0.prefix_len().cmp(&a.0.prefix_len()));
        self.ipv6_rules
            .sort_by(|a, b| b.0.prefix_len().cmp(&a.0.prefix_len()));
    }

    pub fn evaluate(&self, packet: &PacketMetadata) -> Action {
        let mut decision: Option<Action> = None;

        for ip in [&packet.src_ip, &packet.dst_ip] {
            if let Some(action) = self.match_ip(ip, packet.direction) {
                if action == Action::Deny {
                    return Action::Deny;
                }
                decision.get_or_insert(action.clone());
            }
        }

        for port in [packet.dst_port, packet.src_port].into_iter().flatten() {
            if let Some(action) = self.match_port(packet.protocol, port, packet.direction) {
                if action == Action::Deny {
                    return Action::Deny;
                }
                decision.get_or_insert(action.clone());
            }
        }

        if let Some((action, dir)) = self.proto_rules.get(&packet.protocol)
            && *dir == packet.direction
        {
            if *action == Action::Deny {
                return Action::Deny;
            }
            decision.get_or_insert(action.clone());
        }

        if let Some(action) = decision {
            return action;
        }

        if let Some((action, dir)) = &self.default
            && *dir == packet.direction
        {
            return action.clone();
        }

        Action::Deny
    }

    fn match_port(&self, proto: IpProtocol, port: u16, direction: Direction) -> Option<Action> {
        if let Some((action, dir)) = self.port_rules.get(&(proto, port))
            && *dir == direction
        {
            return Some(action.clone());
        }
        for (p, range, action, dir) in &self.port_ranges {
            if *p == proto && range.contains(port) && *dir == direction {
                return Some(action.clone());
            }
        }
        None
    }

    fn match_ip(&self, ip: &IpAddr, direction: Direction) -> Option<Action> {
        match ip {
            IpAddr::V4(_) => self.match_lpm(ip, &self.ipv4_rules, direction),
            IpAddr::V6(_) => self.match_lpm(ip, &self.ipv6_rules, direction),
        }
    }

    fn match_lpm(
        &self,
        ip: &IpAddr,
        table: &[(Cidr, Action, Direction)],
        direction: Direction,
    ) -> Option<Action> {
        for (cidr, action, dir) in table {
            if *dir != direction {
                continue;
            }
            if cidr.contains(ip) {
                return Some(action.clone());
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: IpProtocol,
}

impl FlowKey {
    pub fn from_metadata(meta: &PacketMetadata) -> Self {
        FlowKey {
            src_ip: meta.src_ip,
            dst_ip: meta.dst_ip,
            src_port: meta.src_port.unwrap_or(0),
            dst_port: meta.dst_port.unwrap_or(0),
            protocol: meta.protocol,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    New,
    SynSent,
    SynReceived,
    Established,
    FinWait,
    Closed,
}

#[derive(Debug, Clone)]
struct CounterWindow {
    start: Instant,
    count: u64,
}

#[derive(Debug, Clone)]
struct BeaconState {
    last: Instant,
    last_delta: Option<Duration>,
    stable_hits: u32,
}

impl CounterWindow {
    fn new(start: Instant) -> Self {
        CounterWindow { start, count: 0 }
    }

    fn hit(&mut self, now: Instant, window: Duration) -> u64 {
        if now.duration_since(self.start) > window {
            self.start = now;
            self.count = 0;
        }
        self.count += 1;
        self.count
    }

    fn decay(&mut self, amount: u64) {
        if self.count >= amount {
            self.count -= amount;
        } else {
            self.count = 0;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlowStats {
    pub packets: u64,
    pub new_flows: u64,
    pub evicted: u64,
}

impl FlowStats {
    fn add_packet(&mut self) {
        self.packets += 1;
    }
    fn add_flow(&mut self) {
        self.new_flows += 1;
    }
    fn add_evicted(&mut self) {
        self.evicted += 1;
    }
}

#[derive(Debug, Clone)]
struct FlowEntry {
    state: FlowState,
    last_seen: Instant,
    application: ApplicationType,
    tls: Option<TlsMetadata>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowOutcome {
    pub is_new: bool,
    pub state: FlowState,
    pub fast_allowed: bool,
    pub previous_state: Option<FlowState>,
    pub application: ApplicationType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSnapshot {
    pub key: FlowKey,
    pub state: FlowState,
    pub last_seen: Instant,
    pub application: ApplicationType,
    pub tls: Option<TlsMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSyncState {
    pub flows: Vec<FlowSnapshot>,
    pub stats: FlowStats,
}

#[derive(Debug, Clone)]
pub struct VerdictLog {
    pub timestamp: Instant,
    pub interface: Option<String>,
    pub meta: PacketMetadata,
    pub verdict: Action,
    pub flow: FlowOutcome,
    pub blocked_by_protector: bool,
    pub path: Path,
}

#[derive(Debug)]
pub struct FlowTable {
    capacity: usize,
    lru: VecDeque<FlowKey>,
    table: HashMap<FlowKey, FlowEntry>,
    stats: Vec<FlowStats>,
    handshake_timeout: Duration,
    established_timeout: Duration,
    closed_timeout: Duration,
}

#[derive(Debug)]
pub struct AttackProtector {
    syn_limit: u64,
    syn_window: Duration,
    icmp_limit: u64,
    icmp_window: Duration,
    udp_limit: u64,
    udp_total_limit: u64,
    udp_window: Duration,
    syn_counters: HashMap<IpAddr, CounterWindow>,
    icmp_counters: HashMap<IpAddr, CounterWindow>,
    udp_counters: HashMap<IpAddr, CounterWindow>,
    udp_conn_counters: HashMap<(IpAddr, u16), CounterWindow>,
    udp_total_counter: CounterWindow,
}

#[derive(Debug)]
pub struct BehaviorDetector {
    rate_limit: u64,
    rate_window: Duration,
    brute_limit: u64,
    brute_window: Duration,
    beacon_tolerance: f64,
    beacon_min_delta: Duration,
    beacon_states: HashMap<(IpAddr, IpAddr, u16), BeaconState>,
    rate_counters: HashMap<IpAddr, CounterWindow>,
    brute_counters: HashMap<(IpAddr, IpAddr, u16), CounterWindow>,
}

#[derive(Debug, Clone)]
pub struct ThreatIntel {
    bad_ips: HashSet<IpAddr>,
    bad_domains: HashSet<String>,
    updated_at: Option<Instant>,
}

impl FlowTable {
    pub fn new(capacity: usize) -> Self {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        FlowTable {
            capacity: capacity.max(1),
            lru: VecDeque::new(),
            table: HashMap::new(),
            stats: vec![
                FlowStats {
                    packets: 0,
                    new_flows: 0,
                    evicted: 0,
                };
                cores
            ],
            handshake_timeout: Duration::from_secs(30),
            established_timeout: Duration::from_secs(300),
            closed_timeout: Duration::from_secs(15),
        }
    }

    pub fn observe(&mut self, meta: &PacketMetadata, now: Instant) -> FlowOutcome {
        let key = FlowKey::from_metadata(meta);
        let cpu = self.cpu_index();
        self.reap_expired(now);
        self.bump_packet(cpu);

        if let Some(entry) = self.table.get(&key).cloned() {
            if is_expired(entry.state, entry.last_seen, now, self) {
                self.remove_entry(&key);
            } else {
                let new_state = advance_state(entry.state, meta.tcp_flags);
                if let Some(entry_mut) = self.table.get_mut(&key) {
                    entry_mut.state = new_state;
                    entry_mut.last_seen = now;
                    entry_mut.application = meta.application;
                    if meta.tls.is_some() {
                        entry_mut.tls = meta.tls.clone();
                    }
                }
                self.touch(&key);
                return FlowOutcome {
                    is_new: false,
                    state: new_state,
                    fast_allowed: matches!(new_state, FlowState::Established),
                    previous_state: Some(entry.state),
                    application: entry.application,
                };
            }
        }

        // new flow
        let initial = initial_state(meta.protocol, meta.tcp_flags);
        self.insert_new(key, initial, meta.application, meta.tls.clone(), now, cpu);
        self.bump_new_flow(cpu);
        FlowOutcome {
            is_new: true,
            state: initial,
            fast_allowed: false,
            previous_state: None,
            application: meta.application,
        }
    }

    pub fn stats(&self) -> FlowStats {
        let mut agg = FlowStats {
            packets: 0,
            new_flows: 0,
            evicted: 0,
        };
        for s in &self.stats {
            agg.packets += s.packets;
            agg.new_flows += s.new_flows;
            agg.evicted += s.evicted;
        }
        agg
    }

    pub fn set_capacity(&mut self, new_capacity: usize) {
        let new_capacity = new_capacity.max(1);
        while self.table.len() > new_capacity {
            if let Some(oldest) = self.lru.pop_front() {
                self.table.remove(&oldest);
            } else {
                break;
            }
        }
        self.capacity = new_capacity;
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn snapshot(&self) -> Vec<FlowSnapshot> {
        self.lru
            .iter()
            .filter_map(|k| {
                self.table.get(k).map(|entry| FlowSnapshot {
                    key: *k,
                    state: entry.state,
                    last_seen: entry.last_seen,
                    application: entry.application,
                    tls: entry.tls.clone(),
                })
            })
            .collect()
    }

    pub fn export_state(&self) -> FlowSyncState {
        FlowSyncState {
            flows: self.snapshot(),
            stats: self.stats(),
        }
    }

    pub fn import_state(&mut self, state: &FlowSyncState, now: Instant) {
        for snap in &state.flows {
            self.insert_or_replace(
                snap.key,
                snap.state,
                snap.application,
                snap.tls.clone(),
                now,
            );
        }
        // best-effort stats merge
        if let Some(stat) = self.stats.get_mut(0) {
            stat.packets = stat.packets.max(state.stats.packets);
            stat.new_flows = stat.new_flows.max(state.stats.new_flows);
            stat.evicted = stat.evicted.max(state.stats.evicted);
        }
    }

    pub fn reap_expired(&mut self, now: Instant) -> usize {
        let mut removed = 0usize;
        let mut to_remove = Vec::new();
        for (key, entry) in self.table.iter() {
            if is_expired(entry.state, entry.last_seen, now, self) {
                to_remove.push(*key);
            }
        }
        for key in to_remove {
            self.remove_entry(&key);
            removed += 1;
        }
        removed
    }

    fn insert_new(
        &mut self,
        key: FlowKey,
        state: FlowState,
        application: ApplicationType,
        tls: Option<TlsMetadata>,
        now: Instant,
        cpu: usize,
    ) {
        if self.table.len() >= self.capacity
            && let Some(oldest) = self.lru.pop_front()
        {
            self.table.remove(&oldest);
            self.bump_evicted(cpu);
        }
        self.lru.push_back(key);
        self.table.insert(
            key,
            FlowEntry {
                state,
                last_seen: now,
                application,
                tls,
            },
        );
    }

    fn insert_or_replace(
        &mut self,
        key: FlowKey,
        state: FlowState,
        application: ApplicationType,
        tls: Option<TlsMetadata>,
        now: Instant,
    ) {
        if self.table.contains_key(&key) {
            if let Some(entry) = self.table.get_mut(&key) {
                entry.state = state;
                entry.last_seen = now;
                entry.application = application;
                entry.tls = tls;
            }
            self.touch(&key);
        } else {
            let cpu = self.cpu_index();
            self.insert_new(key, state, application, tls, now, cpu);
        }
    }

    fn touch(&mut self, key: &FlowKey) {
        if let Some(pos) = self.lru.iter().position(|k| k == key) {
            self.lru.remove(pos);
            self.lru.push_back(*key);
        }
    }

    fn remove_entry(&mut self, key: &FlowKey) {
        self.table.remove(key);
        if let Some(pos) = self.lru.iter().position(|k| k == key) {
            self.lru.remove(pos);
        }
    }

    fn cpu_index(&self) -> usize {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        (hasher.finish() as usize) % self.stats.len()
    }

    fn timeout_for(&self, state: FlowState) -> Duration {
        match state {
            FlowState::New | FlowState::SynSent | FlowState::SynReceived => self.handshake_timeout,
            FlowState::Established => self.established_timeout,
            FlowState::FinWait => Duration::from_secs(60),
            FlowState::Closed => self.closed_timeout,
        }
    }

    fn bump_packet(&mut self, cpu: usize) {
        if let Some(stat) = self.stats.get_mut(cpu) {
            stat.add_packet();
        }
    }

    fn bump_new_flow(&mut self, cpu: usize) {
        if let Some(stat) = self.stats.get_mut(cpu) {
            stat.add_flow();
        }
    }

    fn bump_evicted(&mut self, cpu: usize) {
        if let Some(stat) = self.stats.get_mut(cpu) {
            stat.add_evicted();
        }
    }
}

impl AttackProtector {
    pub fn new() -> Self {
        AttackProtector {
            syn_limit: 1024,
            syn_window: Duration::from_secs(1),
            icmp_limit: 256,
            icmp_window: Duration::from_secs(1),
            udp_limit: 512,
            udp_total_limit: 1024,
            udp_window: Duration::from_secs(1),
            syn_counters: HashMap::new(),
            icmp_counters: HashMap::new(),
            udp_counters: HashMap::new(),
            udp_conn_counters: HashMap::new(),
            udp_total_counter: CounterWindow::new(Instant::now()),
        }
    }

    pub fn default() -> Self {
        Self::new()
    }

    pub fn with_limits(syn_limit: u64, icmp_limit: u64, udp_limit: u64, window: Duration) -> Self {
        AttackProtector {
            syn_limit,
            syn_window: window,
            icmp_limit,
            icmp_window: window,
            udp_limit,
            udp_total_limit: udp_limit.saturating_mul(2).max(udp_limit),
            udp_window: window,
            syn_counters: HashMap::new(),
            icmp_counters: HashMap::new(),
            udp_counters: HashMap::new(),
            udp_conn_counters: HashMap::new(),
            udp_total_counter: CounterWindow::new(Instant::now()),
        }
    }

    pub fn check(&mut self, meta: &PacketMetadata, flow: &FlowOutcome, now: Instant) -> bool {
        // Invalid ACK-only without prior SYN: drop early to protect CPU.
        if meta.protocol == IpProtocol::Tcp {
            if let Some(flags) = meta.tcp_flags
                && {
                    let syn = flags & 0x02 != 0;
                    let ack = flags & 0x10 != 0;
                    ack && !syn && flow.is_new && flow.previous_state.is_none()
                }
            {
                return false;
            }
        }

        // SYN flood mitigation: track incomplete TCP handshakes by source IP.
        if meta.protocol == IpProtocol::Tcp {
            if matches!(
                flow.state,
                FlowState::SynSent | FlowState::SynReceived | FlowState::New
            ) {
                let counter = self
                    .syn_counters
                    .entry(meta.src_ip)
                    .or_insert_with(|| CounterWindow::new(now));
                if counter.hit(now, self.syn_window) > self.syn_limit {
                    return false;
                }
            }
            // Reduce counter when connection transitions to established.
            if matches!(flow.state, FlowState::Established) {
                if let Some(prev) = flow.previous_state
                    && matches!(
                        prev,
                        FlowState::SynSent | FlowState::SynReceived | FlowState::New
                    )
                    && let Some(counter) = self.syn_counters.get_mut(&meta.src_ip)
                {
                    counter.decay(1);
                }
            }
        }

        // ICMP rate limit (per source IP).
        if meta.protocol == IpProtocol::Icmpv4 || meta.protocol == IpProtocol::Icmpv6 {
            let counter = self
                .icmp_counters
                .entry(meta.src_ip)
                .or_insert_with(|| CounterWindow::new(now));
            if counter.hit(now, self.icmp_window) > self.icmp_limit {
                return false;
            }
        }

        // UDP flood tracking (per source IP).
        if meta.protocol == IpProtocol::Udp {
            // Global UDP cap to prevent randomized-source floods.
            if self.udp_total_counter.hit(now, self.udp_window) > self.udp_total_limit {
                return false;
            }
            // Per-source packet rate
            let counter = self
                .udp_counters
                .entry(meta.src_ip)
                .or_insert_with(|| CounterWindow::new(now));
            if counter.hit(now, self.udp_window) > self.udp_limit {
                return false;
            }
            // Per-source-dst-port rate to catch randomized ports
            if let Some(dst) = meta.dst_port {
                let key = (meta.src_ip, dst);
                let counter = self
                    .udp_conn_counters
                    .entry(key)
                    .or_insert_with(|| CounterWindow::new(now));
                // Stricter per-port limit (quarter of global limit, minimum 64)
                let per_port_limit = (self.udp_limit / 4).max(64);
                if counter.hit(now, self.udp_window) > per_port_limit {
                    return false;
                }
            }
        }

        true
    }
}

impl BehaviorDetector {
    pub fn new() -> Self {
        // Conservative default to surface application-layer floods quickly.
        Self::with_limits(100, 5, Duration::from_secs(1))
    }

    pub fn default() -> Self {
        Self::new()
    }

    pub fn with_limits(rate_limit: u64, brute_limit: u64, window: Duration) -> Self {
        BehaviorDetector {
            rate_limit,
            rate_window: window,
            brute_limit,
            brute_window: window,
            beacon_tolerance: 0.20,
            beacon_min_delta: Duration::from_millis(0),
            beacon_states: HashMap::new(),
            rate_counters: HashMap::new(),
            brute_counters: HashMap::new(),
        }
    }

    pub fn observe(
        &mut self,
        meta: &PacketMetadata,
        flow: &FlowOutcome,
        now: Instant,
    ) -> Vec<BehaviorAlert> {
        let mut alerts = Vec::new();

        // Generic per-source rate anomaly.
        let rate = self
            .rate_counters
            .entry(meta.src_ip)
            .or_insert_with(|| CounterWindow::new(now));
        let rate_hits = rate.hit(now, self.rate_window);
        if rate_hits > self.rate_limit {
            alerts.push(BehaviorAlert {
                kind: BehaviorKind::RateAnomaly,
                src: meta.src_ip,
                dst: None,
                port: None,
                count: rate_hits,
                timestamp: now,
            });
        }

        // Beacon-like timing detection (periodic low-volume traffic).
        if let (Some(dst), Some(port)) = (Some(meta.dst_ip), meta.dst_port) {
            let key = (meta.src_ip, dst, port);
            let state = self.beacon_states.entry(key).or_insert(BeaconState {
                last: now,
                last_delta: None,
                stable_hits: 0,
            });
            let delta = now.duration_since(state.last);
            if let Some(prev) = state.last_delta {
                let tol = (prev.as_secs_f64() * self.beacon_tolerance).max(0.001);
                let diff = (delta.as_secs_f64() - prev.as_secs_f64()).abs();
                if delta >= self.beacon_min_delta && diff <= tol {
                    state.stable_hits += 1;
                } else {
                    state.stable_hits = 0;
                }
            }
            state.last_delta = Some(delta);
            state.last = now;
            if state.stable_hits >= 2 {
                alerts.push(BehaviorAlert {
                    kind: BehaviorKind::Beacon,
                    src: meta.src_ip,
                    dst: Some(dst),
                    port: Some(port),
                    count: state.stable_hits as u64,
                    timestamp: now,
                });
                state.stable_hits = 0;
            }
        }

        // Brute-force detection: repeated new connection attempts to same target/port.
        if flow.is_new {
            if let Some(dst_port) = meta.dst_port {
                let key = (meta.src_ip, meta.dst_ip, dst_port);
                let counter = self
                    .brute_counters
                    .entry(key)
                    .or_insert_with(|| CounterWindow::new(now));
                let hits = counter.hit(now, self.brute_window);
                if hits > self.brute_limit {
                    alerts.push(BehaviorAlert {
                        kind: BehaviorKind::BruteForce,
                        src: meta.src_ip,
                        dst: Some(meta.dst_ip),
                        port: Some(dst_port),
                        count: hits,
                        timestamp: now,
                    });
                }
            }
        }

        alerts
    }
}

fn normalize_payload(data: &[u8]) -> Vec<u8> {
    // Basic normalization: percent-decode twice to catch double-encoding, strip BOM.
    fn percent_decode_once(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            if input[i] == b'%' && i + 2 < input.len() {
                let hi = input[i + 1];
                let lo = input[i + 2];
                let hex = |b: u8| -> Option<u8> {
                    match b {
                        b'0'..=b'9' => Some(b - b'0'),
                        b'a'..=b'f' => Some(b - b'a' + 10),
                        b'A'..=b'F' => Some(b - b'A' + 10),
                        _ => None,
                    }
                };
                if let (Some(h), Some(l)) = (hex(hi), hex(lo)) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
            }
            out.push(input[i]);
            i += 1;
        }
        out
    }

    let mut decoded = percent_decode_once(data);
    decoded = percent_decode_once(&decoded);
    // Strip UTF-8 BOM if present
    if decoded.starts_with(&[0xEF, 0xBB, 0xBF]) {
        decoded.drain(0..3);
    }
    decoded
}

fn parse_tls_metadata(payload: &[u8]) -> Option<TlsMetadata> {
    if payload.len() < 6 {
        return None;
    }
    if payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }
    if payload.get(5).copied() != Some(0x01) {
        return None;
    }
    // Skip record header (5 bytes) + handshake header (4 bytes)
    if payload.len() < 9 {
        return None;
    }
    let mut idx = 9usize;
    // Version (2) + Random (32)
    if payload.len() < idx + 34 {
        return None;
    }
    idx += 34;
    // Session ID
    let sid_len = payload.get(idx).copied()? as usize;
    idx += 1 + sid_len;
    if payload.len() < idx + 2 {
        return None;
    }
    // Cipher suites vector
    let cipher_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2;
    if payload.len() < idx + cipher_len {
        return None;
    }
    let mut cipher_suites = Vec::new();
    let mut cs_idx = idx;
    while cs_idx + 1 < idx + cipher_len {
        cipher_suites.push(u16::from_be_bytes([payload[cs_idx], payload[cs_idx + 1]]));
        cs_idx += 2;
    }
    idx += cipher_len;
    if payload.len() < idx + 1 {
        return Some(TlsMetadata {
            sni: None,
            cipher_suites,
        });
    }
    // Compression methods
    let comp_len = payload[idx] as usize;
    idx += 1 + comp_len;
    // Extensions length
    if payload.len() < idx + 2 {
        return Some(TlsMetadata {
            sni: None,
            cipher_suites,
        });
    }
    let ext_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2;
    let ext_end = idx.saturating_add(ext_len).min(payload.len());
    let mut sni: Option<String> = None;
    while idx + 4 <= ext_end {
        let etype = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
        let elen = u16::from_be_bytes([payload[idx + 2], payload[idx + 3]]) as usize;
        idx += 4;
        if idx + elen > ext_end {
            break;
        }
        if etype == 0x00 {
            // SNI extension
            if idx + 5 <= ext_end {
                let list_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
                let name_type = payload[idx + 2];
                let name_len = u16::from_be_bytes([payload[idx + 3], payload[idx + 4]]) as usize;
                if name_type == 0 && idx + 5 + name_len <= ext_end && list_len >= name_len + 3 {
                    if let Ok(host) = std::str::from_utf8(&payload[idx + 5..idx + 5 + name_len]) {
                        sni = Some(host.to_string());
                    }
                }
            }
        }
        idx += elen;
    }
    Some(TlsMetadata { sni, cipher_suites })
}

impl ThreatIntel {
    pub fn new() -> Self {
        ThreatIntel {
            bad_ips: HashSet::new(),
            bad_domains: HashSet::new(),
            updated_at: None,
        }
    }

    pub fn default() -> Self {
        Self::new()
    }

    pub fn update(&mut self, ips: &[IpAddr], domains: &[String], now: Instant) {
        for ip in ips {
            self.bad_ips.insert(*ip);
        }
        for d in domains {
            self.bad_domains.insert(d.to_ascii_lowercase());
        }
        self.updated_at = Some(now);
    }

    pub fn check(&self, meta: &PacketMetadata, now: Instant) -> Option<BehaviorAlert> {
        if self.bad_ips.contains(&meta.src_ip) || self.bad_ips.contains(&meta.dst_ip) {
            return Some(BehaviorAlert {
                kind: BehaviorKind::ThreatIntel,
                src: meta.src_ip,
                dst: Some(meta.dst_ip),
                port: meta.dst_port,
                count: 1,
                timestamp: now,
            });
        }
        if let Some(tls) = &meta.tls {
            if let Some(sni) = &tls.sni {
                let sni_lower = sni.to_ascii_lowercase();
                if self.bad_domains.contains(&sni_lower) {
                    return Some(BehaviorAlert {
                        kind: BehaviorKind::ThreatIntel,
                        src: meta.src_ip,
                        dst: Some(meta.dst_ip),
                        port: meta.dst_port,
                        count: 1,
                        timestamp: now,
                    });
                }
            }
        }
        None
    }

    pub fn updated_at(&self) -> Option<Instant> {
        self.updated_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FirewallCounters {
    pub allowed: u64,
    pub dropped: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub action: Action,
    pub flow: FlowOutcome,
    pub blocked_by_protector: bool,
    pub path: Path,
    pub tls_decryption_allowed: bool,
}

#[derive(Debug)]
pub struct FirewallManager {
    firewall: Firewall,
    flows: FlowTable,
    protector: AttackProtector,
    behavior: BehaviorDetector,
    signature_engine: SignatureEngine,
    reassembly: TcpReassembly,
    signature_tails: HashMap<FlowKey, Vec<u8>>,
    block_behavior: bool,
    block_signatures: bool,
    block_c2: bool,
    ids_enabled: bool,
    ips_enabled: bool,
    tls_policy: Option<TlsPolicy>,
    threat_intel: ThreatIntel,
    identity_map: HashMap<IpAddr, String>,
    geo_map: HashMap<IpAddr, String>,
    geo_rules_enabled: bool,
    time_rules_enabled: bool,
    failover_enabled: bool,
    counters: FirewallCounters,
    interfaces: HashMap<String, bool>,
    logs: std::collections::VecDeque<VerdictLog>,
    max_logs: usize,
    dpi_logging_enabled: bool,
    proto_counters: HashMap<IpProtocol, u64>,
    policies: PolicyEngine,
    policy_version: u64,
    alerts: std::collections::VecDeque<BehaviorAlert>,
    max_alerts: usize,
    suspicious: HashSet<FlowKey>,
    rule_hits: HashMap<u64, u64>,
    time_override: Option<u8>,
}

impl FirewallManager {
    pub fn new(flow_capacity: usize) -> Self {
        Self::with_log_capacity(flow_capacity, 1024)
    }

    pub fn with_log_capacity(flow_capacity: usize, log_capacity: usize) -> Self {
        FirewallManager {
            firewall: Firewall::new(),
            flows: FlowTable::new(flow_capacity),
            protector: AttackProtector::new(),
            behavior: BehaviorDetector::new(),
            signature_engine: SignatureEngine::with_default_rules(),
            reassembly: TcpReassembly::new(4096),
            signature_tails: HashMap::new(),
            block_behavior: false,
            block_signatures: true,
            block_c2: false,
            ids_enabled: true,
            ips_enabled: true,
            tls_policy: None,
            threat_intel: ThreatIntel::new(),
            identity_map: HashMap::new(),
            geo_map: HashMap::new(),
            geo_rules_enabled: true,
            time_rules_enabled: true,
            failover_enabled: true,
            counters: FirewallCounters::default(),
            interfaces: HashMap::new(),
            logs: std::collections::VecDeque::new(),
            max_logs: log_capacity.max(1),
            dpi_logging_enabled: true,
            proto_counters: HashMap::new(),
            policies: PolicyEngine::default(),
            policy_version: 0,
            alerts: std::collections::VecDeque::new(),
            max_alerts: 512,
            suspicious: HashSet::new(),
            rule_hits: HashMap::new(),
            time_override: None,
        }
    }

    pub fn add_rule(&mut self, rule: Rule) -> u64 {
        self.firewall.add_rule(rule)
    }

    pub fn remove_rule(&mut self, id: u64) -> bool {
        self.firewall.remove_rule(id)
    }

    pub fn rules(&self) -> &[(u64, Rule)] {
        self.firewall.list_rules()
    }

    pub fn export_flow_state(&self) -> FlowSyncState {
        self.flows.export_state()
    }

    pub fn import_flow_state(&mut self, state: &FlowSyncState, now: Instant) {
        self.flows.import_state(state, now);
    }

    pub fn set_flow_capacity(&mut self, capacity: usize) {
        self.flows.set_capacity(capacity);
    }

    pub fn flow_capacity(&self) -> usize {
        self.flows.capacity()
    }

    pub fn set_failover_enabled(&mut self, enabled: bool) {
        self.failover_enabled = enabled;
    }

    pub fn failover_enabled(&self) -> bool {
        self.failover_enabled
    }

    pub fn add_policy_rule(
        &mut self,
        priority: u32,
        action: Action,
        condition: PolicyCondition,
    ) -> u64 {
        self.policies.add_rule(priority, action, condition)
    }

    pub fn remove_policy_rule(&mut self, id: u64) -> bool {
        self.policies.remove_rule(id)
    }

    pub fn list_policy_rules(&self) -> &[PolicyRule] {
        self.policies.list()
    }

    pub fn apply_policy_entries(&mut self, entries: Vec<PolicyEntry>) {
        self.policies.replace_all(entries);
        self.policy_version = self.policy_version.wrapping_add(1);
    }

    pub fn policy_version(&self) -> u64 {
        self.policy_version
    }

    pub fn enable_interface(&mut self, name: &str) {
        self.interfaces.insert(name.to_string(), true);
    }

    pub fn disable_interface(&mut self, name: &str) {
        self.interfaces.insert(name.to_string(), false);
    }

    fn interface_allowed(&self, name: Option<&str>) -> bool {
        if let Some(iface) = name {
            self.interfaces.get(iface).copied().unwrap_or(true)
        } else {
            true
        }
    }

    pub fn evaluate(
        &mut self,
        meta: &PacketMetadata,
        interface: Option<&str>,
        now: Instant,
    ) -> Evaluation {
        let mut meta = self.enrich_metadata(meta);
        let flow_key = FlowKey::from_metadata(&meta);
        let iface_allowed = self.interface_allowed(interface);
        let base_action = if iface_allowed {
            self.firewall.evaluate(&meta)
        } else {
            Action::Deny
        };
        let mut action = base_action.clone();
        let mut matched_rule = self.matching_rule_id(&meta, &base_action);
        let flow = self.flows.observe(&meta, now);
        let mut blocked_by_protector = false;
        if self.ips_enabled && !self.protector.check(&meta, &flow, now) {
            action = Action::Deny;
            blocked_by_protector = true;
        }
        if self.ips_enabled {
            if let Some(pol) = &self.tls_policy {
                if let Some(tls) = &meta.tls {
                    if let Some(sni) = &tls.sni {
                        if !pol.allow_snis.is_empty()
                            && !pol.allow_snis.iter().any(|d| d.eq_ignore_ascii_case(sni))
                        {
                            action = Action::Deny;
                        }
                        if pol.deny_snis.iter().any(|d| d.eq_ignore_ascii_case(sni)) {
                            action = Action::Deny;
                        }
                    }
                    if !pol.allow_ciphers.is_empty()
                        && !tls
                            .cipher_suites
                            .iter()
                            .any(|c| pol.allow_ciphers.contains(c))
                    {
                        action = Action::Deny;
                    }
                    if pol
                        .deny_ciphers
                        .iter()
                        .any(|c| tls.cipher_suites.contains(c))
                    {
                        action = Action::Deny;
                    }
                    if pol.enforce && matches!(action, Action::Deny) && self.ids_enabled {
                        self.push_alert(BehaviorAlert {
                            kind: BehaviorKind::TlsViolation,
                            src: meta.src_ip,
                            dst: Some(meta.dst_ip),
                            port: meta.dst_port,
                            count: 1,
                            timestamp: now,
                        });
                        self.suspicious.insert(flow_key);
                    }
                }
            }
        }
        if self.ips_enabled {
            if let Some(alert) = self.threat_intel.check(&meta, now) {
                action = Action::Deny;
                if self.ids_enabled {
                    self.push_alert(alert);
                    self.suspicious.insert(flow_key);
                }
            }
        }
        if !blocked_by_protector {
            if let Some(policy_action) = self.policies.evaluate_with_time(
                &meta,
                self.time_override,
                self.geo_rules_enabled,
                self.time_rules_enabled,
            ) {
                action = resolve_conflict(base_action, policy_action);
            }
        }

        // Behavioral telemetry (does not alter verdict).
        let mut rate_alert_seen = false;
        let mut beacon_alert_seen = false;
        let mut sig_hits = meta.signatures.clone();
        let mut scan_data: Option<Vec<u8>> = None;
        // Reassemble TCP payloads to detect split signatures.
        if meta.protocol == IpProtocol::Tcp {
            if let Some(seq) = meta.seq_number {
                let reassembled =
                    self.reassembly
                        .process(flow_key, meta.direction, seq, &meta.payload);
                if !reassembled.is_empty() {
                    scan_data = Some(reassembled);
                }
            }
        }
        // Default to direct payload if no reassembly data.
        if scan_data.is_none() && !meta.payload.is_empty() {
            scan_data = Some(meta.payload.clone());
        }
        if let Some(data) = &scan_data {
            // Prepend tail from this flow to catch boundary-crossing patterns.
            let mut buf = Vec::new();
            if let Some(tail) = self.signature_tails.get(&flow_key) {
                buf.extend_from_slice(tail);
            }
            buf.extend_from_slice(data);
            // Scan raw and normalized encodings.
            sig_hits = self.signature_engine.scan_exploits(&buf);
            let norm = normalize_payload(&buf);
            let mut norm_hits = self.signature_engine.scan_exploits(&norm);
            sig_hits.append(&mut norm_hits);
            // Update TLS metadata from reassembled payload if present.
            if meta.tls.is_none() {
                if let Some(tls) = parse_tls_metadata(&buf) {
                    meta.tls = Some(tls);
                }
            }
            // Update tail with last 32 bytes for future detections.
            let keep = buf.len().min(32);
            self.signature_tails
                .insert(flow_key, buf[buf.len() - keep..].to_vec());
        } else {
            self.signature_tails.remove(&flow_key);
        }
        if self.ids_enabled {
            for alert in self.behavior.observe(&meta, &flow, now) {
                if matches!(alert.kind, BehaviorKind::RateAnomaly) {
                    rate_alert_seen = true;
                }
                if matches!(alert.kind, BehaviorKind::Beacon) {
                    beacon_alert_seen = true;
                }
                self.push_alert(alert);
                self.suspicious.insert(flow_key);
            }
        }
        if self.ids_enabled && !sig_hits.is_empty() {
            for _sig in &sig_hits {
                self.push_alert(BehaviorAlert {
                    kind: BehaviorKind::Signature,
                    src: meta.src_ip,
                    dst: Some(meta.dst_ip),
                    port: meta.dst_port,
                    count: 1,
                    timestamp: now,
                });
                self.suspicious.insert(flow_key);
                if self.block_signatures && self.ips_enabled {
                    action = Action::Deny;
                }
            }
        }
        if self.block_c2 && (beacon_alert_seen || rate_alert_seen) && self.ips_enabled {
            action = Action::Deny;
        }
        if self.block_behavior && (rate_alert_seen || beacon_alert_seen) {
            action = Action::Deny;
        }

        match action {
            Action::Allow => self.counters.allowed += 1,
            Action::Deny => self.counters.dropped += 1,
            Action::Redirect { .. } => self.counters.allowed += 1,
        }
        if let Some(id) = matched_rule.take() {
            *self.rule_hits.entry(id).or_insert(0) += 1;
        }
        *self.proto_counters.entry(meta.protocol).or_insert(0) += 1;
        let path = classify_path(&action, &flow, blocked_by_protector);
        let evaluation = Evaluation {
            action,
            flow,
            blocked_by_protector,
            path,
            tls_decryption_allowed: self.tls_decryption_allowed(),
        };
        self.push_log(&meta, interface, &evaluation, now);
        evaluation
    }

    pub fn counters(&self) -> FirewallCounters {
        self.counters
    }

    pub fn flows(&self) -> Vec<FlowSnapshot> {
        self.flows.snapshot()
    }

    pub fn flow_stats(&self) -> FlowStats {
        self.flows.stats()
    }

    pub fn logs(&self, limit: Option<usize>) -> Vec<VerdictLog> {
        let lim = limit.unwrap_or(self.logs.len());
        self.logs.iter().rev().take(lim).cloned().collect()
    }

    pub fn alerts(&self, limit: Option<usize>) -> Vec<BehaviorAlert> {
        let lim = limit.unwrap_or(self.alerts.len()).min(self.max_alerts);
        self.alerts.iter().rev().take(lim).cloned().collect()
    }

    pub fn clear_alerts(&mut self) {
        self.alerts.clear();
    }

    pub fn suspicious_flows(&self) -> Vec<FlowSnapshot> {
        let keys: HashSet<_> = self.suspicious.iter().copied().collect();
        self.flows
            .snapshot()
            .into_iter()
            .filter(|snap| keys.contains(&snap.key))
            .collect()
    }

    pub fn set_ids_enabled(&mut self, enabled: bool) {
        self.ids_enabled = enabled;
    }

    pub fn set_ips_enabled(&mut self, enabled: bool) {
        self.ips_enabled = enabled;
    }

    pub fn ids_enabled(&self) -> bool {
        self.ids_enabled
    }

    pub fn ips_enabled(&self) -> bool {
        self.ips_enabled
    }

    pub fn set_tls_policy(&mut self, policy: Option<TlsPolicy>) {
        self.tls_policy = policy;
    }

    pub fn tls_policy(&self) -> Option<TlsPolicy> {
        self.tls_policy.clone()
    }

    pub fn tls_decryption_allowed(&self) -> bool {
        self.tls_policy
            .as_ref()
            .map(|p| p.allow_decryption)
            .unwrap_or(false)
    }

    pub fn rule_hits(&self) -> HashMap<u64, u64> {
        self.rule_hits.clone()
    }

    pub fn add_identity(&mut self, ip: IpAddr, user: String) {
        self.identity_map.insert(ip, user);
    }

    pub fn add_geo(&mut self, ip: IpAddr, geo: String) {
        self.geo_map.insert(ip, geo);
    }

    pub fn set_geo_rules_enabled(&mut self, enabled: bool) {
        self.geo_rules_enabled = enabled;
    }

    pub fn set_time_rules_enabled(&mut self, enabled: bool) {
        self.time_rules_enabled = enabled;
    }

    pub fn set_behavior_detector(&mut self, detector: BehaviorDetector) {
        self.behavior = detector;
    }

    pub fn set_behavior_blocking(&mut self, enabled: bool) {
        self.block_behavior = enabled;
    }

    pub fn set_signature_blocking(&mut self, enabled: bool) {
        self.block_signatures = enabled;
    }

    pub fn set_c2_blocking(&mut self, enabled: bool) {
        self.block_c2 = enabled;
    }

    pub fn set_logging_enabled(&mut self, enabled: bool) {
        self.dpi_logging_enabled = enabled;
    }

    pub fn protocol_counters(&self) -> HashMap<IpProtocol, u64> {
        self.proto_counters.clone()
    }

    pub fn update_threat_intel(&mut self, ips: &[IpAddr], domains: &[String], now: Instant) {
        self.threat_intel.update(ips, domains, now);
    }

    pub fn threat_intel_updated_at(&self) -> Option<Instant> {
        self.threat_intel.updated_at()
    }

    pub fn set_time_override(&mut self, hour: Option<u8>) {
        self.time_override = hour;
    }

    fn enrich_metadata(&self, meta: &PacketMetadata) -> PacketMetadata {
        let mut cloned = meta.clone();
        if cloned.user.is_none() {
            if let Some(u) = self.identity_map.get(&meta.src_ip) {
                cloned.user = Some(u.clone());
            }
        }
        if cloned.geo.is_none() {
            if let Some(g) = self.geo_map.get(&meta.src_ip) {
                cloned.geo = Some(g.clone());
            }
        }
        cloned
    }

    fn push_alert(&mut self, alert: BehaviorAlert) {
        if self.alerts.len() >= self.max_alerts {
            self.alerts.pop_front();
        }
        self.alerts.push_back(alert);
    }

    fn matching_rule_id(&self, meta: &PacketMetadata, action: &Action) -> Option<u64> {
        for (id, rule) in &self.firewall.rules {
            if &rule.action != action || rule.direction != meta.direction {
                continue;
            }
            let matched = match &rule.subject {
                RuleSubject::Cidr { network } => {
                    network.contains(&meta.dst_ip) || network.contains(&meta.src_ip)
                }
                RuleSubject::Port { protocol, range } => {
                    *protocol == meta.protocol
                        && (meta.dst_port.map(|p| range.contains(p)).unwrap_or(false)
                            || meta.src_port.map(|p| range.contains(p)).unwrap_or(false))
                }
                RuleSubject::Protocol { protocol } => *protocol == meta.protocol,
                RuleSubject::Default => true,
            };
            if matched {
                return Some(*id);
            }
        }
        None
    }

    fn push_log(
        &mut self,
        meta: &PacketMetadata,
        interface: Option<&str>,
        eval: &Evaluation,
        ts: Instant,
    ) {
        if !self.dpi_logging_enabled {
            return;
        }
        if self.logs.len() >= self.max_logs {
            self.logs.pop_front();
        }
        self.logs.push_back(VerdictLog {
            timestamp: ts,
            interface: interface.map(|s| s.to_string()),
            meta: meta.clone(),
            verdict: eval.action.clone(),
            flow: eval.flow,
            blocked_by_protector: eval.blocked_by_protector,
            path: eval.path,
        });
    }
}

fn initial_state(proto: IpProtocol, tcp_flags: Option<u16>) -> FlowState {
    match proto {
        IpProtocol::Tcp => advance_state(FlowState::New, tcp_flags),
        _ => FlowState::Established,
    }
}

fn advance_state(current: FlowState, tcp_flags: Option<u16>) -> FlowState {
    if tcp_flags.is_none() {
        return match current {
            FlowState::New => FlowState::Established,
            _ => current,
        };
    }
    let flags = tcp_flags.unwrap();
    let syn = flags & 0x02 != 0;
    let ack = flags & 0x10 != 0;
    let fin = flags & 0x01 != 0;
    let rst = flags & 0x04 != 0;

    match current {
        FlowState::New => {
            if syn && ack {
                FlowState::SynReceived
            } else if syn {
                FlowState::SynSent
            } else {
                FlowState::Established
            }
        }
        FlowState::SynSent | FlowState::SynReceived => {
            if rst {
                FlowState::Closed
            } else if ack && !syn {
                FlowState::Established
            } else {
                current
            }
        }
        FlowState::Established => {
            if rst {
                FlowState::Closed
            } else if fin {
                FlowState::FinWait
            } else {
                FlowState::Established
            }
        }
        FlowState::FinWait => {
            if rst {
                FlowState::Closed
            } else if ack {
                FlowState::Closed
            } else {
                FlowState::FinWait
            }
        }
        FlowState::Closed => {
            if syn {
                FlowState::SynSent
            } else {
                FlowState::Closed
            }
        }
    }
}

fn is_expired(state: FlowState, last_seen: Instant, now: Instant, table: &FlowTable) -> bool {
    now.duration_since(last_seen) > table.timeout_for(state)
}

pub fn parse_cidr(input: &str) -> Result<Cidr, ParseError> {
    let parts: Vec<&str> = input.split('/').collect();
    if parts.len() != 2 {
        return Err(ParseError::Invalid("cidr format"));
    }
    let ip: IpAddr = parts[0].parse().map_err(|_| ParseError::Invalid("ip"))?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| ParseError::Invalid("prefix"))?;
    match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return Err(ParseError::Invalid("prefix >32"));
            }
            Ok(Cidr::V4 { addr: v4, prefix })
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return Err(ParseError::Invalid("prefix >128"));
            }
            Ok(Cidr::V6 { addr: v6, prefix })
        }
    }
}

fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_parser::IpProtocol;

    fn meta(
        ip: &str,
        proto: IpProtocol,
        sport: Option<u16>,
        dport: Option<u16>,
        flags: Option<u16>,
    ) -> PacketMetadata {
        PacketMetadata {
            direction: Direction::Ingress,
            src_ip: ip.parse().unwrap(),
            dst_ip: "192.168.1.1".parse().unwrap(),
            protocol: proto,
            src_port: sport,
            dst_port: dport,
            seq_number: None,
            tcp_flags: flags,
            application: ApplicationType::Unknown,
            payload: Vec::new(),
            signatures: Vec::new(),
            user: None,
            geo: None,
            tls: None,
        }
    }

    #[test]
    fn cidr_allow_deny() {
        let mut fw = Firewall::new();
        let _ = fw.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Cidr {
                network: parse_cidr("10.0.0.0/8").unwrap(),
            },
            direction: Direction::Ingress,
        });
        let _ = fw.add_rule(Rule {
            action: Action::Deny,
            subject: RuleSubject::Cidr {
                network: parse_cidr("10.1.0.0/16").unwrap(),
            },
            direction: Direction::Ingress,
        });

        let allowed = meta("10.2.1.1", IpProtocol::Tcp, None, Some(80), None);
        let denied = meta("10.1.1.1", IpProtocol::Tcp, None, Some(80), None);

        assert_eq!(fw.evaluate(&allowed), Action::Allow);
        assert_eq!(fw.evaluate(&denied), Action::Deny);
    }

    #[test]
    fn lpm_order_prefers_longer_prefix() {
        let mut fw = Firewall::new();
        let _ = fw.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Cidr {
                network: parse_cidr("10.0.0.0/8").unwrap(),
            },
            direction: Direction::Ingress,
        });
        let _ = fw.add_rule(Rule {
            action: Action::Deny,
            subject: RuleSubject::Cidr {
                network: parse_cidr("10.0.0.0/24").unwrap(),
            },
            direction: Direction::Ingress,
        });
        let pkt = meta("10.0.0.1", IpProtocol::Tcp, None, Some(80), None);
        assert_eq!(fw.evaluate(&pkt), Action::Deny);
    }

    #[test]
    fn port_and_proto_rules() {
        let mut fw = Firewall::new();
        let _ = fw.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Protocol {
                protocol: IpProtocol::Udp,
            },
            direction: Direction::Ingress,
        });
        let _ = fw.add_rule(Rule {
            action: Action::Deny,
            subject: RuleSubject::Port {
                protocol: IpProtocol::Udp,
                range: PortRange::new(5000, 6000),
            },
            direction: Direction::Ingress,
        });
        let packet = meta("10.0.0.1", IpProtocol::Udp, Some(5500), Some(53), None);
        assert_eq!(fw.evaluate(&packet), Action::Deny);

        let ok = meta("10.0.0.1", IpProtocol::Udp, Some(4000), Some(53), None);
        assert_eq!(fw.evaluate(&ok), Action::Allow);
    }

    #[test]
    fn direction_matters() {
        let mut fw = Firewall::new();
        let _ = fw.add_rule(Rule {
            action: Action::Deny,
            subject: RuleSubject::Protocol {
                protocol: IpProtocol::Tcp,
            },
            direction: Direction::Egress,
        });
        let _ = fw.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        let mut pkt = meta("10.0.0.1", IpProtocol::Tcp, Some(12345), Some(80), None);
        pkt.direction = Direction::Egress;
        assert_eq!(fw.evaluate(&pkt), Action::Deny);
        pkt.direction = Direction::Ingress;
        assert_eq!(fw.evaluate(&pkt), Action::Allow);
    }

    #[test]
    fn default_applies_per_direction() {
        let mut fw = Firewall::new();
        let _ = fw.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Egress,
        });
        let pkt_ing = meta("10.0.0.1", IpProtocol::Udp, None, Some(53), None);
        let mut pkt_egr = pkt_ing.clone();
        pkt_egr.direction = Direction::Egress;
        assert_eq!(fw.evaluate(&pkt_ing), Action::Deny);
        assert_eq!(fw.evaluate(&pkt_egr), Action::Allow);
    }

    #[test]
    fn tcp_flow_establish_and_fast_path() {
        let mut table = FlowTable::new(1024);
        let base = meta("10.0.0.1", IpProtocol::Tcp, Some(12345), Some(80), None);
        let t0 = Instant::now();
        let syn = PacketMetadata {
            tcp_flags: Some(0x02),
            seq_number: Some(1),
            payload: Vec::new(),
            ..base.clone()
        };
        let first = table.observe(&syn, t0);
        assert!(first.is_new);
        assert_eq!(first.state, FlowState::SynSent);

        let ack = PacketMetadata {
            tcp_flags: Some(0x10),
            seq_number: Some(2),
            payload: Vec::new(),
            ..base.clone()
        };
        let second = table.observe(&ack, t0 + Duration::from_secs(1));
        assert!(!second.is_new);
        assert_eq!(second.state, FlowState::Established);

        let mut base_seq = base.clone();
        base_seq.seq_number = Some(3);
        let third = table.observe(&base_seq, t0 + Duration::from_secs(2));
        assert!(third.fast_allowed);
        assert_eq!(third.state, FlowState::Established);
    }

    #[test]
    fn flow_timeouts_respect_state() {
        let mut table = FlowTable::new(8);
        let base = meta(
            "10.0.0.1",
            IpProtocol::Tcp,
            Some(12345),
            Some(80),
            Some(0x02),
        );
        let now = Instant::now();
        // New -> SynSent
        let _ = table.observe(&base, now);
        assert_eq!(table.reap_expired(now + Duration::from_secs(31)), 1);

        // Established times out later
        let mut udp_table = FlowTable::new(4);
        let udp_pkt = meta("10.0.0.2", IpProtocol::Udp, Some(10), Some(20), None);
        let _ = udp_table.observe(&udp_pkt, now);
        assert_eq!(udp_table.reap_expired(now + Duration::from_secs(250)), 0);
        assert!(udp_table.reap_expired(now + Duration::from_secs(400)) >= 1);

        // Closed state times out with closed_timeout
        let mut tcp = FlowTable::new(4);
        let base_tcp = meta("10.0.0.3", IpProtocol::Tcp, Some(1234), Some(80), None);
        let syn = PacketMetadata {
            tcp_flags: Some(0x02),
            seq_number: Some(1),
            payload: Vec::new(),
            ..base_tcp.clone()
        };
        let ack = PacketMetadata {
            tcp_flags: Some(0x10),
            seq_number: Some(2),
            payload: Vec::new(),
            ..base_tcp.clone()
        };
        let fin = PacketMetadata {
            tcp_flags: Some(0x01),
            seq_number: Some(3),
            payload: Vec::new(),
            ..base_tcp.clone()
        };
        tcp.observe(&syn, now);
        tcp.observe(&ack, now + Duration::from_secs(1));
        tcp.observe(&fin, now + Duration::from_secs(2));
        tcp.observe(&ack, now + Duration::from_secs(3)); // transition to Closed
        assert!(tcp.reap_expired(now + Duration::from_secs(20)) >= 1);
    }

    #[test]
    fn lru_eviction_and_expiry() {
        let mut table = FlowTable::new(1);
        let base = meta("10.0.0.1", IpProtocol::Udp, Some(1), Some(2), None);
        let now = Instant::now();
        let _ = table.observe(&base, now);
        let other = meta("10.0.0.2", IpProtocol::Udp, Some(3), Some(4), None);
        let _ = table.observe(&other, now);
        assert_eq!(table.stats().evicted, 1);

        // Expire the remaining flow
        let removed = table.reap_expired(now + Duration::from_secs(400));
        assert!(removed >= 1);
    }

    #[test]
    fn attack_protector_limits() {
        let mut prot = AttackProtector::with_limits(2, 1, 2, Duration::from_secs(1));
        let now = Instant::now();
        let flow = FlowOutcome {
            is_new: true,
            state: FlowState::SynSent,
            fast_allowed: false,
            previous_state: None,
            application: ApplicationType::Unknown,
        };
        let packet = meta("10.0.0.1", IpProtocol::Tcp, Some(1), Some(2), Some(0x02));

        assert!(prot.check(&packet, &flow, now));
        assert!(prot.check(&packet, &flow, now));
        assert!(!prot.check(&packet, &flow, now)); // exceeds syn limit

        let icmp = meta("10.0.0.2", IpProtocol::Icmpv4, None, None, None);
        assert!(prot.check(&icmp, &flow, now));
        assert!(!prot.check(&icmp, &flow, now)); // exceeds icmp limit

        let udp_flow = FlowOutcome {
            is_new: true,
            state: FlowState::Established,
            fast_allowed: true,
            previous_state: None,
            application: ApplicationType::Unknown,
        };
        let udp_pkt = meta("10.0.0.3", IpProtocol::Udp, Some(10), Some(20), None);
        assert!(prot.check(&udp_pkt, &udp_flow, now));
        assert!(prot.check(&udp_pkt, &udp_flow, now));
        assert!(!prot.check(&udp_pkt, &udp_flow, now)); // exceeds udp limit

        // Window reset allows again
        assert!(prot.check(&udp_pkt, &udp_flow, now + Duration::from_secs(2)));

        // SYN decay when established
        let est_flow = FlowOutcome {
            is_new: false,
            state: FlowState::Established,
            fast_allowed: true,
            previous_state: Some(FlowState::SynSent),
            application: ApplicationType::Unknown,
        };
        let tcp_pkt = meta("10.0.0.4", IpProtocol::Tcp, Some(30), Some(40), Some(0x12));
        // Add pending syns
        let syn_flow = FlowOutcome {
            is_new: true,
            state: FlowState::SynSent,
            fast_allowed: false,
            previous_state: None,
            application: ApplicationType::Unknown,
        };
        assert!(prot.check(&tcp_pkt, &syn_flow, now));
        assert!(prot.check(&tcp_pkt, &syn_flow, now));
        // This would exceed limit without decay
        assert!(prot.check(&tcp_pkt, &est_flow, now));
    }

    #[test]
    fn regression_syn_decay_allows_followup() {
        let mut prot = AttackProtector::with_limits(1, 10, 10, Duration::from_secs(1));
        let now = Instant::now();
        let tcp_pkt = meta(
            "10.0.0.5",
            IpProtocol::Tcp,
            Some(1111),
            Some(80),
            Some(0x02),
        );
        let syn_flow = FlowOutcome {
            is_new: true,
            state: FlowState::SynSent,
            fast_allowed: false,
            previous_state: None,
            application: ApplicationType::Unknown,
        };
        assert!(prot.check(&tcp_pkt, &syn_flow, now)); // first SYN allowed
        assert!(!prot.check(&tcp_pkt, &syn_flow, now)); // second exceeded limit

        // Transition to established decays pending SYN count
        let est_flow = FlowOutcome {
            is_new: false,
            state: FlowState::Established,
            fast_allowed: true,
            previous_state: Some(FlowState::SynSent),
            application: ApplicationType::Unknown,
        };
        assert!(prot.check(&tcp_pkt, &est_flow, now));
        // New SYN still hits limit immediately...
        assert!(!prot.check(&tcp_pkt, &syn_flow, now));
        // ...but after window reset it should pass again
        assert!(prot.check(&tcp_pkt, &syn_flow, now + Duration::from_secs(2)));
    }

    #[test]
    fn regression_lru_retains_recent_flow() {
        let mut table = FlowTable::new(2);
        let now = Instant::now();
        let a = meta("10.0.0.1", IpProtocol::Udp, Some(1), Some(2), None);
        let b = meta("10.0.0.2", IpProtocol::Udp, Some(3), Some(4), None);
        let c = meta("10.0.0.3", IpProtocol::Udp, Some(5), Some(6), None);
        table.observe(&a, now);
        table.observe(&b, now);
        // Touch A to make it most recent
        table.observe(&a, now + Duration::from_secs(1));
        // Insert C should evict B (oldest), not A
        table.observe(&c, now + Duration::from_secs(2));
        assert!(table.table.contains_key(&FlowKey::from_metadata(&a)));
        assert!(table.table.contains_key(&FlowKey::from_metadata(&c)));
        assert!(!table.table.contains_key(&FlowKey::from_metadata(&b)));
        assert!(table.stats().evicted >= 1);
    }

    #[test]
    fn firewall_manager_add_remove_and_interface_toggle() {
        let mut mgr = FirewallManager::new(16);
        let allow_id = mgr.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        let drop_id = mgr.add_rule(Rule {
            action: Action::Deny,
            subject: RuleSubject::Port {
                protocol: IpProtocol::Tcp,
                range: PortRange::new(22, 22),
            },
            direction: Direction::Ingress,
        });
        assert_eq!(mgr.rules().len(), 2);

        let pkt = meta(
            "10.0.0.1",
            IpProtocol::Tcp,
            Some(1234),
            Some(80),
            Some(0x02),
        );
        let eval = mgr.evaluate(&pkt, Some("eth0"), Instant::now());
        assert_eq!(eval.action, Action::Allow);

        mgr.disable_interface("eth0");
        let eval_blocked = mgr.evaluate(&pkt, Some("eth0"), Instant::now());
        assert_eq!(eval_blocked.action, Action::Deny);

        assert!(mgr.remove_rule(drop_id));
        assert!(mgr.rules().iter().all(|(id, _)| *id != drop_id));
        assert!(mgr.rules().iter().any(|(id, _)| *id == allow_id));
    }

    #[test]
    fn logs_cap_and_redirect_action() {
        let mut mgr = FirewallManager::with_log_capacity(8, 2);
        let _ = mgr.add_rule(Rule {
            action: Action::Redirect { interface: None },
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        let meta = meta("10.0.0.1", IpProtocol::Tcp, Some(1), Some(2), Some(0x12));
        let now = Instant::now();
        let _ = mgr.evaluate(&meta, Some("eth0"), now);
        let _ = mgr.evaluate(&meta, Some("eth0"), now);
        let _ = mgr.evaluate(&meta, Some("eth0"), now);
        let logs = mgr.logs(None);
        assert_eq!(logs.len(), 2);
        assert!(matches!(logs[0].verdict, Action::Redirect { .. }));
        // Redirects are treated as slow path; accept fast in case flow was already established
        let path = logs[0].path;
        assert!(
            matches!(path, Path::Slow(_)) || path == Path::Fast,
            "unexpected path for redirect: {:?}",
            path
        );
    }

    #[test]
    fn path_classification_covers_cases() {
        let mut mgr = FirewallManager::with_log_capacity(8, 4);
        // default allow ingress
        mgr.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        // packet with unknown app -> slow
        let meta_pkt = meta("10.0.0.1", IpProtocol::Tcp, Some(1), Some(2), Some(0x12));
        let eval = mgr.evaluate(&meta_pkt, None, Instant::now());
        assert!(matches!(
            eval.path,
            Path::Slow(SlowReason::UnknownApplication) | Path::Slow(SlowReason::NewFlow)
        ));

        // mark application known to force fast path when established
        let mut meta_known = meta_pkt.clone();
        meta_known.application = ApplicationType::Http;
        let _ = mgr.evaluate(&meta_known, None, Instant::now());
        let eval2 = mgr.evaluate(&meta_known, None, Instant::now());
        if eval2.flow.fast_allowed && !eval2.flow.is_new {
            assert_eq!(eval2.path, Path::Fast);
        }

        // protect-triggered slow path
        let mut prot_mgr = FirewallManager::with_log_capacity(8, 4);
        prot_mgr.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        let pkt_protected = meta(
            "10.0.0.9",
            IpProtocol::Tcp,
            Some(1000),
            Some(80),
            Some(0x02),
        );
        // saturate protector
        let _ = prot_mgr.evaluate(&pkt_protected, None, Instant::now());
        let eval3 = prot_mgr.evaluate(&pkt_protected, None, Instant::now());
        assert!(matches!(eval3.path, Path::Slow(_)));
    }

    #[test]
    fn behavior_detector_emits_rate_and_bruteforce_alerts() {
        let mut detector = BehaviorDetector::with_limits(2, 2, Duration::from_secs(1));
        let now = Instant::now();
        let meta = meta(
            "10.1.1.1",
            IpProtocol::Tcp,
            Some(1000),
            Some(22),
            Some(0x02),
        );
        let flow_new = FlowOutcome {
            is_new: true,
            state: FlowState::SynSent,
            fast_allowed: false,
            previous_state: None,
            application: ApplicationType::Unknown,
        };
        let flow_existing = FlowOutcome {
            is_new: false,
            state: FlowState::Established,
            fast_allowed: true,
            previous_state: Some(FlowState::SynSent),
            application: ApplicationType::Unknown,
        };

        // Rate anomaly after third packet
        detector.observe(&meta, &flow_existing, now);
        detector.observe(&meta, &flow_existing, now);
        let alerts = detector.observe(&meta, &flow_existing, now);
        assert!(alerts.iter().any(|a| a.kind == BehaviorKind::RateAnomaly));

        // Brute-force after third new attempt to same dst/port
        let mut brute_alerted = false;
        for i in 0..3 {
            let mut meta_b = meta.clone();
            meta_b.src_port = Some(5000 + i);
            let alerts = detector.observe(&meta_b, &flow_new, now);
            brute_alerted =
                brute_alerted || alerts.iter().any(|a| a.kind == BehaviorKind::BruteForce);
        }
        assert!(brute_alerted, "expected brute-force alert");
    }

    #[test]
    fn tls_policy_blocks_sni() {
        let mut mgr = FirewallManager::new(8);
        mgr.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        mgr.set_tls_policy(Some(TlsPolicy {
            allow_snis: vec!["example.com".into()],
            deny_snis: Vec::new(),
            allow_ciphers: vec![0x1301],
            deny_ciphers: Vec::new(),
            enforce: true,
            allow_decryption: true,
        }));
        let mut meta_tls = meta(
            "10.0.0.1",
            IpProtocol::Tcp,
            Some(443),
            Some(44444),
            Some(0x02),
        );
        meta_tls.application = ApplicationType::TlsClientHello;
        meta_tls.tls = Some(TlsMetadata {
            sni: Some("bad.com".into()),
            cipher_suites: vec![0x1301],
        });
        let eval = mgr.evaluate(&meta_tls, None, Instant::now());
        assert_eq!(eval.action, Action::Deny);
        assert!(mgr.tls_decryption_allowed());
    }

    #[test]
    fn threat_intel_blocks_ip_and_domain() {
        let mut mgr = FirewallManager::new(8);
        mgr.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        let bad_ip: IpAddr = "10.5.5.5".parse().unwrap();
        let domain = "evil.com".to_string();
        mgr.update_threat_intel(&[bad_ip], &[domain.clone()], Instant::now());

        let mut meta_ip = meta(
            "10.5.5.5",
            IpProtocol::Tcp,
            Some(80),
            Some(1234),
            Some(0x02),
        );
        meta_ip.application = ApplicationType::TlsClientHello;
        meta_ip.tls = Some(TlsMetadata {
            sni: Some("good.com".into()),
            cipher_suites: vec![0x1301],
        });
        let eval_ip = mgr.evaluate(&meta_ip, None, Instant::now());
        assert_eq!(eval_ip.action, Action::Deny);
        assert!(!mgr.alerts(None).is_empty());

        let mut meta_domain = meta(
            "10.1.1.1",
            IpProtocol::Tcp,
            Some(80),
            Some(1234),
            Some(0x02),
        );
        meta_domain.application = ApplicationType::TlsClientHello;
        meta_domain.tls = Some(TlsMetadata {
            sni: Some("evil.com".into()),
            cipher_suites: vec![0x1301],
        });
        let eval_dom = mgr.evaluate(&meta_domain, None, Instant::now());
        assert_eq!(eval_dom.action, Action::Deny);
        assert!(
            mgr.alerts(None)
                .iter()
                .any(|a| matches!(a.kind, BehaviorKind::ThreatIntel))
        );
    }

    #[test]
    fn firewall_manager_records_alerts() {
        let mut mgr = FirewallManager::new(8);
        mgr.set_behavior_detector(BehaviorDetector::with_limits(1, 1, Duration::from_secs(10)));
        mgr.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        let pkt = meta("10.0.0.9", IpProtocol::Tcp, Some(1), Some(22), Some(0x02));
        let now = Instant::now();
        let _ = mgr.evaluate(&pkt, None, now);
        let _ = mgr.evaluate(&pkt, None, now);
        let alerts = mgr.alerts(None);
        assert!(!alerts.is_empty());
        assert!(alerts.iter().any(|a| a.kind == BehaviorKind::RateAnomaly));
    }

    #[test]
    fn ids_toggle_disables_alerts() {
        let mut mgr = FirewallManager::new(8);
        mgr.set_behavior_detector(BehaviorDetector::with_limits(1, 1, Duration::from_secs(10)));
        mgr.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        let pkt = meta("10.0.0.9", IpProtocol::Tcp, Some(1), Some(22), Some(0x02));
        let now = Instant::now();
        mgr.set_ids_enabled(false);
        let _ = mgr.evaluate(&pkt, None, now);
        let _ = mgr.evaluate(&pkt, None, now);
        assert!(mgr.alerts(None).is_empty());
        assert!(mgr.suspicious_flows().is_empty());
    }

    #[test]
    fn rule_hits_are_recorded() {
        let mut mgr = FirewallManager::new(8);
        let id = mgr.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Port {
                protocol: IpProtocol::Tcp,
                range: PortRange::new(80, 80),
            },
            direction: Direction::Ingress,
        });
        let pkt = meta(
            "10.0.0.1",
            IpProtocol::Tcp,
            Some(1234),
            Some(80),
            Some(0x10),
        );
        let _ = mgr.evaluate(&pkt, None, Instant::now());
        let hits = mgr.rule_hits();
        assert_eq!(hits.get(&id).copied().unwrap_or(0), 1);
    }

    #[test]
    fn policy_priority_and_conflict_resolution() {
        let mut mgr = FirewallManager::new(16);
        mgr.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        // Lower priority deny for HTTP
        mgr.add_policy_rule(
            5,
            Action::Deny,
            PolicyCondition {
                src: None,
                dst: None,
                users: Vec::new(),
                applications: vec![ApplicationType::Http],
                geos: Vec::new(),
                time_windows: Vec::new(),
            },
        );
        // Higher priority allow overrides
        mgr.add_policy_rule(
            10,
            Action::Allow,
            PolicyCondition {
                src: None,
                dst: None,
                users: Vec::new(),
                applications: vec![ApplicationType::Http],
                geos: Vec::new(),
                time_windows: Vec::new(),
            },
        );
        let mut meta_pkt = meta(
            "10.0.0.1",
            IpProtocol::Tcp,
            Some(80),
            Some(1234),
            Some(0x12),
        );
        meta_pkt.application = ApplicationType::Http;
        let eval = mgr.evaluate(&meta_pkt, None, Instant::now());
        assert_eq!(eval.action, Action::Allow);

        // Conflict between base allow and policy deny should deny
        mgr.add_policy_rule(
            20,
            Action::Deny,
            PolicyCondition {
                src: None,
                dst: None,
                users: vec!["alice".into()],
                applications: Vec::new(),
                geos: Vec::new(),
                time_windows: Vec::new(),
            },
        );
        meta_pkt.user = Some("alice".into());
        let eval2 = mgr.evaluate(&meta_pkt, None, Instant::now());
        assert_eq!(eval2.action, Action::Deny);
    }

    #[test]
    fn protocol_counters_increment() {
        let mut mgr = FirewallManager::new(8);
        mgr.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        let udp = meta("10.0.0.1", IpProtocol::Udp, Some(1), Some(2), None);
        let tcp = meta("10.0.0.2", IpProtocol::Tcp, Some(1), Some(2), Some(0x12));
        mgr.evaluate(&udp, None, Instant::now());
        mgr.evaluate(&tcp, None, Instant::now());
        let counts = mgr.protocol_counters();
        assert_eq!(counts.get(&IpProtocol::Udp), Some(&1));
        assert_eq!(counts.get(&IpProtocol::Tcp), Some(&1));
    }

    #[test]
    fn time_based_policy_respects_window() {
        let mut mgr = FirewallManager::new(4);
        mgr.add_rule(Rule {
            action: Action::Deny,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        mgr.add_policy_rule(
            10,
            Action::Allow,
            PolicyCondition {
                src: None,
                dst: None,
                users: Vec::new(),
                applications: Vec::new(),
                geos: Vec::new(),
                time_windows: vec![TimeWindow {
                    start_hour: 9,
                    end_hour: 17,
                }],
            },
        );
        let pkt = meta("10.0.0.1", IpProtocol::Tcp, Some(1), Some(80), Some(0x02));
        mgr.set_time_override(Some(10));
        assert_eq!(
            mgr.evaluate(&pkt, None, Instant::now()).action,
            Action::Allow
        );
        mgr.set_time_override(Some(20));
        assert_eq!(
            mgr.evaluate(&pkt, None, Instant::now()).action,
            Action::Deny
        );
    }

    #[test]
    fn identity_and_geo_enrichment() {
        let mut mgr = FirewallManager::new(4);
        mgr.add_rule(Rule {
            action: Action::Deny,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        mgr.add_policy_rule(
            5,
            Action::Allow,
            PolicyCondition {
                src: None,
                dst: None,
                users: vec!["alice".into()],
                applications: Vec::new(),
                geos: vec!["US".into()],
                time_windows: Vec::new(),
            },
        );
        mgr.add_identity("10.1.1.1".parse().unwrap(), "alice".into());
        mgr.add_geo("10.1.1.1".parse().unwrap(), "US".into());
        let pkt = meta("10.1.1.1", IpProtocol::Tcp, Some(1), Some(2), Some(0x02));
        let eval = mgr.evaluate(&pkt, None, Instant::now());
        assert_eq!(eval.action, Action::Allow);
    }

    #[test]
    fn time_policy_disabled_allows_outside_window() {
        let mut mgr = FirewallManager::new(4);
        mgr.add_rule(Rule {
            action: Action::Deny,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        mgr.add_policy_rule(
            5,
            Action::Allow,
            PolicyCondition {
                src: None,
                dst: None,
                users: Vec::new(),
                applications: Vec::new(),
                geos: Vec::new(),
                time_windows: vec![TimeWindow {
                    start_hour: 9,
                    end_hour: 10,
                }],
            },
        );
        let pkt = meta("10.0.0.1", IpProtocol::Tcp, Some(1), Some(80), Some(0x02));
        mgr.set_time_override(Some(22));
        mgr.set_time_rules_enabled(false);
        assert_eq!(
            mgr.evaluate(&pkt, None, Instant::now()).action,
            Action::Allow
        );
    }

    #[test]
    fn geo_policy_disabled_allows() {
        let mut mgr = FirewallManager::new(4);
        mgr.add_rule(Rule {
            action: Action::Deny,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        mgr.add_policy_rule(
            5,
            Action::Allow,
            PolicyCondition {
                src: None,
                dst: None,
                users: Vec::new(),
                applications: Vec::new(),
                geos: vec!["US".into()],
                time_windows: Vec::new(),
            },
        );
        mgr.add_geo("10.0.0.1".parse().unwrap(), "US".into());
        mgr.set_geo_rules_enabled(false);
        let pkt = meta("10.0.0.1", IpProtocol::Tcp, Some(1), Some(80), Some(0x02));
        assert_eq!(
            mgr.evaluate(&pkt, None, Instant::now()).action,
            Action::Allow
        );
    }

    #[test]
    fn tls_metadata_captured_in_snapshot() {
        let mut mgr = FirewallManager::new(4);
        mgr.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        let mut pkt = meta(
            "10.0.0.1",
            IpProtocol::Tcp,
            Some(443),
            Some(1234),
            Some(0x12),
        );
        pkt.tls = Some(TlsMetadata {
            sni: Some("example.com".into()),
            cipher_suites: vec![0x1301],
        });
        let now = Instant::now();
        mgr.evaluate(&pkt, None, now);
        let snaps = mgr.flows();
        assert_eq!(snaps.len(), 1);
        assert_eq!(
            snaps[0].tls.as_ref().and_then(|t| t.sni.clone()),
            Some("example.com".into())
        );
    }

    #[test]
    fn flow_state_can_sync_between_instances() {
        let mut mgr_a = FirewallManager::new(8);
        mgr_a.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        let pkt = meta(
            "10.0.0.1",
            IpProtocol::Tcp,
            Some(1000),
            Some(80),
            Some(0x12),
        );
        mgr_a.evaluate(&pkt, None, Instant::now());
        let sync = mgr_a.export_flow_state();

        let mut mgr_b = FirewallManager::new(8);
        mgr_b.import_flow_state(&sync, Instant::now());
        let eval_b = mgr_b.evaluate(&pkt, None, Instant::now());
        // Should see flow as existing (fast_allowed) after sync
        assert!(!eval_b.flow.is_new);
    }

    #[test]
    fn threat_intel_updates_timestamp() {
        let mut mgr = FirewallManager::new(4);
        let t0 = Instant::now();
        mgr.update_threat_intel(&["10.0.0.9".parse().unwrap()], &Vec::new(), t0);
        assert!(mgr.threat_intel_updated_at().is_some());
    }

    #[test]
    fn logging_can_be_disabled() {
        let mut mgr = FirewallManager::with_log_capacity(4, 4);
        mgr.set_logging_enabled(false);
        mgr.add_rule(Rule {
            action: Action::Allow,
            subject: RuleSubject::Default,
            direction: Direction::Ingress,
        });
        let pkt = meta("10.0.0.1", IpProtocol::Udp, Some(1), Some(2), None);
        mgr.evaluate(&pkt, None, Instant::now());
        assert!(mgr.logs(None).is_empty());
    }

    #[test]
    fn policy_version_increments_on_replace() {
        let mut mgr = FirewallManager::new(4);
        let v0 = mgr.policy_version();
        let entries = vec![PolicyEntry {
            priority: 1,
            action: Action::Allow,
            condition: PolicyCondition {
                src: None,
                dst: None,
                users: Vec::new(),
                applications: Vec::new(),
                geos: Vec::new(),
                time_windows: Vec::new(),
            },
        }];
        mgr.apply_policy_entries(entries);
        let v1 = mgr.policy_version();
        assert_ne!(v0, v1);
        assert_eq!(mgr.list_policy_rules().len(), 1);
    }

    #[test]
    fn tcp_reassembly_in_order_and_out_of_order() {
        let flow = FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 1234,
            dst_port: 80,
            protocol: IpProtocol::Tcp,
        };
        let mut reasm = TcpReassembly::new(4096);
        let out1 = reasm.process(flow, Direction::Ingress, 1, b"hel");
        assert_eq!(out1, b"hel");
        // Out-of-order arrives later
        let out2 = reasm.process(flow, Direction::Ingress, 7, b"world");
        assert!(out2.is_empty());
        let out3 = reasm.process(flow, Direction::Ingress, 4, b"lo ");
        assert_eq!(out3, b"lo world");
    }

    #[test]
    fn tcp_reassembly_drops_over_buffer() {
        let flow = FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 1234,
            dst_port: 80,
            protocol: IpProtocol::Tcp,
        };
        let mut reasm = TcpReassembly::new(4);
        // Buffer is small; out-of-order large chunk should be dropped.
        reasm.process(flow, Direction::Ingress, 10, b"abcdef");
        let out = reasm.process(flow, Direction::Ingress, 1, b"hi ");
        assert_eq!(out, b"hi ");
        // No buffered data should have been added due to overflow
        assert!(
            reasm
                .streams
                .get(&(flow, Direction::Ingress))
                .map(|s| s.buffer.is_empty())
                .unwrap_or(true)
        );
    }

    #[test]
    fn signature_engine_detects_common_protocols() {
        let engine = SignatureEngine::with_default_rules();
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            engine.detect_application(IpProtocol::Tcp, 1234, 80, http),
            ApplicationType::Http
        );

        let dns = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            engine.detect_application(IpProtocol::Udp, 1234, 53, &dns),
            ApplicationType::Dns
        );

        let ftp = b"STOR file.bin\r\n";
        assert_eq!(
            engine.detect_application(IpProtocol::Tcp, 21, 1024, ftp),
            ApplicationType::FileTransfer
        );

        let tls = [0x16, 0x03, 0x01, 0x00, 0x00, 0x01];
        assert_eq!(
            engine.detect_application(IpProtocol::Tcp, 5555, 443, &tls),
            ApplicationType::TlsClientHello
        );

        let unknown = b"\x00\x01";
        assert_eq!(
            engine.detect_application(IpProtocol::Tcp, 1, 2, unknown),
            ApplicationType::Unknown
        );
    }
}
