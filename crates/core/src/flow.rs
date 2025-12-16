#![forbid(unsafe_code)]

use crate::{ApplicationType, PacketMetadata, TlsMetadata};
use packet_parser::IpProtocol;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlowStats {
    pub packets: u64,
    pub new_flows: u64,
    pub evicted: u64,
}

impl FlowStats {
    pub fn add_packet(&mut self) {
        self.packets += 1;
    }
    pub fn add_flow(&mut self) {
        self.new_flows += 1;
    }
    pub fn add_evicted(&mut self) {
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

    pub fn contains(&self, key: &FlowKey) -> bool {
        self.table.contains_key(key)
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

pub(crate) fn initial_state(proto: IpProtocol, tcp_flags: Option<u16>) -> FlowState {
    match proto {
        IpProtocol::Tcp => advance_state(FlowState::New, tcp_flags),
        _ => FlowState::Established,
    }
}

pub(crate) fn advance_state(current: FlowState, tcp_flags: Option<u16>) -> FlowState {
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

pub(crate) fn is_expired(state: FlowState, last_seen: Instant, now: Instant, table: &FlowTable) -> bool {
    now.duration_since(last_seen) > table.timeout_for(state)
}
