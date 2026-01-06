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

#[derive(Debug, Clone, Copy)]
struct FlowTimeouts {
    handshake_timeout: Duration,
    established_timeout: Duration,
    closed_timeout: Duration,
}

#[derive(Debug)]
struct FlowShard {
    capacity: usize,
    lru: VecDeque<FlowKey>,
    table: HashMap<FlowKey, FlowEntry>,
    stats: FlowStats,
    last_evicted: Option<FlowKey>,
}

impl FlowShard {
    fn new(capacity: usize) -> Self {
        FlowShard {
            capacity: capacity.max(1),
            lru: VecDeque::new(),
            table: HashMap::new(),
            stats: FlowStats::default(),
            last_evicted: None,
        }
    }

    fn observe(
        &mut self,
        key: FlowKey,
        meta: &PacketMetadata,
        now: Instant,
        timeouts: &FlowTimeouts,
    ) -> FlowOutcome {
        self.reap_expired(now, timeouts);
        self.stats.add_packet();

        if let Some(entry) = self.table.get(&key).cloned() {
            if is_expired(entry.state, entry.last_seen, now, timeouts) {
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
        self.insert_new(key, initial, meta.application, meta.tls.clone(), now);
        self.stats.add_flow();
        FlowOutcome {
            is_new: true,
            state: initial,
            fast_allowed: false,
            previous_state: None,
            application: meta.application,
        }
    }

    fn stats(&self) -> FlowStats {
        self.stats
    }

    fn set_capacity(&mut self, new_capacity: usize) {
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

    fn len(&self) -> usize {
        self.table.len()
    }

    fn contains(&self, key: &FlowKey) -> bool {
        self.table.contains_key(key)
    }

    fn snapshot(&self) -> Vec<FlowSnapshot> {
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

    fn import_snapshot(&mut self, snap: &FlowSnapshot) {
        self.insert_or_replace_with_last_seen(
            snap.key,
            snap.state,
            snap.application,
            snap.tls.clone(),
            snap.last_seen,
        );
    }

    fn reap_expired(&mut self, now: Instant, timeouts: &FlowTimeouts) -> usize {
        let mut removed = 0usize;
        let mut to_remove = Vec::new();
        for (key, entry) in self.table.iter() {
            if is_expired(entry.state, entry.last_seen, now, timeouts) {
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
    ) {
        if self.table.len() >= self.capacity {
            if let Some(oldest) = self.lru.pop_front() {
                self.table.remove(&oldest);
                self.stats.add_evicted();
                self.last_evicted = Some(oldest);
            }
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

    fn insert_or_replace_with_last_seen(
        &mut self,
        key: FlowKey,
        state: FlowState,
        application: ApplicationType,
        tls: Option<TlsMetadata>,
        last_seen: Instant,
    ) {
        if self.table.contains_key(&key) {
            if let Some(entry) = self.table.get_mut(&key) {
                entry.state = state;
                entry.last_seen = last_seen;
                entry.application = application;
                entry.tls = tls;
            }
            self.touch(&key);
        } else {
            self.insert_new(key, state, application, tls, last_seen);
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
}

#[derive(Debug)]
pub struct FlowTable {
    capacity: usize,
    shards: Vec<FlowShard>,
    timeouts: FlowTimeouts,
    last_evicted: Option<FlowKey>,
}

impl FlowTable {
    pub fn new(capacity: usize) -> Self {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        FlowTable::with_shards(capacity, cores)
    }

    pub fn with_shards(capacity: usize, shards: usize) -> Self {
        let capacity = capacity.max(1);
        let shard_count = shard_count(capacity, shards);
        let mut shard_vec = Vec::with_capacity(shard_count);
        for idx in 0..shard_count {
            shard_vec.push(FlowShard::new(shard_capacity(capacity, shard_count, idx)));
        }
        FlowTable {
            capacity,
            shards: shard_vec,
            timeouts: FlowTimeouts {
                handshake_timeout: Duration::from_secs(30),
                established_timeout: Duration::from_secs(300),
                closed_timeout: Duration::from_secs(15),
            },
            last_evicted: None,
        }
    }

    pub fn observe(&mut self, meta: &PacketMetadata, now: Instant) -> FlowOutcome {
        let key = FlowKey::from_metadata(meta);
        let shard_idx = self.select_shard(&key);
        let shard = self
            .shards
            .get_mut(shard_idx)
            .expect("flow shard index out of range");
        let outcome = shard.observe(key, meta, now, &self.timeouts);
        self.last_evicted = shard.last_evicted.take();
        outcome
    }

    pub fn observe_on_shard(
        &mut self,
        shard_idx: usize,
        meta: &PacketMetadata,
        now: Instant,
    ) -> Result<FlowOutcome, String> {
        if shard_idx >= self.shards.len() {
            return Err(format!(
                "flow shard {shard_idx} out of range (shards={})",
                self.shards.len()
            ));
        }
        let key = FlowKey::from_metadata(meta);
        let shard = self
            .shards
            .get_mut(shard_idx)
            .ok_or_else(|| "flow shard index out of range".to_string())?;
        let outcome = shard.observe(key, meta, now, &self.timeouts);
        self.last_evicted = shard.last_evicted.take();
        Ok(outcome)
    }

    pub fn stats(&self) -> FlowStats {
        let mut agg = FlowStats::default();
        for shard in &self.shards {
            let stats = shard.stats();
            agg.packets += stats.packets;
            agg.new_flows += stats.new_flows;
            agg.evicted += stats.evicted;
        }
        agg
    }

    pub fn set_capacity(&mut self, new_capacity: usize) {
        let new_capacity = new_capacity.max(1);
        let desired_shards = shard_count(
            new_capacity,
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
        );
        if desired_shards != self.shards.len() {
            self.rebuild(new_capacity, desired_shards);
            return;
        }
        self.capacity = new_capacity;
        let shard_count = self.shards.len();
        for (idx, shard) in self.shards.iter_mut().enumerate() {
            shard.set_capacity(shard_capacity(new_capacity, shard_count, idx));
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(FlowShard::len).sum()
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len().max(1)
    }

    pub fn shard_for_key(&self, key: &FlowKey) -> usize {
        self.select_shard(key)
    }

    pub fn contains(&self, key: &FlowKey) -> bool {
        let idx = self.select_shard(key);
        self.shards
            .get(idx)
            .map(|shard| shard.contains(key))
            .unwrap_or(false)
    }

    pub fn snapshot(&self) -> Vec<FlowSnapshot> {
        let mut out = Vec::new();
        for shard in &self.shards {
            out.extend(shard.snapshot());
        }
        out
    }

    pub fn export_state(&self) -> FlowSyncState {
        FlowSyncState {
            flows: self.snapshot(),
            stats: self.stats(),
        }
    }

    pub fn import_state(&mut self, state: &FlowSyncState, _now: Instant) {
        for snap in &state.flows {
            let idx = self.select_shard(&snap.key);
            if let Some(shard) = self.shards.get_mut(idx) {
                shard.import_snapshot(snap);
            }
        }
        if let Some(shard) = self.shards.first_mut() {
            shard.stats.packets = shard.stats.packets.max(state.stats.packets);
            shard.stats.new_flows = shard.stats.new_flows.max(state.stats.new_flows);
            shard.stats.evicted = shard.stats.evicted.max(state.stats.evicted);
        }
    }

    pub fn reap_expired(&mut self, now: Instant) -> usize {
        let mut removed = 0usize;
        for shard in &mut self.shards {
            removed += shard.reap_expired(now, &self.timeouts);
        }
        removed
    }

    pub fn take_last_evicted(&mut self) -> Option<FlowKey> {
        self.last_evicted.take()
    }

    fn select_shard(&self, key: &FlowKey) -> usize {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len().max(1)
    }

    fn rebuild(&mut self, new_capacity: usize, new_shards: usize) {
        let snapshots = self.snapshot();
        let aggregated = self.stats();
        let mut rebuilt = FlowTable::with_shards(new_capacity, new_shards);
        for snap in &snapshots {
            let idx = rebuilt.select_shard(&snap.key);
            if let Some(shard) = rebuilt.shards.get_mut(idx) {
                shard.import_snapshot(snap);
            }
        }
        if let Some(shard) = rebuilt.shards.first_mut() {
            shard.stats = aggregated;
        }
        self.capacity = rebuilt.capacity;
        self.shards = rebuilt.shards;
        self.timeouts = rebuilt.timeouts;
        self.last_evicted = None;
    }
}

fn shard_count(capacity: usize, requested: usize) -> usize {
    let requested = requested.max(1);
    requested.min(capacity.max(1))
}

fn shard_capacity(total: usize, shards: usize, idx: usize) -> usize {
    let base = total / shards;
    let rem = total % shards;
    base + if idx < rem { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApplicationType, Direction, PacketMetadata};
    use packet_parser::IpProtocol;

    fn meta() -> PacketMetadata {
        PacketMetadata {
            direction: Direction::Ingress,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            protocol: IpProtocol::Tcp,
            src_port: Some(1234),
            dst_port: Some(443),
            seq_number: None,
            tcp_flags: None,
            application: ApplicationType::Unknown,
            payload: Vec::new(),
            signatures: Vec::new(),
            user: None,
            geo: None,
            tls: None,
        }
    }

    #[test]
    fn observe_on_shard_uses_explicit_index() {
        let mut table = FlowTable::with_shards(8, 2);
        let meta = meta();
        let key = FlowKey::from_metadata(&meta);
        table.observe_on_shard(1, &meta, Instant::now()).unwrap();
        assert!(table.shards[1].contains(&key));
        assert!(!table.shards[0].contains(&key));
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

fn is_expired(
    state: FlowState,
    last_seen: Instant,
    now: Instant,
    timeouts: &FlowTimeouts,
) -> bool {
    now.duration_since(last_seen) > timeout_for(state, timeouts)
}

fn timeout_for(state: FlowState, timeouts: &FlowTimeouts) -> Duration {
    match state {
        FlowState::New | FlowState::SynSent | FlowState::SynReceived => timeouts.handshake_timeout,
        FlowState::Established => timeouts.established_timeout,
        FlowState::FinWait => Duration::from_secs(60),
        FlowState::Closed => timeouts.closed_timeout,
    }
}
