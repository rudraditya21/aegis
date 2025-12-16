#![forbid(unsafe_code)]

use crate::{FlowOutcome, FlowState, PacketMetadata};
use packet_parser::IpProtocol;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CounterWindow {
    pub(crate) start: Instant,
    pub(crate) count: u64,
}

impl CounterWindow {
    pub fn new(start: Instant) -> Self {
        CounterWindow { start, count: 0 }
    }

    pub fn hit(&mut self, now: Instant, window: Duration) -> u64 {
        if now.duration_since(self.start) > window {
            self.start = now;
            self.count = 0;
        }
        self.count += 1;
        self.count
    }

    pub fn decay(&mut self, amount: u64) {
        if self.count >= amount {
            self.count -= amount;
        } else {
            self.count = 0;
        }
    }
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

        if meta.protocol == IpProtocol::Icmpv4 || meta.protocol == IpProtocol::Icmpv6 {
            let counter = self
                .icmp_counters
                .entry(meta.src_ip)
                .or_insert_with(|| CounterWindow::new(now));
            if counter.hit(now, self.icmp_window) > self.icmp_limit {
                return false;
            }
        }

        if meta.protocol == IpProtocol::Udp {
            if self.udp_total_counter.hit(now, self.udp_window) > self.udp_total_limit {
                return false;
            }
            let counter = self
                .udp_counters
                .entry(meta.src_ip)
                .or_insert_with(|| CounterWindow::new(now));
            if counter.hit(now, self.udp_window) > self.udp_limit {
                return false;
            }
            if let Some(dst) = meta.dst_port {
                let key = (meta.src_ip, dst);
                let counter = self
                    .udp_conn_counters
                    .entry(key)
                    .or_insert_with(|| CounterWindow::new(now));
                let per_port_limit = (self.udp_limit / 4).max(64);
                if counter.hit(now, self.udp_window) > per_port_limit {
                    return false;
                }
            }
        }

        true
    }
}
