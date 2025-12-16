#![forbid(unsafe_code)]

use crate::{BehaviorAlert, BehaviorKind, PacketMetadata};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ThreatIntel {
    pub(crate) bad_ips: HashSet<IpAddr>,
    pub(crate) bad_domains: HashSet<String>,
    pub(crate) updated_at: Option<Instant>,
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
