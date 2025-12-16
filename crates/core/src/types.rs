#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::time::Instant;

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
