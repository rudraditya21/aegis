#![forbid(unsafe_code)]

use std::fmt;
use std::time::SystemTime;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "pcap")]
mod pcap;

#[cfg(feature = "pcap")]
pub use pcap::{PcapDataplane, PcapFrame};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum BackendKind {
    Pcap,
    AfXdp,
    Dpdk,
}

impl Default for BackendKind {
    fn default() -> Self {
        BackendKind::Pcap
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case"))]
pub struct DataplaneConfig {
    pub backend: BackendKind,
    pub pcap: Option<PcapConfig>,
    pub af_xdp: Option<AfXdpConfig>,
    pub dpdk: Option<DpdkConfig>,
    pub rss: Option<RssConfig>,
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        DataplaneConfig {
            backend: BackendKind::Pcap,
            pcap: Some(PcapConfig::default()),
            af_xdp: None,
            dpdk: None,
            rss: None,
        }
    }
}

impl DataplaneConfig {
    pub fn pcap_config(&self) -> PcapConfig {
        self.pcap.clone().unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case"))]
pub struct PcapConfig {
    pub snaplen: i32,
    pub promisc: bool,
    pub timeout_ms: i32,
    pub filter: Option<String>,
}

impl Default for PcapConfig {
    fn default() -> Self {
        PcapConfig {
            snaplen: 65535,
            promisc: true,
            timeout_ms: 1_000,
            filter: None,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case"))]
pub struct AfXdpConfig {
    pub queue: Option<u32>,
    pub umem_frames: usize,
    pub frame_size: usize,
    pub headroom: usize,
    pub use_need_wakeup: bool,
}

impl Default for AfXdpConfig {
    fn default() -> Self {
        AfXdpConfig {
            queue: None,
            umem_frames: 4096,
            frame_size: 2048,
            headroom: 256,
            use_need_wakeup: false,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case"))]
pub struct DpdkConfig {
    pub port_id: Option<u16>,
    pub rx_queues: u16,
    pub tx_queues: u16,
    pub mbuf_count: usize,
    pub mbuf_cache: usize,
    pub socket_id: Option<u16>,
    pub core_mask: Option<String>,
}

impl Default for DpdkConfig {
    fn default() -> Self {
        DpdkConfig {
            port_id: None,
            rx_queues: 1,
            tx_queues: 1,
            mbuf_count: 8192,
            mbuf_cache: 256,
            socket_id: None,
            core_mask: None,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case"))]
pub struct RssConfig {
    pub enabled: bool,
    pub symmetric: bool,
    pub hash_fields: Vec<RssHashField>,
    pub seed: Option<u64>,
    pub queues: Option<Vec<u16>>,
}

impl Default for RssConfig {
    fn default() -> Self {
        RssConfig {
            enabled: true,
            symmetric: false,
            hash_fields: vec![
                RssHashField::Ipv4,
                RssHashField::Ipv6,
                RssHashField::Tcp,
                RssHashField::Udp,
            ],
            seed: None,
            queues: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum RssHashField {
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataplaneStats {
    pub received: u64,
    pub dropped: u64,
    pub if_dropped: u64,
    pub transmitted: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct DataplaneCapabilities {
    pub supports_zero_copy_rx: bool,
    pub supports_zero_copy_tx: bool,
    pub supports_rss: bool,
    pub supports_tx: bool,
    pub supports_filters: bool,
}

#[derive(Debug)]
pub enum DataplaneError {
    Unsupported(&'static str),
    Backend(String),
    Config(String),
}

impl fmt::Display for DataplaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataplaneError::Unsupported(msg) => write!(f, "unsupported: {msg}"),
            DataplaneError::Backend(msg) => write!(f, "{msg}"),
            DataplaneError::Config(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for DataplaneError {}

pub trait FrameView {
    fn bytes(&self) -> &[u8];
    fn timestamp(&self) -> Option<SystemTime>;
}

pub trait Dataplane {
    type Frame<'a>: FrameView
    where
        Self: 'a;

    fn next_frame(&mut self) -> Result<Option<Self::Frame<'_>>, DataplaneError>;
    fn send_frame(&mut self, frame: &Self::Frame<'_>) -> Result<(), DataplaneError>;
    fn stats(&mut self) -> Result<DataplaneStats, DataplaneError>;
    fn configure_rss(&mut self, rss: &RssConfig) -> Result<(), DataplaneError>;
    fn capabilities(&self) -> DataplaneCapabilities;
}

#[derive(Debug)]
pub enum DataplaneHandle {
    #[cfg(feature = "pcap")]
    Pcap(PcapDataplane),
}

#[derive(Debug)]
pub enum AnyFrame<'a> {
    #[cfg(feature = "pcap")]
    Pcap(PcapFrame<'a>),
}

impl FrameView for AnyFrame<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "pcap")]
            AnyFrame::Pcap(frame) => frame.bytes(),
        }
    }

    fn timestamp(&self) -> Option<SystemTime> {
        match self {
            #[cfg(feature = "pcap")]
            AnyFrame::Pcap(frame) => frame.timestamp(),
        }
    }
}

impl DataplaneHandle {
    pub fn open_live(iface: &str, cfg: &DataplaneConfig) -> Result<Self, DataplaneError> {
        match cfg.backend {
            BackendKind::Pcap => {
                #[cfg(feature = "pcap")]
                {
                    let pcap_cfg = cfg.pcap_config();
                    let mut dp = PcapDataplane::open_live(iface, &pcap_cfg)?;
                    if let Some(filter) = &pcap_cfg.filter {
                        dp.set_filter(filter)?;
                    }
                    return Ok(DataplaneHandle::Pcap(dp));
                }
                #[cfg(not(feature = "pcap"))]
                {
                    let _ = iface;
                    Err(DataplaneError::Unsupported(
                        "pcap backend not built (enable feature pcap)",
                    ))
                }
            }
            BackendKind::AfXdp => Err(DataplaneError::Unsupported(
                if cfg!(target_os = "linux") {
                    "af-xdp backend not built (enable feature af-xdp)"
                } else {
                    "af-xdp backend only supported on linux"
                },
            )),
            BackendKind::Dpdk => Err(DataplaneError::Unsupported(
                if cfg!(target_os = "linux") {
                    "dpdk backend not built (enable feature dpdk)"
                } else {
                    "dpdk backend only supported on linux"
                },
            )),
        }
    }
}

impl Dataplane for DataplaneHandle {
    type Frame<'a> = AnyFrame<'a>;

    fn next_frame(&mut self) -> Result<Option<Self::Frame<'_>>, DataplaneError> {
        match self {
            #[cfg(feature = "pcap")]
            DataplaneHandle::Pcap(dp) => dp
                .next_frame()
                .map(|opt| opt.map(AnyFrame::Pcap)),
        }
    }

    fn send_frame(&mut self, frame: &Self::Frame<'_>) -> Result<(), DataplaneError> {
        match self {
            #[cfg(feature = "pcap")]
            DataplaneHandle::Pcap(dp) => match frame {
                AnyFrame::Pcap(frame) => dp.send_frame(frame),
            },
        }
    }

    fn stats(&mut self) -> Result<DataplaneStats, DataplaneError> {
        match self {
            #[cfg(feature = "pcap")]
            DataplaneHandle::Pcap(dp) => dp.stats(),
        }
    }

    fn configure_rss(&mut self, rss: &RssConfig) -> Result<(), DataplaneError> {
        match self {
            #[cfg(feature = "pcap")]
            DataplaneHandle::Pcap(dp) => dp.configure_rss(rss),
        }
    }

    fn capabilities(&self) -> DataplaneCapabilities {
        match self {
            #[cfg(feature = "pcap")]
            DataplaneHandle::Pcap(dp) => dp.capabilities(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_pcap_backend() {
        let cfg = DataplaneConfig::default();
        assert_eq!(cfg.backend, BackendKind::Pcap);
        assert!(cfg.pcap.is_some());
    }

    #[test]
    fn pcap_config_falls_back_to_default() {
        let mut cfg = DataplaneConfig::default();
        cfg.pcap = None;
        let pcap = cfg.pcap_config();
        assert_eq!(pcap.snaplen, 65535);
        assert!(pcap.promisc);
        assert_eq!(pcap.timeout_ms, 1_000);
    }

    #[test]
    fn rss_defaults_cover_common_fields() {
        let rss = RssConfig::default();
        assert!(rss.enabled);
        assert!(rss.hash_fields.contains(&RssHashField::Ipv4));
        assert!(rss.hash_fields.contains(&RssHashField::Tcp));
    }

    #[test]
    fn unsupported_backend_reports_error() {
        let mut cfg = DataplaneConfig::default();
        cfg.backend = BackendKind::AfXdp;
        let err = DataplaneHandle::open_live("eth0", &cfg).unwrap_err();
        match err {
            DataplaneError::Unsupported(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
