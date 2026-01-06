#![forbid(unsafe_code)]

use std::fmt;
use std::time::SystemTime;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "pcap")]
mod pcap;

#[cfg(feature = "pcap")]
pub use pcap::{PcapDataplane, PcapFrame};

#[cfg(all(feature = "af-xdp", target_os = "linux"))]
mod af_xdp;

#[cfg(all(feature = "af-xdp", target_os = "linux"))]
pub use af_xdp::AfXdpDataplane;

#[cfg(all(feature = "dpdk", target_os = "linux"))]
mod dpdk;

#[cfg(all(feature = "dpdk", target_os = "linux"))]
pub use dpdk::DpdkDataplane;

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
    pub numa_node: Option<i32>,
    pub use_hugepages: bool,
    pub hugepage_size_kb: Option<usize>,
    pub hugepage_fallback: bool,
    pub numa_fallback: bool,
    pub xdp_program_pin: Option<String>,
    pub xsk_map_pin: Option<String>,
    pub pin_dir: Option<String>,
    pub program_name: Option<String>,
    pub map_name: Option<String>,
    pub xsk_map_entries: Option<u32>,
    pub attach: bool,
    pub mode: AfXdpMode,
    pub update_if_noexist: bool,
}

impl Default for AfXdpConfig {
    fn default() -> Self {
        AfXdpConfig {
            queue: None,
            umem_frames: 4096,
            frame_size: 2048,
            headroom: 256,
            use_need_wakeup: false,
            numa_node: None,
            use_hugepages: false,
            hugepage_size_kb: None,
            hugepage_fallback: true,
            numa_fallback: true,
            xdp_program_pin: None,
            xsk_map_pin: None,
            pin_dir: None,
            program_name: None,
            map_name: None,
            xsk_map_entries: None,
            attach: false,
            mode: AfXdpMode::Auto,
            update_if_noexist: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum AfXdpMode {
    Auto,
    Skb,
    Drv,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case"))]
pub struct DpdkConfig {
    pub port_id: Option<u16>,
    pub rx_queue: Option<u16>,
    pub tx_queue: Option<u16>,
    pub rx_queues: u16,
    pub tx_queues: u16,
    pub mbuf_count: usize,
    pub mbuf_cache: usize,
    pub socket_id: Option<u16>,
    pub queue_sockets: Option<Vec<u16>>,
    pub core_mask: Option<String>,
    pub mem_channels: u32,
    pub no_huge: bool,
    pub hugepage_fallback: bool,
    pub file_prefix: Option<String>,
    pub eal_args: Vec<String>,
    pub rx_desc: u16,
    pub tx_desc: u16,
    pub rx_burst: u16,
    pub tx_burst: u16,
    pub promisc: bool,
}

impl Default for DpdkConfig {
    fn default() -> Self {
        DpdkConfig {
            port_id: None,
            rx_queue: None,
            tx_queue: None,
            rx_queues: 1,
            tx_queues: 1,
            mbuf_count: 8192,
            mbuf_cache: 256,
            socket_id: None,
            queue_sockets: None,
            core_mask: None,
            mem_channels: 4,
            no_huge: false,
            hugepage_fallback: true,
            file_prefix: None,
            eal_args: Vec::new(),
            rx_desc: 1024,
            tx_desc: 1024,
            rx_burst: 32,
            tx_burst: 32,
            promisc: true,
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
    pub cpu_affinity: Option<Vec<usize>>,
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
            cpu_affinity: None,
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

/// Writable TX buffer that can be committed without extra copies.
pub trait TxLease {
    fn buffer(&mut self) -> &mut [u8];
    fn commit(self, len: usize) -> Result<(), DataplaneError>;
}

#[derive(Debug)]
pub struct UnsupportedTxLease {
    buf: [u8; 0],
}

impl TxLease for UnsupportedTxLease {
    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    fn commit(self, _len: usize) -> Result<(), DataplaneError> {
        Err(DataplaneError::Unsupported("tx lease not supported"))
    }
}

pub trait Dataplane {
    type Frame<'a>: FrameView
    where
        Self: 'a;
    type Tx<'a>: TxLease
    where
        Self: 'a;

    fn next_frame(&mut self) -> Result<Option<Self::Frame<'_>>, DataplaneError>;
    /// Lease a TX buffer for zero-copy writes when supported.
    fn lease_tx(&mut self, len: usize) -> Result<Self::Tx<'_>, DataplaneError>;
    fn send_frame(&mut self, frame: &Self::Frame<'_>) -> Result<(), DataplaneError>;
    fn send_bytes(&mut self, data: &[u8]) -> Result<(), DataplaneError> {
        let mut lease = self.lease_tx(data.len())?;
        let buf = lease.buffer();
        if buf.len() < data.len() {
            return Err(DataplaneError::Backend(
                "tx lease shorter than requested length".into(),
            ));
        }
        buf[..data.len()].copy_from_slice(data);
        lease.commit(data.len())
    }
    fn stats(&mut self) -> Result<DataplaneStats, DataplaneError>;
    fn configure_rss(&mut self, rss: &RssConfig) -> Result<(), DataplaneError>;
    fn capabilities(&self) -> DataplaneCapabilities;
}

#[derive(Debug)]
pub enum DataplaneHandle {
    #[cfg(feature = "pcap")]
    Pcap(PcapDataplane),
    #[cfg(all(feature = "af-xdp", target_os = "linux"))]
    AfXdp(AfXdpDataplane),
    #[cfg(all(feature = "dpdk", target_os = "linux"))]
    Dpdk(DpdkDataplane),
}

#[derive(Debug)]
pub enum AnyFrame<'a> {
    #[cfg(feature = "pcap")]
    Pcap(PcapFrame<'a>),
    #[cfg(all(feature = "af-xdp", target_os = "linux"))]
    AfXdp(af_xdp::AfXdpFrame<'a>),
    #[cfg(all(feature = "dpdk", target_os = "linux"))]
    Dpdk(dpdk::DpdkFrame<'a>),
}

impl FrameView for AnyFrame<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "pcap")]
            AnyFrame::Pcap(frame) => frame.bytes(),
            #[cfg(all(feature = "af-xdp", target_os = "linux"))]
            AnyFrame::AfXdp(frame) => frame.bytes(),
            #[cfg(all(feature = "dpdk", target_os = "linux"))]
            AnyFrame::Dpdk(frame) => frame.bytes(),
        }
    }

    fn timestamp(&self) -> Option<SystemTime> {
        match self {
            #[cfg(feature = "pcap")]
            AnyFrame::Pcap(frame) => frame.timestamp(),
            #[cfg(all(feature = "af-xdp", target_os = "linux"))]
            AnyFrame::AfXdp(frame) => frame.timestamp(),
            #[cfg(all(feature = "dpdk", target_os = "linux"))]
            AnyFrame::Dpdk(frame) => frame.timestamp(),
        }
    }
}

#[derive(Debug)]
pub enum AnyTxLease<'a> {
    #[cfg(all(feature = "af-xdp", target_os = "linux"))]
    AfXdp(af_xdp::AfXdpTxLease<'a>),
    #[cfg(all(feature = "dpdk", target_os = "linux"))]
    Dpdk(dpdk::DpdkTxLease<'a>),
    Unsupported(UnsupportedTxLease),
}

impl TxLease for AnyTxLease<'_> {
    fn buffer(&mut self) -> &mut [u8] {
        match self {
            #[cfg(all(feature = "af-xdp", target_os = "linux"))]
            AnyTxLease::AfXdp(lease) => TxLease::buffer(lease),
            #[cfg(all(feature = "dpdk", target_os = "linux"))]
            AnyTxLease::Dpdk(lease) => TxLease::buffer(lease),
            AnyTxLease::Unsupported(lease) => TxLease::buffer(lease),
        }
    }

    fn commit(self, len: usize) -> Result<(), DataplaneError> {
        match self {
            #[cfg(all(feature = "af-xdp", target_os = "linux"))]
            AnyTxLease::AfXdp(lease) => TxLease::commit(lease, len),
            #[cfg(all(feature = "dpdk", target_os = "linux"))]
            AnyTxLease::Dpdk(lease) => TxLease::commit(lease, len),
            AnyTxLease::Unsupported(lease) => TxLease::commit(lease, len),
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
            BackendKind::AfXdp => {
                #[cfg(all(feature = "af-xdp", target_os = "linux"))]
                {
                    let af_cfg = cfg.af_xdp.clone().unwrap_or_default();
                    let mut program_pin = af_cfg.xdp_program_pin.clone();
                    let mut map_pin = af_cfg.xsk_map_pin.clone();
                    if af_cfg.attach && program_pin.is_none() {
                        let pin_dir = af_cfg
                            .pin_dir
                            .clone()
                            .unwrap_or_else(|| "/sys/fs/bpf/aegis".to_string());
                        let program_name = af_cfg
                            .program_name
                            .clone()
                            .unwrap_or_else(|| format!("xdp_prog_{iface}"));
                        let map_name = af_cfg
                            .map_name
                            .clone()
                            .unwrap_or_else(|| format!("xsk_map_{iface}"));
                        let entries = af_cfg
                            .xsk_map_entries
                            .unwrap_or_else(|| af_cfg.queue.unwrap_or(0) + 1)
                            .max(1);
                        let pinned = aegis_af_xdp::ensure_pinned_xdp_program(
                            std::path::Path::new(&pin_dir),
                            &program_name,
                            &map_name,
                            entries,
                        )
                        .map_err(|e| DataplaneError::Backend(format!("af-xdp pin: {e}")))?;
                        program_pin = Some(pinned.program_pin.to_string_lossy().to_string());
                        map_pin = Some(pinned.map_pin.to_string_lossy().to_string());
                    }
                    let inner_cfg = aegis_af_xdp::AfXdpConfig {
                        queue: af_cfg.queue,
                        umem_frames: af_cfg.umem_frames,
                        frame_size: af_cfg.frame_size,
                        headroom: af_cfg.headroom,
                        use_need_wakeup: af_cfg.use_need_wakeup,
                        numa_node: af_cfg.numa_node,
                        use_hugepages: af_cfg.use_hugepages,
                        hugepage_size_kb: af_cfg.hugepage_size_kb,
                        hugepage_fallback: af_cfg.hugepage_fallback,
                        numa_fallback: af_cfg.numa_fallback,
                    };
                    let dp = AfXdpDataplane::open_live(iface, &inner_cfg).map_err(|e| {
                        DataplaneError::Backend(format!("af-xdp init: {e}"))
                    })?;
                    if let Some(map_pin) = map_pin.as_deref() {
                        dp.update_xsk_map(map_pin)
                            .map_err(|e| DataplaneError::Backend(format!("af-xdp map: {e}")))?;
                    }
                    if af_cfg.attach {
                        let prog_pin = program_pin.as_deref().ok_or_else(|| {
                            DataplaneError::Config(
                                "xdp_program_pin or pin_dir required when attach=true".into(),
                            )
                        })?;
                        let flags = crate::af_xdp::XdpAttachFlags {
                            mode: match af_cfg.mode {
                                AfXdpMode::Auto => crate::af_xdp::XdpAttachMode::Auto,
                                AfXdpMode::Skb => crate::af_xdp::XdpAttachMode::Skb,
                                AfXdpMode::Drv => crate::af_xdp::XdpAttachMode::Drv,
                            },
                            update_if_noexist: af_cfg.update_if_noexist,
                        };
                        dp.attach_xdp_program(prog_pin, flags)
                            .map_err(|e| DataplaneError::Backend(format!("af-xdp attach: {e}")))?;
                    }
                    return Ok(DataplaneHandle::AfXdp(dp));
                }
                #[cfg(not(all(feature = "af-xdp", target_os = "linux")))]
                {
                    let _ = iface;
                    Err(DataplaneError::Unsupported(
                        if cfg!(target_os = "linux") {
                            "af-xdp backend not built (enable feature af-xdp)"
                        } else {
                            "af-xdp backend only supported on linux"
                        },
                    ))
                }
            }
            BackendKind::Dpdk => {
                #[cfg(all(feature = "dpdk", target_os = "linux"))]
                {
                    let dpdk_cfg = cfg.dpdk.clone().unwrap_or_default();
                    let inner_cfg = aegis_dpdk::DpdkConfig {
                        port_id: dpdk_cfg.port_id,
                        rx_queue: dpdk_cfg.rx_queue,
                        tx_queue: dpdk_cfg.tx_queue,
                        rx_queues: dpdk_cfg.rx_queues,
                        tx_queues: dpdk_cfg.tx_queues,
                        mbuf_count: dpdk_cfg.mbuf_count,
                        mbuf_cache: dpdk_cfg.mbuf_cache,
                        socket_id: dpdk_cfg.socket_id.map(|v| v as i32),
                        queue_sockets: dpdk_cfg
                            .queue_sockets
                            .clone()
                            .map(|v| v.into_iter().map(|s| s as i32).collect()),
                        core_mask: dpdk_cfg.core_mask.clone(),
                        mem_channels: dpdk_cfg.mem_channels,
                        no_huge: dpdk_cfg.no_huge,
                        hugepage_fallback: dpdk_cfg.hugepage_fallback,
                        file_prefix: dpdk_cfg.file_prefix.clone(),
                        eal_args: dpdk_cfg.eal_args.clone(),
                        rx_desc: dpdk_cfg.rx_desc,
                        tx_desc: dpdk_cfg.tx_desc,
                        rx_burst: dpdk_cfg.rx_burst,
                        tx_burst: dpdk_cfg.tx_burst,
                        promisc: dpdk_cfg.promisc,
                    };
                    let dp = DpdkDataplane::open(iface, &inner_cfg)
                        .map_err(|e| DataplaneError::Backend(format!("dpdk init: {e}")))?;
                    return Ok(DataplaneHandle::Dpdk(dp));
                }
                #[cfg(not(all(feature = "dpdk", target_os = "linux")))]
                {
                    let _ = iface;
                    Err(DataplaneError::Unsupported(
                        if cfg!(target_os = "linux") {
                            "dpdk backend not built (enable feature dpdk)"
                        } else {
                            "dpdk backend only supported on linux"
                        },
                    ))
                }
            }
        }
    }
}

impl Dataplane for DataplaneHandle {
    type Frame<'a> = AnyFrame<'a>;
    type Tx<'a> = AnyTxLease<'a>;

    fn next_frame(&mut self) -> Result<Option<Self::Frame<'_>>, DataplaneError> {
        match self {
            #[cfg(feature = "pcap")]
            DataplaneHandle::Pcap(dp) => dp
                .next_frame()
                .map(|opt| opt.map(AnyFrame::Pcap)),
            #[cfg(all(feature = "af-xdp", target_os = "linux"))]
            DataplaneHandle::AfXdp(dp) => <AfXdpDataplane as Dataplane>::next_frame(dp)
                .map(|opt| opt.map(AnyFrame::AfXdp)),
            #[cfg(all(feature = "dpdk", target_os = "linux"))]
            DataplaneHandle::Dpdk(dp) => <DpdkDataplane as Dataplane>::next_frame(dp)
                .map(|opt| opt.map(AnyFrame::Dpdk)),
        }
    }

    fn lease_tx(&mut self, len: usize) -> Result<Self::Tx<'_>, DataplaneError> {
        match self {
            #[cfg(feature = "pcap")]
            DataplaneHandle::Pcap(_) => Err(DataplaneError::Unsupported(
                "pcap backend does not support tx leasing",
            )),
            #[cfg(all(feature = "af-xdp", target_os = "linux"))]
            DataplaneHandle::AfXdp(dp) => <AfXdpDataplane as Dataplane>::lease_tx(dp, len)
                .map(AnyTxLease::AfXdp),
            #[cfg(all(feature = "dpdk", target_os = "linux"))]
            DataplaneHandle::Dpdk(dp) => <DpdkDataplane as Dataplane>::lease_tx(dp, len)
                .map(AnyTxLease::Dpdk),
        }
    }

    fn send_frame(&mut self, frame: &Self::Frame<'_>) -> Result<(), DataplaneError> {
        match self {
            #[cfg(feature = "pcap")]
            DataplaneHandle::Pcap(dp) => match frame {
                AnyFrame::Pcap(frame) => dp.send_frame(frame),
                _ => Err(DataplaneError::Unsupported("frame type mismatch")),
            },
            #[cfg(all(feature = "af-xdp", target_os = "linux"))]
            DataplaneHandle::AfXdp(dp) => match frame {
                AnyFrame::AfXdp(frame) => <AfXdpDataplane as Dataplane>::send_frame(dp, frame),
                _ => Err(DataplaneError::Unsupported("frame type mismatch")),
            },
            #[cfg(all(feature = "dpdk", target_os = "linux"))]
            DataplaneHandle::Dpdk(dp) => match frame {
                AnyFrame::Dpdk(frame) => <DpdkDataplane as Dataplane>::send_frame(dp, frame),
                _ => Err(DataplaneError::Unsupported("frame type mismatch")),
            },
        }
    }

    fn stats(&mut self) -> Result<DataplaneStats, DataplaneError> {
        match self {
            #[cfg(feature = "pcap")]
            DataplaneHandle::Pcap(dp) => dp.stats(),
            #[cfg(all(feature = "af-xdp", target_os = "linux"))]
            DataplaneHandle::AfXdp(dp) => <AfXdpDataplane as Dataplane>::stats(dp),
            #[cfg(all(feature = "dpdk", target_os = "linux"))]
            DataplaneHandle::Dpdk(dp) => <DpdkDataplane as Dataplane>::stats(dp),
        }
    }

    fn configure_rss(&mut self, rss: &RssConfig) -> Result<(), DataplaneError> {
        match self {
            #[cfg(feature = "pcap")]
            DataplaneHandle::Pcap(dp) => dp.configure_rss(rss),
            #[cfg(all(feature = "af-xdp", target_os = "linux"))]
            DataplaneHandle::AfXdp(dp) => <AfXdpDataplane as Dataplane>::configure_rss(dp, rss),
            #[cfg(all(feature = "dpdk", target_os = "linux"))]
            DataplaneHandle::Dpdk(dp) => <DpdkDataplane as Dataplane>::configure_rss(dp, rss),
        }
    }

    fn capabilities(&self) -> DataplaneCapabilities {
        match self {
            #[cfg(feature = "pcap")]
            DataplaneHandle::Pcap(dp) => dp.capabilities(),
            #[cfg(all(feature = "af-xdp", target_os = "linux"))]
            DataplaneHandle::AfXdp(dp) => dp.capabilities(),
            #[cfg(all(feature = "dpdk", target_os = "linux"))]
            DataplaneHandle::Dpdk(dp) => dp.capabilities(),
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
        assert!(rss.cpu_affinity.is_none());
    }

    #[test]
    fn dpdk_defaults_cover_core_tuning() {
        let dpdk = DpdkConfig::default();
        assert_eq!(dpdk.mem_channels, 4);
        assert_eq!(dpdk.rx_desc, 1024);
        assert_eq!(dpdk.tx_desc, 1024);
        assert_eq!(dpdk.rx_burst, 32);
        assert_eq!(dpdk.tx_burst, 32);
        assert!(dpdk.promisc);
        assert!(dpdk.queue_sockets.is_none());
        assert!(dpdk.hugepage_fallback);
    }

    #[test]
    fn af_xdp_defaults_cover_numa_and_hugepages() {
        let cfg = AfXdpConfig::default();
        assert!(cfg.numa_node.is_none());
        assert!(!cfg.use_hugepages);
        assert!(cfg.hugepage_size_kb.is_none());
        assert!(cfg.hugepage_fallback);
        assert!(cfg.numa_fallback);
    }

    #[test]
    fn unsupported_backend_reports_error() {
        let mut cfg = DataplaneConfig::default();
        cfg.backend = BackendKind::AfXdp;
        let err = DataplaneHandle::open_live("eth0", &cfg).unwrap_err();
        match err {
            DataplaneError::Unsupported(_) => {}
            DataplaneError::Backend(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
