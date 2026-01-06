#![allow(unsafe_code)]

#[derive(Debug, Clone)]
pub struct DpdkConfig {
    pub port_id: Option<u16>,
    pub rx_queue: Option<u16>,
    pub tx_queue: Option<u16>,
    pub rx_queues: u16,
    pub tx_queues: u16,
    pub mbuf_count: usize,
    pub mbuf_cache: usize,
    pub socket_id: Option<i32>,
    pub queue_sockets: Option<Vec<i32>>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpdkRssHashField {
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct DpdkRssConfig {
    pub enabled: bool,
    pub symmetric: bool,
    pub hash_fields: Vec<DpdkRssHashField>,
    pub seed: Option<u64>,
    pub queues: Option<Vec<u16>>,
}

impl Default for DpdkRssConfig {
    fn default() -> Self {
        DpdkRssConfig {
            enabled: true,
            symmetric: false,
            hash_fields: vec![
                DpdkRssHashField::Ipv4,
                DpdkRssHashField::Ipv6,
                DpdkRssHashField::Tcp,
                DpdkRssHashField::Udp,
            ],
            seed: None,
            queues: None,
        }
    }
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

#[derive(Debug)]
pub enum DpdkError {
    Unsupported(&'static str),
    Backend(String),
    Config(String),
}

impl std::fmt::Display for DpdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DpdkError::Unsupported(msg) => write!(f, "unsupported: {msg}"),
            DpdkError::Backend(msg) => write!(f, "{msg}"),
            DpdkError::Config(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for DpdkError {}

#[derive(Debug, Clone, Copy, Default)]
pub struct DpdkStats {
    pub rx: u64,
    pub tx: u64,
    pub rx_dropped: u64,
    pub imissed: u64,
    pub hugepages: bool,
    pub mempool_socket: Option<i32>,
    pub port_socket: Option<i32>,
}

#[cfg(any(test, all(feature = "dpdk", target_os = "linux")))]
const RSS_FIELD_IPV4: u32 = 1 << 0;
#[cfg(any(test, all(feature = "dpdk", target_os = "linux")))]
const RSS_FIELD_IPV6: u32 = 1 << 1;
#[cfg(any(test, all(feature = "dpdk", target_os = "linux")))]
const RSS_FIELD_TCP: u32 = 1 << 2;
#[cfg(any(test, all(feature = "dpdk", target_os = "linux")))]
const RSS_FIELD_UDP: u32 = 1 << 3;
#[cfg(any(test, all(feature = "dpdk", target_os = "linux")))]
const DEFAULT_RSS_KEY_LEN: usize = 40;

#[cfg(any(test, all(feature = "dpdk", target_os = "linux")))]
fn rss_fields_mask(fields: &[DpdkRssHashField]) -> u32 {
    let mut mask = 0u32;
    for field in fields {
        mask |= match field {
            DpdkRssHashField::Ipv4 => RSS_FIELD_IPV4,
            DpdkRssHashField::Ipv6 => RSS_FIELD_IPV6,
            DpdkRssHashField::Tcp => RSS_FIELD_TCP,
            DpdkRssHashField::Udp => RSS_FIELD_UDP,
        };
    }
    mask
}

#[cfg(any(test, all(feature = "dpdk", target_os = "linux")))]
fn build_rss_key(seed: Option<u64>, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = seed.unwrap_or(0x6a09e667f3bcc909);
    while out.len() < len {
        state = splitmix64(state);
        for byte in state.to_le_bytes() {
            if out.len() == len {
                break;
            }
            out.push(byte);
        }
    }
    out
}

#[cfg(any(test, all(feature = "dpdk", target_os = "linux")))]
fn splitmix64(mut state: u64) -> u64 {
    state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

#[cfg(not(all(feature = "dpdk", target_os = "linux")))]
mod stub {
    use super::{DpdkConfig, DpdkError, DpdkRssConfig, DpdkStats};

    #[derive(Debug)]
    pub struct DpdkDataplane;

    #[derive(Debug)]
    pub struct DpdkFrame<'a> {
        data: &'a [u8],
    }

    impl DpdkFrame<'_> {
        pub fn bytes(&self) -> &[u8] {
            self.data
        }

        pub fn mark_sent(&self) {}
    }

    impl DpdkDataplane {
        pub fn open(_iface: &str, _cfg: &DpdkConfig) -> Result<Self, DpdkError> {
            Err(DpdkError::Unsupported("dpdk not enabled"))
        }

        pub fn next_frame(&mut self) -> Result<Option<DpdkFrame<'_>>, DpdkError> {
            Err(DpdkError::Unsupported("dpdk not enabled"))
        }

        pub fn send_frame(&mut self, _frame: &DpdkFrame<'_>) -> Result<(), DpdkError> {
            Err(DpdkError::Unsupported("dpdk not enabled"))
        }

        pub fn stats(&mut self) -> Result<DpdkStats, DpdkError> {
            Err(DpdkError::Unsupported("dpdk not enabled"))
        }

        pub fn configure_rss(&mut self, _cfg: &DpdkRssConfig) -> Result<(), DpdkError> {
            Err(DpdkError::Unsupported("dpdk not enabled"))
        }

        pub fn rx_count(&self) -> u64 {
            0
        }

        pub fn tx_count(&self) -> u64 {
            0
        }
    }
}

#[cfg(not(all(feature = "dpdk", target_os = "linux")))]
pub use stub::{DpdkDataplane, DpdkFrame};

#[cfg(all(feature = "dpdk", target_os = "linux"))]
mod linux {
    use super::{build_rss_key, rss_fields_mask, DpdkConfig, DpdkError, DpdkRssConfig};
    use libc::{c_char, c_int, c_uint};
    use std::cell::Cell;
    use std::ffi::CString;
    use std::fs;
    use std::marker::PhantomData;
    use std::ptr;
    use std::sync::OnceLock;

    const SOCKET_ID_ANY: c_int = -1;

    #[repr(C)]
    pub struct rte_mbuf {
        _private: [u8; 0],
    }

    #[repr(C)]
    pub struct rte_mempool {
        _private: [u8; 0],
    }

    use super::DpdkStats;

    #[repr(C)]
    struct ShimStats {
        rx: u64,
        tx: u64,
        rx_dropped: u64,
        imissed: u64,
    }

    #[repr(C)]
    struct ShimRssInfo {
        hash_key_size: u32,
        reta_size: u16,
        _pad: u16,
        rss_offload: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct PortConfig {
        port_id: u16,
        rx_queues: u16,
        tx_queues: u16,
        rx_desc: u16,
        tx_desc: u16,
        promisc: bool,
        mbuf_count: usize,
        mbuf_cache: usize,
        queue_sockets: Vec<c_int>,
    }

    #[derive(Debug)]
    struct PortState {
        config: PortConfig,
        mempools: Vec<*mut rte_mempool>,
        port_socket: Option<c_int>,
        hugepages: bool,
    }

    // DPDK mempool pointers are thread-safe; PortState is immutable after init.
    unsafe impl Send for PortState {}
    unsafe impl Sync for PortState {}

    #[derive(Debug)]
    struct EalState {
        args: Vec<String>,
        hugepages: bool,
    }

    static PORT_STATE: OnceLock<PortState> = OnceLock::new();
    static EAL_STATE: OnceLock<EalState> = OnceLock::new();

    #[derive(Debug, Clone, Copy)]
    struct HugepageInfo {
        total: u64,
        free: u64,
        size_kb: usize,
    }

    fn hugepage_info() -> Option<HugepageInfo> {
        let body = fs::read_to_string("/proc/meminfo").ok()?;
        let mut total = None;
        let mut free = None;
        let mut size_kb = None;
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("HugePages_Total:") {
                total = rest.split_whitespace().next().and_then(|v| v.parse().ok());
            } else if let Some(rest) = line.strip_prefix("HugePages_Free:") {
                free = rest.split_whitespace().next().and_then(|v| v.parse().ok());
            } else if let Some(rest) = line.strip_prefix("Hugepagesize:") {
                size_kb = rest.split_whitespace().next().and_then(|v| v.parse().ok());
            }
        }
        match (total, free, size_kb) {
            (Some(total), Some(free), Some(size_kb)) => Some(HugepageInfo {
                total,
                free,
                size_kb,
            }),
            _ => None,
        }
    }

    unsafe extern "C" {
        fn rte_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
        fn rte_socket_id() -> c_int;
        fn rte_eth_dev_count_avail() -> u16;
        fn rte_eth_dev_socket_id(port_id: u16) -> c_int;
        fn rte_eth_dev_start(port_id: u16) -> c_int;
        fn rte_eth_promiscuous_enable(port_id: u16);
        fn rte_eth_rx_burst(
            port_id: u16,
            queue_id: u16,
            rx_pkts: *mut *mut rte_mbuf,
            nb_pkts: u16,
        ) -> u16;
        fn rte_eth_tx_burst(
            port_id: u16,
            queue_id: u16,
            tx_pkts: *mut *mut rte_mbuf,
            nb_pkts: u16,
        ) -> u16;
        fn rte_pktmbuf_pool_create(
            name: *const c_char,
            n: c_uint,
            cache_size: c_uint,
            priv_size: u16,
            data_room_size: u16,
            socket_id: c_int,
        ) -> *mut rte_mempool;
        fn rte_pktmbuf_free(m: *mut rte_mbuf);
        fn rte_strerror(errnum: c_int) -> *const c_char;
    }

    unsafe extern "C" {
        fn aegis_dpdk_port_configure(port_id: u16, rxq: u16, txq: u16) -> c_int;
        fn aegis_dpdk_rx_queue_setup(
            port_id: u16,
            qid: u16,
            desc: u16,
            socket_id: c_int,
            pool: *mut rte_mempool,
        ) -> c_int;
        fn aegis_dpdk_tx_queue_setup(
            port_id: u16,
            qid: u16,
            desc: u16,
            socket_id: c_int,
        ) -> c_int;
        fn aegis_dpdk_mbuf_data(m: *const rte_mbuf) -> *const u8;
        fn aegis_dpdk_mbuf_data_len(m: *const rte_mbuf) -> u16;
        fn aegis_dpdk_mbuf_write(m: *mut rte_mbuf, data: *const u8, len: u16) -> c_int;
        fn aegis_dpdk_stats_get(port_id: u16, out: *mut ShimStats) -> c_int;
        fn aegis_dpdk_port_by_name(name: *const c_char, out_port: *mut u16) -> c_int;
        fn aegis_dpdk_rss_info(port_id: u16, out: *mut ShimRssInfo) -> c_int;
        fn aegis_dpdk_rss_configure(
            port_id: u16,
            fields_mask: c_uint,
            symmetric: c_int,
            key: *const u8,
            key_len: c_uint,
            queues: *const u16,
            queue_len: u16,
        ) -> c_int;
        fn aegis_dpdk_errno() -> c_int;
    }

    #[derive(Debug)]
    pub struct DpdkFrame<'a> {
        mbuf: *mut rte_mbuf,
        data: *const u8,
        len: usize,
        sent: Cell<bool>,
        _marker: PhantomData<&'a ()>,
    }

    impl DpdkFrame<'_> {
        pub fn bytes(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.data, self.len) }
        }

        pub fn mark_sent(&self) {
            self.sent.set(true);
        }
    }

    impl Drop for DpdkFrame<'_> {
        fn drop(&mut self) {
            if !self.sent.get() {
                unsafe { rte_pktmbuf_free(self.mbuf) };
            }
        }
    }

    #[derive(Debug)]
    pub struct DpdkDataplane {
        port_id: u16,
        rx_queue: u16,
        tx_queue: u16,
        rx_queues: u16,
        tx_queues: u16,
        mempool: *mut rte_mempool,
        mempool_socket: Option<i32>,
        port_socket: Option<i32>,
        hugepages: bool,
        rx_cache: Vec<*mut rte_mbuf>,
        rx_buf: Vec<*mut rte_mbuf>,
        tx_buf: Vec<*mut rte_mbuf>,
        rx_burst: u16,
        tx_burst: u16,
        rx_count: u64,
        tx_count: u64,
    }

    impl DpdkDataplane {
        pub fn open(iface: &str, cfg: &DpdkConfig) -> Result<Self, DpdkError> {
            if cfg.rx_queues == 0 || cfg.tx_queues == 0 {
                return Err(DpdkError::Config("rx/tx queues must be > 0".into()));
            }
            if cfg.rx_desc == 0 || cfg.tx_desc == 0 {
                return Err(DpdkError::Config("rx/tx descriptors must be > 0".into()));
            }
            if cfg.mem_channels == 0 {
                return Err(DpdkError::Config("mem_channels must be > 0".into()));
            }
            if cfg.mbuf_count == 0 {
                return Err(DpdkError::Config("mbuf_count must be > 0".into()));
            }
            let hugepages = init_eal(cfg)?;

            let port_id = if let Some(pid) = cfg.port_id {
                pid
            } else if !iface.is_empty() {
                let mut pid = 0u16;
                let ciface = CString::new(iface)
                    .map_err(|_| DpdkError::Config("invalid iface".into()))?;
                let rc = unsafe { aegis_dpdk_port_by_name(ciface.as_ptr(), &mut pid) };
                if rc == 0 {
                    pid
                } else {
                    0
                }
            } else {
                0
            };

            let avail = unsafe { rte_eth_dev_count_avail() };
            if avail == 0 {
                return Err(DpdkError::Backend("no DPDK ports available".into()));
            }
            if port_id >= avail {
                return Err(DpdkError::Config("port_id out of range".into()));
            }

            let port_state = init_port(cfg, port_id, hugepages)?;
            let rx_queue = cfg.rx_queue.unwrap_or(0);
            let tx_queue = cfg.tx_queue.unwrap_or(rx_queue);
            if rx_queue >= port_state.config.rx_queues {
                return Err(DpdkError::Config("rx_queue out of range".into()));
            }
            if tx_queue >= port_state.config.tx_queues {
                return Err(DpdkError::Config("tx_queue out of range".into()));
            }
            let mempool_socket = port_state
                .config
                .queue_sockets
                .get(rx_queue as usize)
                .copied()
                .and_then(normalize_socket_id);
            let port_socket = port_state.port_socket.map(|v| v as i32);
            let mbuf_pool = *port_state
                .mempools
                .get(rx_queue as usize)
                .ok_or_else(|| DpdkError::Config("mempool missing for rx_queue".into()))?;

            let rx_burst = cfg.rx_burst.max(1);
            let tx_burst = cfg.tx_burst.max(1);

            Ok(DpdkDataplane {
                port_id,
                rx_queue,
                tx_queue,
                rx_queues: port_state.config.rx_queues,
                tx_queues: port_state.config.tx_queues,
                mempool: mbuf_pool,
                mempool_socket,
                port_socket,
                hugepages: port_state.hugepages,
                rx_cache: Vec::with_capacity(rx_burst as usize),
                rx_buf: vec![ptr::null_mut(); rx_burst as usize],
                tx_buf: vec![ptr::null_mut(); 1],
                rx_burst,
                tx_burst,
                rx_count: 0,
                tx_count: 0,
            })
        }

        pub fn next_frame(&mut self) -> Result<Option<DpdkFrame<'_>>, DpdkError> {
            if let Some(mbuf) = self.rx_cache.pop() {
                return Ok(Some(self.wrap_mbuf(mbuf)));
            }

            let nb = unsafe {
                rte_eth_rx_burst(
                    self.port_id,
                    self.rx_queue,
                    self.rx_buf.as_mut_ptr(),
                    self.rx_burst,
                )
            };
            if nb == 0 {
                return Ok(None);
            }
            let mut first = None;
            for i in 0..nb {
                let mbuf = self.rx_buf[i as usize];
                if i == 0 {
                    first = Some(mbuf);
                } else {
                    self.rx_cache.push(mbuf);
                }
            }
            Ok(first.map(|mbuf| self.wrap_mbuf(mbuf)))
        }

        pub fn send_frame(&mut self, frame: &DpdkFrame<'_>) -> Result<(), DpdkError> {
            let mbuf = frame.mbuf;
            self.tx_buf[0] = mbuf;
            let sent = unsafe {
                rte_eth_tx_burst(self.port_id, self.tx_queue, self.tx_buf.as_mut_ptr(), 1)
            };
            if sent == 1 {
                frame.mark_sent();
                self.tx_count = self.tx_count.wrapping_add(1);
                Ok(())
            } else {
                Err(DpdkError::Backend("tx burst dropped".into()))
            }
        }

        pub fn send_bytes(&mut self, data: &[u8]) -> Result<(), DpdkError> {
            let mbuf = allocate_mbuf(self.mempool, data.len())?;
            let rc = unsafe { aegis_dpdk_mbuf_write(mbuf, data.as_ptr(), data.len() as u16) };
            if rc != 0 {
                unsafe { rte_pktmbuf_free(mbuf) };
                return Err(DpdkError::Backend("mbuf write failed".into()));
            }
            let frame = DpdkFrame {
                mbuf,
                data: data.as_ptr(),
                len: data.len(),
                sent: Cell::new(false),
                _marker: PhantomData,
            };
            self.send_frame(&frame)
        }

        pub fn stats(&mut self) -> Result<DpdkStats, DpdkError> {
            let mut out = ShimStats {
                rx: 0,
                tx: 0,
                rx_dropped: 0,
                imissed: 0,
            };
            let rc = unsafe { aegis_dpdk_stats_get(self.port_id, &mut out) };
            if rc != 0 {
                return Err(dpdk_err("stats get"));
            }
            Ok(DpdkStats {
                rx: out.rx,
                tx: out.tx,
                rx_dropped: out.rx_dropped,
                imissed: out.imissed,
                hugepages: self.hugepages,
                mempool_socket: self.mempool_socket,
                port_socket: self.port_socket,
            })
        }

        pub fn configure_rss(&mut self, cfg: &DpdkRssConfig) -> Result<(), DpdkError> {
            if !cfg.enabled {
                return Ok(());
            }

            let mut info = ShimRssInfo {
                hash_key_size: 0,
                reta_size: 0,
                _pad: 0,
                rss_offload: 0,
            };
            let rc = unsafe { aegis_dpdk_rss_info(self.port_id, &mut info) };
            if rc != 0 {
                return Err(dpdk_err("rss info"));
            }
            if info.rss_offload == 0 {
                return Err(DpdkError::Config("rss offload not supported".into()));
            }

            let fields_mask = rss_fields_mask(&cfg.hash_fields);
            if fields_mask == 0 {
                return Err(DpdkError::Config("rss hash fields empty".into()));
            }

            let queues = match &cfg.queues {
                Some(list) if !list.is_empty() => list.clone(),
                _ => (0..self.rx_queues).collect(),
            };
            if queues.is_empty() {
                return Err(DpdkError::Config("rss queues empty".into()));
            }
            if queues.iter().any(|q| *q >= self.rx_queues) {
                return Err(DpdkError::Config("rss queue out of range".into()));
            }

            let key_len = if info.hash_key_size == 0 {
                super::DEFAULT_RSS_KEY_LEN
            } else {
                info.hash_key_size as usize
            };
            let key = build_rss_key(cfg.seed, key_len);

            let (queue_ptr, queue_len) = if info.reta_size == 0 {
                if queues.len() > 1 {
                    return Err(DpdkError::Config("rss reta not supported".into()));
                }
                (ptr::null(), 0u16)
            } else {
                (queues.as_ptr(), queues.len() as u16)
            };

            let rc = unsafe {
                aegis_dpdk_rss_configure(
                    self.port_id,
                    fields_mask,
                    if cfg.symmetric { 1 } else { 0 },
                    key.as_ptr(),
                    key.len() as c_uint,
                    queue_ptr,
                    queue_len,
                )
            };
            if rc != 0 {
                return Err(dpdk_err("rss configure"));
            }
            Ok(())
        }

        pub fn rx_count(&self) -> u64 {
            self.rx_count
        }

        pub fn tx_count(&self) -> u64 {
            self.tx_count
        }

        fn wrap_mbuf(&mut self, mbuf: *mut rte_mbuf) -> DpdkFrame<'_> {
            let data = unsafe { aegis_dpdk_mbuf_data(mbuf) };
            let len = unsafe { aegis_dpdk_mbuf_data_len(mbuf) } as usize;
            self.rx_count = self.rx_count.wrapping_add(1);
            DpdkFrame {
                mbuf,
                data,
                len,
                sent: Cell::new(false),
                _marker: PhantomData,
            }
        }
    }

    fn init_eal(cfg: &DpdkConfig) -> Result<bool, DpdkError> {
        let no_huge = effective_no_huge(cfg)?;
        let args = build_eal_args(cfg, no_huge);
        if let Some(existing) = EAL_STATE.get() {
            if existing.args != args {
                return Err(DpdkError::Config(
                    "dpdk already initialized with different args".into(),
                ));
            }
            return Ok(existing.hugepages);
        }
        let mut cstrings: Vec<CString> = args
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();
        let mut argv: Vec<*mut c_char> = cstrings
            .iter_mut()
            .map(|s| s.as_ptr() as *mut c_char)
            .collect();
        let rc = unsafe { rte_eal_init(argv.len() as c_int, argv.as_mut_ptr()) };
        if rc < 0 {
            return Err(dpdk_err("rte_eal_init"));
        }
        let hugepages = !no_huge;
        let _ = EAL_STATE.set(EalState { args, hugepages });
        Ok(hugepages)
    }

    fn init_port(
        cfg: &DpdkConfig,
        port_id: u16,
        hugepages: bool,
    ) -> Result<&'static PortState, DpdkError> {
        let (desired, port_socket) = desired_port_config(cfg, port_id)?;
        if let Some(state) = PORT_STATE.get() {
            if state.config != desired {
                return Err(DpdkError::Config(
                    "dpdk port already initialized with different config".into(),
                ));
            }
            if state.hugepages != hugepages {
                return Err(DpdkError::Config(
                    "dpdk already initialized with different hugepage mode".into(),
                ));
            }
            return Ok(state);
        }

        let config = desired.clone();
        let mut mempools = Vec::with_capacity(config.rx_queues as usize);
        for q in 0..config.rx_queues {
            let socket_id = *config
                .queue_sockets
                .get(q as usize)
                .unwrap_or(&SOCKET_ID_ANY);
            let pool = create_mempool(cfg, socket_id, port_id, q)?;
            mempools.push(pool);
        }

        let rc = unsafe { aegis_dpdk_port_configure(port_id, config.rx_queues, config.tx_queues) };
        if rc < 0 {
            return Err(dpdk_err("port configure"));
        }

        for q in 0..config.rx_queues {
            let pool = mempools[q as usize];
            let socket_id = *config
                .queue_sockets
                .get(q as usize)
                .unwrap_or(&SOCKET_ID_ANY);
            let rc = unsafe {
                aegis_dpdk_rx_queue_setup(port_id, q, config.rx_desc, socket_id, pool)
            };
            if rc < 0 {
                return Err(dpdk_err("rx queue setup"));
            }
        }

        for q in 0..config.tx_queues {
            let socket_id = *config
                .queue_sockets
                .get(q as usize)
                .unwrap_or(&SOCKET_ID_ANY);
            let rc = unsafe {
                aegis_dpdk_tx_queue_setup(port_id, q, config.tx_desc, socket_id)
            };
            if rc < 0 {
                return Err(dpdk_err("tx queue setup"));
            }
        }

        let rc = unsafe { rte_eth_dev_start(port_id) };
        if rc < 0 {
            return Err(dpdk_err("dev start"));
        }
        if config.promisc {
            unsafe { rte_eth_promiscuous_enable(port_id) };
        }

        let state = PortState {
            config,
            mempools,
            port_socket,
            hugepages,
        };
        if PORT_STATE.set(state).is_err() {
            let state = PORT_STATE.get().ok_or_else(|| {
                DpdkError::Backend("dpdk port initialization race".into())
            })?;
            if state.config != desired {
                return Err(DpdkError::Config(
                    "dpdk port already initialized with different config".into(),
                ));
            }
            if state.hugepages != hugepages {
                return Err(DpdkError::Config(
                    "dpdk already initialized with different hugepage mode".into(),
                ));
            }
        }
        PORT_STATE.get().ok_or_else(|| DpdkError::Backend("dpdk port init failed".into()))
    }

    fn build_eal_args(cfg: &DpdkConfig, no_huge: bool) -> Vec<String> {
        let mut args = vec!["aegis-dpdk".to_string()];
        if let Some(mask) = &cfg.core_mask {
            if mask.starts_with("0x") {
                args.push("-c".to_string());
                args.push(mask.clone());
            } else {
                args.push("-l".to_string());
                args.push(mask.clone());
            }
        } else {
            args.push("-l".to_string());
            args.push("0".to_string());
        }
        args.push("-n".to_string());
        args.push(cfg.mem_channels.to_string());
        if no_huge && !cfg.eal_args.iter().any(|arg| arg == "--no-huge") {
            args.push("--no-huge".to_string());
        }
        if let Some(prefix) = &cfg.file_prefix {
            args.push("--file-prefix".to_string());
            args.push(prefix.clone());
        }
        args.extend(cfg.eal_args.clone());
        args
    }

    fn effective_no_huge(cfg: &DpdkConfig) -> Result<bool, DpdkError> {
        if cfg.no_huge || cfg.eal_args.iter().any(|arg| arg == "--no-huge") {
            return Ok(true);
        }
        match hugepage_info() {
            Some(info) => {
                if info.total == 0 || info.free == 0 {
                    if cfg.hugepage_fallback {
                        Ok(true)
                    } else {
                        Err(DpdkError::Config(format!(
                            "hugepages unavailable (total={}, free={})",
                            info.total, info.free
                        )))
                    }
                } else {
                    Ok(false)
                }
            }
            None => {
                if cfg.hugepage_fallback {
                    Ok(true)
                } else {
                    Err(DpdkError::Config(
                        "hugepage info unavailable".into(),
                    ))
                }
            }
        }
    }

    fn resolve_queue_sockets(
        cfg: &DpdkConfig,
        port_socket: Option<c_int>,
        max_queues: u16,
    ) -> Result<Vec<c_int>, DpdkError> {
        let max_queues = max_queues.max(1) as usize;
        if let Some(socket_id) = cfg.socket_id {
            if socket_id < SOCKET_ID_ANY {
                return Err(DpdkError::Config(
                    "socket_id must be >= -1".into(),
                ));
            }
        }
        let default_socket = cfg
            .socket_id
            .or(port_socket)
            .unwrap_or_else(|| unsafe { rte_socket_id() });
        let default_socket = if default_socket < 0 {
            SOCKET_ID_ANY
        } else {
            default_socket
        };
        if let Some(list) = &cfg.queue_sockets {
            if list.is_empty() {
                return Err(DpdkError::Config("queue_sockets cannot be empty".into()));
            }
            for &socket_id in list {
                if socket_id < SOCKET_ID_ANY {
                    return Err(DpdkError::Config(
                        "queue_sockets must be >= -1".into(),
                    ));
                }
            }
            if list.len() == 1 {
                return Ok(vec![list[0]; max_queues]);
            }
            if list.len() != max_queues {
                return Err(DpdkError::Config(
                    "queue_sockets must have length 1 or match max queues".into(),
                ));
            }
            return Ok(list.clone());
        }
        Ok(vec![default_socket; max_queues])
    }

    fn port_socket_id(port_id: u16) -> Option<c_int> {
        let socket_id = unsafe { rte_eth_dev_socket_id(port_id) };
        if socket_id < 0 {
            None
        } else {
            Some(socket_id)
        }
    }

    fn normalize_socket_id(socket_id: c_int) -> Option<i32> {
        if socket_id < 0 {
            None
        } else {
            Some(socket_id as i32)
        }
    }

    fn create_mempool(
        cfg: &DpdkConfig,
        socket_id: c_int,
        port_id: u16,
        queue_id: u16,
    ) -> Result<*mut rte_mempool, DpdkError> {
        let name = format!("aegis_mbuf_pool_{port_id}_{queue_id}");
        let name = CString::new(name).map_err(|_| DpdkError::Config("invalid mempool name".into()))?;
        let data_room = 2048u16 + 128u16;
        let pool = unsafe {
            rte_pktmbuf_pool_create(
                name.as_ptr(),
                cfg.mbuf_count as c_uint,
                cfg.mbuf_cache as c_uint,
                0,
                data_room,
                socket_id,
            )
        };
        if pool.is_null() {
            return Err(dpdk_err("mbuf pool create"));
        }
        Ok(pool)
    }

    fn desired_port_config(
        cfg: &DpdkConfig,
        port_id: u16,
    ) -> Result<(PortConfig, Option<c_int>), DpdkError> {
        let port_socket = port_socket_id(port_id);
        let max_queues = cfg.rx_queues.max(cfg.tx_queues);
        let queue_sockets = resolve_queue_sockets(cfg, port_socket, max_queues)?;
        Ok((
            PortConfig {
                port_id,
                rx_queues: cfg.rx_queues,
                tx_queues: cfg.tx_queues,
                rx_desc: cfg.rx_desc,
                tx_desc: cfg.tx_desc,
                promisc: cfg.promisc,
                mbuf_count: cfg.mbuf_count,
                mbuf_cache: cfg.mbuf_cache,
                queue_sockets,
            },
            port_socket,
        ))
    }

    fn allocate_mbuf(pool: *mut rte_mempool, len: usize) -> Result<*mut rte_mbuf, DpdkError> {
        let _ = len;
        unsafe extern "C" {
            fn rte_pktmbuf_alloc(pool: *mut rte_mempool) -> *mut rte_mbuf;
        }
        let mbuf = unsafe { rte_pktmbuf_alloc(pool) };
        if mbuf.is_null() {
            return Err(DpdkError::Backend("mbuf alloc failed".into()));
        }
        Ok(mbuf)
    }

    fn dpdk_err(ctx: &str) -> DpdkError {
        let err = unsafe { aegis_dpdk_errno() };
        let msg = unsafe {
            let cstr = rte_strerror(err);
            if cstr.is_null() {
                format!("{ctx}: errno={err}")
            } else {
                let s = std::ffi::CStr::from_ptr(cstr);
                format!("{ctx}: {}", s.to_string_lossy())
            }
        };
        DpdkError::Backend(msg)
    }
}

#[cfg(all(feature = "dpdk", target_os = "linux"))]
pub use linux::{DpdkDataplane, DpdkFrame};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpdk_config_defaults_are_sane() {
        let cfg = DpdkConfig::default();
        assert!(cfg.rx_queue.is_none());
        assert!(cfg.tx_queue.is_none());
        assert_eq!(cfg.rx_queues, 1);
        assert_eq!(cfg.tx_queues, 1);
        assert_eq!(cfg.mem_channels, 4);
        assert!(!cfg.no_huge);
        assert!(cfg.hugepage_fallback);
        assert!(cfg.queue_sockets.is_none());
        assert!(cfg.promisc);
    }

    #[test]
    fn rss_fields_mask_combines_values() {
        let fields = vec![DpdkRssHashField::Ipv4, DpdkRssHashField::Tcp];
        let mask = rss_fields_mask(&fields);
        assert_ne!(mask & RSS_FIELD_IPV4, 0);
        assert_ne!(mask & RSS_FIELD_TCP, 0);
        assert_eq!(mask & RSS_FIELD_IPV6, 0);
    }

    #[test]
    fn rss_key_generation_is_deterministic() {
        let key_a = build_rss_key(Some(7), DEFAULT_RSS_KEY_LEN);
        let key_b = build_rss_key(Some(7), DEFAULT_RSS_KEY_LEN);
        let key_c = build_rss_key(Some(8), DEFAULT_RSS_KEY_LEN);
        assert_eq!(key_a, key_b);
        assert_ne!(key_a, key_c);
        assert_eq!(key_a.len(), DEFAULT_RSS_KEY_LEN);
    }
}
