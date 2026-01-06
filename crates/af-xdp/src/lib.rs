#![allow(unsafe_code)]

#[derive(Debug, Clone)]
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
        }
    }
}

#[derive(Debug)]
pub enum AfXdpError {
    Unsupported(&'static str),
    Backend(String),
    Config(String),
}

impl std::fmt::Display for AfXdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AfXdpError::Unsupported(msg) => write!(f, "unsupported: {msg}"),
            AfXdpError::Backend(msg) => write!(f, "{msg}"),
            AfXdpError::Config(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for AfXdpError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AfXdpStats {
    pub rx_dropped: u64,
    pub rx_invalid_descs: u64,
    pub tx_invalid_descs: u64,
    pub rx_ring_full: u64,
    pub rx_fill_ring_empty: u64,
    pub tx_ring_empty: u64,
    pub umem_hugepages: bool,
    pub umem_numa_node: Option<i32>,
    pub umem_len: usize,
}

#[derive(Debug, Clone)]
pub struct PinnedXdp {
    pub program_pin: std::path::PathBuf,
    pub map_pin: std::path::PathBuf,
}

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::{AfXdpConfig, AfXdpError};

    #[derive(Debug)]
    pub struct AfXdpDataplane;

    #[derive(Debug)]
    pub struct AfXdpFrame<'a> {
        data: &'a [u8],
    }

    impl AfXdpFrame<'_> {
        pub fn bytes(&self) -> &[u8] {
            self.data
        }
    }


    #[derive(Debug, Clone, Copy)]
    pub enum XdpAttachMode {
        Auto,
        Skb,
        Drv,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct XdpAttachFlags {
        pub mode: XdpAttachMode,
        pub update_if_noexist: bool,
    }

    impl Default for XdpAttachFlags {
        fn default() -> Self {
            XdpAttachFlags {
                mode: XdpAttachMode::Auto,
                update_if_noexist: true,
            }
        }
    }

    impl AfXdpDataplane {
        pub fn open_live(_iface: &str, _cfg: &AfXdpConfig) -> Result<Self, AfXdpError> {
            Err(AfXdpError::Unsupported("af-xdp only supported on linux"))
        }

        pub fn next_frame(&mut self) -> Result<Option<AfXdpFrame<'_>>, AfXdpError> {
            Err(AfXdpError::Unsupported("af-xdp only supported on linux"))
        }

        pub fn send_frame(&mut self, _frame: &AfXdpFrame<'_>) -> Result<(), AfXdpError> {
            Err(AfXdpError::Unsupported("af-xdp only supported on linux"))
        }

        pub fn stats(&mut self) -> Result<super::AfXdpStats, AfXdpError> {
            Err(AfXdpError::Unsupported("af-xdp only supported on linux"))
        }

        pub fn rx_count(&self) -> u64 {
            0
        }

        pub fn tx_count(&self) -> u64 {
            0
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use stub::{AfXdpDataplane, AfXdpFrame, XdpAttachFlags, XdpAttachMode};

#[cfg(target_os = "linux")]
mod linux {
use super::{AfXdpConfig, AfXdpError, AfXdpStats, PinnedXdp};
use libc::{
    c_int, c_ulong, c_void, pollfd, sockaddr, socklen_t, AF_NETLINK, AF_XDP,
    MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, MSG_DONTWAIT,
    NETLINK_ROUTE, POLLIN, PROT_READ, PROT_WRITE, SOCK_RAW,
};
use std::ffi::CString;
use std::mem::{self, size_of};
use std::os::fd::RawFd;
use std::fs;
use std::ptr;
use std::slice;
use std::sync::atomic::{fence, Ordering};
use std::path::Path;

const XDP_UMEM_REG: c_int = 1;
const XDP_UMEM_FILL_RING: c_int = 4;
const XDP_UMEM_COMPLETION_RING: c_int = 5;
const XDP_RX_RING: c_int = 6;
const XDP_TX_RING: c_int = 7;
const XDP_MMAP_OFFSETS: c_int = 9;
const XDP_STATISTICS: c_int = 10;

const XDP_PGOFF_RX_RING: i64 = 0;
const XDP_PGOFF_TX_RING: i64 = 0x8000_0000;
const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x1_0000_0000;
const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x1_8000_0000;

const XDP_RING_NEED_WAKEUP: u32 = 1;

const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;
const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;

const BPF_OBJ_GET: u32 = 7;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_CREATE: u32 = 0;
const BPF_PROG_LOAD: u32 = 5;
const BPF_OBJ_PIN: u32 = 6;
const BPF_ANY: u64 = 0;

const BPF_PROG_TYPE_XDP: u32 = 6;
const BPF_MAP_TYPE_XSKMAP: u32 = 17;
const BPF_FUNC_REDIRECT_MAP: i32 = 51;

const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_ALU64: u8 = 0x07;
const BPF_JMP: u8 = 0x05;
const BPF_IMM: u8 = 0x00;
const BPF_DW: u8 = 0x18;
const BPF_MEM: u8 = 0x60;
const BPF_W: u8 = 0x00;
const BPF_MOV: u8 = 0xb0;
const BPF_K: u8 = 0x00;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;
const BPF_PSEUDO_MAP_FD: u8 = 1;
const XDP_MD_RX_QUEUE_INDEX: i16 = 16;

const IFLA_XDP: u16 = 43;
const IFLA_XDP_FD: u16 = 1;
const IFLA_XDP_FLAGS: u16 = 3;
const MPOL_BIND: c_int = 2;

#[derive(Debug, Clone, Copy)]
struct HugepageInfo {
    free: u64,
    size_kb: usize,
}

fn hugepage_info() -> Option<HugepageInfo> {
    let body = fs::read_to_string("/proc/meminfo").ok()?;
    let mut free = None;
    let mut size_kb = None;
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("HugePages_Free:") {
            free = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("Hugepagesize:") {
            size_kb = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }
    match (free, size_kb) {
        (Some(free), Some(size_kb)) => Some(HugepageInfo { free, size_kb }),
        _ => None,
    }
}

fn bind_memory(ptr: *mut c_void, len: usize, node: i32) -> Result<(), AfXdpError> {
    if node < 0 {
        return Err(AfXdpError::Config("numa_node must be >= 0".into()));
    }
    let bits = (size_of::<c_ulong>() * 8) as usize;
    let node = node as usize;
    let words = (node / bits) + 1;
    let mut mask = vec![0 as c_ulong; words];
    let idx = node / bits;
    let bit = node % bits;
    mask[idx] |= 1u64 << bit;
    let maxnode = (words * bits) as c_ulong;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mbind,
            ptr,
            len,
            MPOL_BIND,
            mask.as_ptr(),
            maxnode,
            0u32,
        )
    };
    if rc != 0 {
        return Err(AfXdpError::Backend(errno_msg("mbind(umem)")));
    }
    Ok(())
}

fn allocate_umem(cfg: &AfXdpConfig, len: usize) -> Result<(*mut u8, bool, Option<i32>), AfXdpError> {
    let mut use_huge = cfg.use_hugepages;
    let mut page_size = None;
    if use_huge {
        match hugepage_info() {
            Some(info) => {
                let expected = cfg.hugepage_size_kb.unwrap_or(info.size_kb);
                if expected != info.size_kb {
                    if cfg.hugepage_fallback {
                        use_huge = false;
                    } else {
                        return Err(AfXdpError::Config(
                            "hugepage size does not match system".into(),
                        ));
                    }
                } else {
                    let size_bytes = expected.saturating_mul(1024);
                    if size_bytes == 0 {
                        if cfg.hugepage_fallback {
                            use_huge = false;
                        } else {
                            return Err(AfXdpError::Config("invalid hugepage size".into()));
                        }
                    } else {
                        let needed = (len + size_bytes - 1) / size_bytes;
                        if info.free < needed as u64 {
                            if cfg.hugepage_fallback {
                                use_huge = false;
                            } else {
                                return Err(AfXdpError::Config(
                                    "insufficient hugepages available".into(),
                                ));
                            }
                        }
                        if len % size_bytes != 0 {
                            if cfg.hugepage_fallback {
                                use_huge = false;
                            } else {
                                return Err(AfXdpError::Config(
                                    "umem length not hugepage aligned".into(),
                                ));
                            }
                        }
                        page_size = Some(size_bytes);
                    }
                }
            }
            None => {
                if cfg.hugepage_fallback {
                    use_huge = false;
                } else {
                    return Err(AfXdpError::Config(
                        "hugepage info unavailable".into(),
                    ));
                }
            }
        }
    }

    let mut flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE;
    if use_huge {
        flags |= MAP_HUGETLB;
    }
    let mut ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE,
            flags,
            -1,
            0,
        )
    };
    if ptr == MAP_FAILED && use_huge && cfg.hugepage_fallback {
        use_huge = false;
        flags &= !MAP_HUGETLB;
        ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                PROT_READ | PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
    }
    if ptr == MAP_FAILED {
        return Err(AfXdpError::Backend(errno_msg("mmap(umem)")));
    }

    let mut numa_node = None;
    if let Some(node) = cfg.numa_node {
        match bind_memory(ptr, len, node) {
            Ok(()) => numa_node = Some(node),
            Err(err) => {
                if cfg.numa_fallback {
                    numa_node = None;
                } else {
                    unsafe {
                        libc::munmap(ptr, len);
                    }
                    return Err(err);
                }
            }
        }
    }

    let _ = page_size;
    Ok((ptr as *mut u8, use_huge, numa_node))
}

#[repr(C)]
struct SockaddrXdp {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
    sxdp_shared_umem: u32,
}

#[repr(C)]
struct IfInfoMsg {
    ifi_family: u8,
    __ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
struct NlAttr {
    nla_len: u16,
    nla_type: u16,
}

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

#[repr(C)]
struct XdpRingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
struct XdpMmapOffsets {
    rx: XdpRingOffset,
    tx: XdpRingOffset,
    fr: XdpRingOffset,
    cr: XdpRingOffset,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

#[repr(C)]
struct XdpStatistics {
    rx_dropped: u64,
    rx_invalid_descs: u64,
    tx_invalid_descs: u64,
    rx_ring_full: u64,
    rx_fill_ring_empty: u64,
    tx_ring_empty: u64,
}

#[repr(C)]
struct BpfAttr {
    map_fd: u32,
    key: u64,
    value: u64,
    flags: u64,
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u8,
    dst_src: u8,
    off: i16,
    imm: i32,
}

impl BpfInsn {
    fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        BpfInsn {
            code,
            dst_src: dst | (src << 4),
            off,
            imm,
        }
    }
}

#[repr(C)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
}

#[repr(C)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
}

#[repr(C)]
struct BpfObjPinAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

#[derive(Debug)]
pub struct AfXdpFrame<'a> {
    data: &'a [u8],
    addr: u64,
}

impl AfXdpFrame<'_> {
    pub fn bytes(&self) -> &[u8] {
        self.data
    }
}

#[derive(Debug)]
struct Umem {
    base: *mut u8,
    len: usize,
    frame_size: usize,
    headroom: usize,
    hugepages: bool,
    numa_node: Option<i32>,
    free_list: Vec<u64>,
    fill: RingU64,
    comp: RingU64,
}

#[derive(Debug)]
struct RingU64 {
    producer: *mut u32,
    consumer: *mut u32,
    desc: *mut u64,
    flags: *mut u32,
    size: u32,
    mask: u32,
}

#[derive(Debug)]
struct RingDesc {
    producer: *mut u32,
    consumer: *mut u32,
    desc: *mut XdpDesc,
    flags: *mut u32,
    size: u32,
    mask: u32,
}

#[derive(Debug)]
pub struct AfXdpDataplane {
    sock: RawFd,
    umem: Umem,
    rx: RingDesc,
    tx: RingDesc,
    ifindex: u32,
    queue_id: u32,
    need_wakeup: bool,
    last_rx_addr: Option<u64>,
    rx_count: u64,
    tx_count: u64,
}

impl AfXdpDataplane {
    pub fn open_live(iface: &str, cfg: &AfXdpConfig) -> Result<Self, AfXdpError> {
        let ifindex = if_index(iface)?;
        let queue_id = cfg.queue.unwrap_or(0);
        let frame_size = cfg.frame_size.max(2048);
        let headroom = cfg.headroom.min(frame_size / 2);
        let frames = cfg.umem_frames.max(2048).next_power_of_two();
        let umem_len = frame_size
            .checked_mul(frames)
            .ok_or_else(|| AfXdpError::Config("umem size overflow".into()))?;

        let sock = unsafe { libc::socket(AF_XDP, SOCK_RAW, 0) };
        if sock < 0 {
            return Err(AfXdpError::Backend(errno_msg("socket(AF_XDP)")));
        }

        let (umem_base, umem_hugepages, umem_numa_node) = match allocate_umem(cfg, umem_len) {
            Ok(res) => res,
            Err(err) => {
                unsafe {
                    libc::close(sock);
                }
                return Err(err);
            }
        };

        let reg = XdpUmemReg {
            addr: umem_base as u64,
            len: umem_len as u64,
            chunk_size: frame_size as u32,
            headroom: headroom as u32,
            flags: 0,
        };
        let rc = unsafe {
            libc::setsockopt(
                sock,
                SOL_XDP(),
                XDP_UMEM_REG,
                &reg as *const _ as *const c_void,
                size_of::<XdpUmemReg>() as socklen_t,
            )
        };
        if rc != 0 {
            unsafe {
                libc::close(sock);
                libc::munmap(umem_base as *mut c_void, umem_len);
            }
            return Err(AfXdpError::Backend(errno_msg("setsockopt(XDP_UMEM_REG)")));
        }

        set_ring_size(sock, XDP_UMEM_FILL_RING, frames as u32)?;
        set_ring_size(sock, XDP_UMEM_COMPLETION_RING, frames as u32)?;
        set_ring_size(sock, XDP_RX_RING, frames as u32)?;
        set_ring_size(sock, XDP_TX_RING, frames as u32)?;

        let mut offsets = XdpMmapOffsets {
            rx: XdpRingOffset {
                producer: 0,
                consumer: 0,
                desc: 0,
                flags: 0,
            },
            tx: XdpRingOffset {
                producer: 0,
                consumer: 0,
                desc: 0,
                flags: 0,
            },
            fr: XdpRingOffset {
                producer: 0,
                consumer: 0,
                desc: 0,
                flags: 0,
            },
            cr: XdpRingOffset {
                producer: 0,
                consumer: 0,
                desc: 0,
                flags: 0,
            },
        };
        let mut optlen = size_of::<XdpMmapOffsets>() as socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                sock,
                SOL_XDP(),
                XDP_MMAP_OFFSETS,
                &mut offsets as *mut _ as *mut c_void,
                &mut optlen as *mut _,
            )
        };
        if rc != 0 {
            unsafe {
                libc::close(sock);
                libc::munmap(umem_base as *mut c_void, umem_len);
            }
            return Err(AfXdpError::Backend(errno_msg("getsockopt(XDP_MMAP_OFFSETS)")));
        }

        let rx = map_ring_desc(sock, XDP_PGOFF_RX_RING, &offsets.rx, frames as u32)?;
        let tx = map_ring_desc(sock, XDP_PGOFF_TX_RING, &offsets.tx, frames as u32)?;
        let fill = map_ring_u64(sock, XDP_UMEM_PGOFF_FILL_RING, &offsets.fr, frames as u32)?;
        let comp = map_ring_u64(
            sock,
            XDP_UMEM_PGOFF_COMPLETION_RING,
            &offsets.cr,
            frames as u32,
        )?;

        let mut umem = Umem {
            base: umem_base,
            len: umem_len,
            frame_size,
            headroom,
            hugepages: umem_hugepages,
            numa_node: umem_numa_node,
            free_list: Vec::with_capacity(frames),
            fill,
            comp,
        };
        for i in 0..frames {
            umem.free_list.push((i * frame_size) as u64);
        }
        umem.fill_available()?;

        let sxdp = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: 0,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
            sxdp_shared_umem: 0,
        };
        let rc = unsafe {
            libc::bind(
                sock,
                &sxdp as *const _ as *const sockaddr,
                size_of::<SockaddrXdp>() as socklen_t,
            )
        };
        if rc != 0 {
            unsafe {
                libc::close(sock);
                libc::munmap(umem_base as *mut c_void, umem_len);
            }
            return Err(AfXdpError::Backend(errno_msg("bind(AF_XDP)")));
        }

        Ok(AfXdpDataplane {
            sock,
            umem,
            rx,
            tx,
            ifindex,
            queue_id,
            need_wakeup: cfg.use_need_wakeup,
            last_rx_addr: None,
            rx_count: 0,
            tx_count: 0,
        })
    }

    pub fn attach_xdp_program(
        &self,
        program_pin: &str,
        flags: XdpAttachFlags,
    ) -> Result<(), AfXdpError> {
        let prog_fd = bpf_obj_get(program_pin)?;
        attach_xdp_fd(self.ifindex, prog_fd, flags)?;
        unsafe {
            libc::close(prog_fd);
        }
        Ok(())
    }

    pub fn update_xsk_map(&self, map_pin: &str) -> Result<(), AfXdpError> {
        let map_fd = bpf_obj_get(map_pin)?;
        let key = self.queue_id as u32;
        let fd = self.sock as u32;
        bpf_map_update(map_fd, &key, &fd)?;
        unsafe {
            libc::close(map_fd);
        }
        Ok(())
    }

    fn poll_rx(&self) -> bool {
        let mut fds = pollfd {
            fd: self.sock,
            events: POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut fds, 1, 0) };
        rc > 0 && (fds.revents & POLLIN) != 0
    }

    fn kick_tx(&self) {
        let rc = unsafe {
            libc::sendto(
                self.sock,
                ptr::null(),
                0,
                MSG_DONTWAIT,
                ptr::null(),
                0,
            )
        };
        let _ = rc;
    }

    fn should_wakeup(ring: &RingDesc) -> bool {
        if ring.flags.is_null() {
            return false;
        }
        let flags = unsafe { ptr::read_volatile(ring.flags) };
        flags & XDP_RING_NEED_WAKEUP != 0
    }

    fn reclaim_completed(&mut self) {
        let mut cons = unsafe { ptr::read_volatile(self.umem.comp.consumer) };
        let prod = unsafe { ptr::read_volatile(self.umem.comp.producer) };
        fence(Ordering::Acquire);
        while cons != prod {
            let idx = (cons & self.umem.comp.mask) as isize;
            let addr = unsafe { ptr::read_volatile(self.umem.comp.desc.offset(idx)) };
            self.umem.free_list.push(addr);
            cons = cons.wrapping_add(1);
        }
        unsafe {
            ptr::write_volatile(self.umem.comp.consumer, cons);
        }
        fence(Ordering::Release);
    }
}

pub fn ensure_pinned_xdp_program(
    pin_dir: &Path,
    program_name: &str,
    map_name: &str,
    max_entries: u32,
) -> Result<PinnedXdp, AfXdpError> {
    if max_entries == 0 {
        return Err(AfXdpError::Config("xsk map entries must be > 0".into()));
    }
    std::fs::create_dir_all(pin_dir)
        .map_err(|e| AfXdpError::Backend(format!("create pin dir: {e}")))?;
    let prog_path = pin_dir.join(program_name);
    let map_path = pin_dir.join(map_name);

    let map_fd = if map_path.exists() {
        bpf_obj_get(map_path.to_str().ok_or_else(|| {
            AfXdpError::Config("invalid xsk map pin path".into())
        })?)?
    } else {
        let fd = bpf_map_create_xsk(max_entries)?;
        bpf_obj_pin(fd, &map_path)?;
        fd
    };

    if prog_path.exists() {
        let _ = bpf_obj_get(prog_path.to_str().ok_or_else(|| {
            AfXdpError::Config("invalid xdp program pin path".into())
        })?)?;
        unsafe {
            libc::close(map_fd);
        }
        return Ok(PinnedXdp {
            program_pin: prog_path,
            map_pin: map_path,
        });
    }

    let insns = build_xsk_redirect_prog(map_fd as i32);
    let prog_fd = bpf_prog_load_xdp(&insns, program_name)?;
    bpf_obj_pin(prog_fd, &prog_path)?;
    unsafe {
        libc::close(prog_fd);
        libc::close(map_fd);
    }

    Ok(PinnedXdp {
        program_pin: prog_path,
        map_pin: map_path,
    })
}

impl Drop for AfXdpDataplane {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.sock);
            libc::munmap(self.umem.base as *mut c_void, self.umem.len);
        }
    }
}

impl AfXdpDataplane {
    pub fn next_frame(&mut self) -> Result<Option<AfXdpFrame<'_>>, AfXdpError> {
        if let Some(addr) = self.last_rx_addr.take() {
            self.umem.free_list.push(addr);
            self.umem.fill_available()?;
        }

        if !self.poll_rx() {
            return Ok(None);
        }

        let mut cons = unsafe { ptr::read_volatile(self.rx.consumer) };
        let prod = unsafe { ptr::read_volatile(self.rx.producer) };
        fence(Ordering::Acquire);
        if cons == prod {
            return Ok(None);
        }
        let idx = (cons & self.rx.mask) as isize;
        let desc = unsafe { ptr::read_volatile(self.rx.desc.offset(idx)) };
        cons = cons.wrapping_add(1);
        unsafe {
            ptr::write_volatile(self.rx.consumer, cons);
        }
        fence(Ordering::Release);

        let addr = desc.addr;
        let data_ptr = unsafe { self.umem.base.add(addr as usize) };
        let data = unsafe { slice::from_raw_parts(data_ptr, desc.len as usize) };
        self.last_rx_addr = Some(self.umem.frame_base(addr));
        self.rx_count = self.rx_count.wrapping_add(1);
        Ok(Some(AfXdpFrame { data, addr }))
    }

    pub fn send_frame(&mut self, frame: &AfXdpFrame<'_>) -> Result<(), AfXdpError> {
        self.reclaim_completed();
        let addr = self
            .umem
            .free_list
            .pop()
            .ok_or_else(|| AfXdpError::Backend("no free umem frames".into()))?;
        let start = addr as usize + self.umem.headroom;
        let end = start + frame.data.len();
        if end > self.umem.len {
            self.umem.free_list.push(addr);
            return Err(AfXdpError::Backend("frame too large for umem".into()));
        }
        unsafe {
            ptr::copy_nonoverlapping(
                frame.data.as_ptr(),
                self.umem.base.add(start),
                frame.data.len(),
            );
        }

        let mut prod = unsafe { ptr::read_volatile(self.tx.producer) };
        let cons = unsafe { ptr::read_volatile(self.tx.consumer) };
        if prod.wrapping_sub(cons) >= self.tx.size {
            self.umem.free_list.push(addr);
            return Err(AfXdpError::Backend("tx ring full".into()));
        }
        let idx = (prod & self.tx.mask) as isize;
        let desc = XdpDesc {
            addr: addr + self.umem.headroom as u64,
            len: frame.data.len() as u32,
            options: 0,
        };
        unsafe {
            ptr::write_volatile(self.tx.desc.offset(idx), desc);
        }
        prod = prod.wrapping_add(1);
        unsafe {
            ptr::write_volatile(self.tx.producer, prod);
        }
        fence(Ordering::Release);

        if self.need_wakeup && Self::should_wakeup(&self.tx) {
            self.kick_tx();
        }
        self.tx_count = self.tx_count.wrapping_add(1);
        Ok(())
    }

    pub fn stats(&mut self) -> Result<AfXdpStats, AfXdpError> {
        let mut stats = XdpStatistics {
            rx_dropped: 0,
            rx_invalid_descs: 0,
            tx_invalid_descs: 0,
            rx_ring_full: 0,
            rx_fill_ring_empty: 0,
            tx_ring_empty: 0,
        };
        let mut len = size_of::<XdpStatistics>() as socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                self.sock,
                SOL_XDP(),
                XDP_STATISTICS,
                &mut stats as *mut _ as *mut c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(AfXdpError::Backend(errno_msg("getsockopt(XDP_STATISTICS)")));
        }
        Ok(AfXdpStats {
            rx_dropped: stats.rx_dropped,
            rx_invalid_descs: stats.rx_invalid_descs,
            tx_invalid_descs: stats.tx_invalid_descs,
            rx_ring_full: stats.rx_ring_full,
            rx_fill_ring_empty: stats.rx_fill_ring_empty,
            tx_ring_empty: stats.tx_ring_empty,
            umem_hugepages: self.umem.hugepages,
            umem_numa_node: self.umem.numa_node,
            umem_len: self.umem.len,
        })
    }

    pub fn rx_count(&self) -> u64 {
        self.rx_count
    }

    pub fn tx_count(&self) -> u64 {
        self.tx_count
    }
}

impl Umem {
    fn frame_base(&self, addr: u64) -> u64 {
        if addr >= self.headroom as u64 {
            addr - self.headroom as u64
        } else {
            addr
        }
    }

    fn fill_available(&mut self) -> Result<(), AfXdpError> {
        let mut prod = unsafe { ptr::read_volatile(self.fill.producer) };
        let cons = unsafe { ptr::read_volatile(self.fill.consumer) };
        let space = self.fill.size - prod.wrapping_sub(cons);
        let mut pushed = 0u32;
        while pushed < space {
            let addr = match self.free_list.pop() {
                Some(a) => a,
                None => break,
            };
            let idx = (prod & self.fill.mask) as isize;
            unsafe {
                ptr::write_volatile(self.fill.desc.offset(idx), addr);
            }
            prod = prod.wrapping_add(1);
            pushed += 1;
        }
        unsafe {
            ptr::write_volatile(self.fill.producer, prod);
        }
        fence(Ordering::Release);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum XdpAttachMode {
    Skb,
    Drv,
    Auto,
}

#[derive(Debug, Clone, Copy)]
pub struct XdpAttachFlags {
    pub mode: XdpAttachMode,
    pub update_if_noexist: bool,
}

impl Default for XdpAttachFlags {
    fn default() -> Self {
        XdpAttachFlags {
            mode: XdpAttachMode::Auto,
            update_if_noexist: true,
        }
    }
}

fn set_ring_size(sock: RawFd, opt: c_int, size: u32) -> Result<(), AfXdpError> {
    let rc = unsafe {
        libc::setsockopt(
            sock,
            SOL_XDP(),
            opt,
            &size as *const _ as *const c_void,
            size_of::<u32>() as socklen_t,
        )
    };
    if rc != 0 {
        return Err(AfXdpError::Backend(errno_msg("setsockopt ring size")));
    }
    Ok(())
}

fn map_ring_desc(sock: RawFd, offset: i64, ring: &XdpRingOffset, size: u32) -> Result<RingDesc, AfXdpError> {
    let desc_size = size_of::<XdpDesc>() as u64 * size as u64;
    let ring_size = ring.desc + desc_size;
    let addr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            ring_size as usize,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            sock,
            offset,
        )
    };
    if addr == MAP_FAILED {
        return Err(AfXdpError::Backend(errno_msg("mmap ring")));
    }
    let base = addr as *mut u8;
    Ok(RingDesc {
        producer: unsafe { base.add(ring.producer as usize) } as *mut u32,
        consumer: unsafe { base.add(ring.consumer as usize) } as *mut u32,
        desc: unsafe { base.add(ring.desc as usize) } as *mut XdpDesc,
        flags: unsafe { base.add(ring.flags as usize) } as *mut u32,
        size,
        mask: size - 1,
    })
}

fn map_ring_u64(sock: RawFd, offset: i64, ring: &XdpRingOffset, size: u32) -> Result<RingU64, AfXdpError> {
    let desc_size = size_of::<u64>() as u64 * size as u64;
    let ring_size = ring.desc + desc_size;
    let addr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            ring_size as usize,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            sock,
            offset,
        )
    };
    if addr == MAP_FAILED {
        return Err(AfXdpError::Backend(errno_msg("mmap umem ring")));
    }
    let base = addr as *mut u8;
    Ok(RingU64 {
        producer: unsafe { base.add(ring.producer as usize) } as *mut u32,
        consumer: unsafe { base.add(ring.consumer as usize) } as *mut u32,
        desc: unsafe { base.add(ring.desc as usize) } as *mut u64,
        flags: unsafe { base.add(ring.flags as usize) } as *mut u32,
        size,
        mask: size - 1,
    })
}

fn if_index(iface: &str) -> Result<u32, AfXdpError> {
    let cstr = CString::new(iface).map_err(|_| AfXdpError::Config("invalid iface".into()))?;
    let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if idx == 0 {
        Err(AfXdpError::Backend(errno_msg("if_nametoindex")))
    } else {
        Ok(idx)
    }
}

fn bpf_obj_get(path: &str) -> Result<RawFd, AfXdpError> {
    let cpath = CString::new(path).map_err(|_| AfXdpError::Config("invalid bpf path".into()))?;
    let mut attr: BpfAttr = unsafe { mem::zeroed() };
    attr.pathname = cpath.as_ptr() as u64;
    let rc = unsafe { libc::syscall(libc::SYS_bpf, BPF_OBJ_GET, &attr, size_of::<BpfAttr>()) };
    if rc < 0 {
        return Err(AfXdpError::Backend(errno_msg("bpf_obj_get")));
    }
    Ok(rc as RawFd)
}

fn bpf_map_update<K: Sized, V: Sized>(map_fd: RawFd, key: &K, value: &V) -> Result<(), AfXdpError> {
    let mut attr: BpfAttr = unsafe { mem::zeroed() };
    attr.map_fd = map_fd as u32;
    attr.key = key as *const _ as u64;
    attr.value = value as *const _ as u64;
    attr.flags = BPF_ANY;
    let rc = unsafe { libc::syscall(libc::SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, size_of::<BpfAttr>()) };
    if rc < 0 {
        return Err(AfXdpError::Backend(errno_msg("bpf_map_update_elem")));
    }
    Ok(())
}

fn bpf_map_create_xsk(max_entries: u32) -> Result<RawFd, AfXdpError> {
    let mut attr = BpfMapCreateAttr {
        map_type: BPF_MAP_TYPE_XSKMAP,
        key_size: size_of::<u32>() as u32,
        value_size: size_of::<u32>() as u32,
        max_entries,
        map_flags: 0,
    };
    let rc = unsafe { libc::syscall(libc::SYS_bpf, BPF_MAP_CREATE, &mut attr, size_of::<BpfMapCreateAttr>()) };
    if rc < 0 {
        return Err(AfXdpError::Backend(errno_msg("bpf_map_create")));
    }
    Ok(rc as RawFd)
}

fn bpf_obj_pin(fd: RawFd, path: &Path) -> Result<(), AfXdpError> {
    let cpath = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| AfXdpError::Config("invalid pin path".into()))?;
    let mut attr = BpfObjPinAttr {
        pathname: cpath.as_ptr() as u64,
        bpf_fd: fd as u32,
        file_flags: 0,
    };
    let rc = unsafe { libc::syscall(libc::SYS_bpf, BPF_OBJ_PIN, &mut attr, size_of::<BpfObjPinAttr>()) };
    if rc < 0 {
        return Err(AfXdpError::Backend(errno_msg("bpf_obj_pin")));
    }
    Ok(())
}

fn build_xsk_redirect_prog(map_fd: i32) -> Vec<BpfInsn> {
    vec![
        BpfInsn::new(BPF_LDX | BPF_MEM | BPF_W, 2, 1, XDP_MD_RX_QUEUE_INDEX, 0),
        BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD, 0, map_fd),
        BpfInsn::new(0, 0, 0, 0, 0),
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, 0),
        BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_REDIRECT_MAP),
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]
}

fn bpf_prog_load_xdp(insns: &[BpfInsn], name: &str) -> Result<RawFd, AfXdpError> {
    let license = CString::new("GPL").unwrap();
    let mut log_buf = vec![0u8; 16 * 1024];
    let mut prog_name = [0u8; 16];
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(prog_name.len());
    prog_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    let mut attr = BpfProgLoadAttr {
        prog_type: BPF_PROG_TYPE_XDP,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: log_buf.len() as u32,
        log_buf: log_buf.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        prog_name,
    };
    let rc = unsafe { libc::syscall(libc::SYS_bpf, BPF_PROG_LOAD, &mut attr, size_of::<BpfProgLoadAttr>()) };
    if rc < 0 {
        let log = String::from_utf8_lossy(&log_buf).trim().to_string();
        let msg = if log.is_empty() {
            errno_msg("bpf_prog_load")
        } else {
            format!("bpf_prog_load: {log}")
        };
        return Err(AfXdpError::Backend(msg));
    }
    Ok(rc as RawFd)
}

fn attach_xdp_fd(ifindex: u32, prog_fd: RawFd, flags: XdpAttachFlags) -> Result<(), AfXdpError> {
    let netlink = unsafe { libc::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
    if netlink < 0 {
        return Err(AfXdpError::Backend(errno_msg("socket(AF_NETLINK)")));
    }
    let mut req = Vec::new();
    let nlmsg_len = size_of::<libc::nlmsghdr>() + size_of::<IfInfoMsg>();
    let mut hdr = libc::nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_type: libc::RTM_SETLINK,
        nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    let ifi = IfInfoMsg {
        ifi_family: libc::AF_UNSPEC as u8,
        __ifi_pad: 0,
        ifi_type: 0,
        ifi_index: ifindex as i32,
        ifi_flags: 0,
        ifi_change: 0,
    };
    req.extend_from_slice(unsafe {
        slice::from_raw_parts(
            &hdr as *const _ as *const u8,
            size_of::<libc::nlmsghdr>(),
        )
    });
    req.extend_from_slice(unsafe {
        slice::from_raw_parts(&ifi as *const _ as *const u8, size_of::<IfInfoMsg>())
    });

    let mut xdp_attrs = Vec::new();
    add_attr_u32(&mut xdp_attrs, IFLA_XDP_FD, prog_fd as u32);
    let flag_val = match flags.mode {
        XdpAttachMode::Skb => XDP_FLAGS_SKB_MODE,
        XdpAttachMode::Drv => XDP_FLAGS_DRV_MODE,
        XdpAttachMode::Auto => 0,
    } | if flags.update_if_noexist {
        XDP_FLAGS_UPDATE_IF_NOEXIST
    } else {
        0
    };
    add_attr_u32(&mut xdp_attrs, IFLA_XDP_FLAGS, flag_val);
    add_attr_nested(&mut req, IFLA_XDP, &xdp_attrs);

    // Patch nlmsg_len
    let len = req.len() as u32;
    unsafe {
        let hdr_ptr = req.as_mut_ptr() as *mut libc::nlmsghdr;
        (*hdr_ptr).nlmsg_len = len;
    }

    let rc = unsafe {
        libc::send(
            netlink,
            req.as_ptr() as *const c_void,
            req.len(),
            0,
        )
    };
    if rc < 0 {
        unsafe {
            libc::close(netlink);
        }
        return Err(AfXdpError::Backend(errno_msg("netlink send")));
    }
    let mut buf = [0u8; 4096];
    let rc = unsafe { libc::recv(netlink, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
    unsafe {
        libc::close(netlink);
    }
    if rc < 0 {
        return Err(AfXdpError::Backend(errno_msg("netlink recv")));
    }
    Ok(())
}

fn add_attr_u32(buf: &mut Vec<u8>, attr_type: u16, value: u32) {
    let payload = value.to_ne_bytes();
    add_attr(buf, attr_type, &payload);
}

fn add_attr_nested(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let start = buf.len();
    add_attr(buf, attr_type, payload);
    let len = (buf.len() - start) as u16;
    let hdr_ptr = unsafe { buf.as_mut_ptr().add(start) as *mut NlAttr };
    unsafe {
        (*hdr_ptr).nla_len = len;
    }
}

fn add_attr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let hdr = NlAttr {
        nla_len: (size_of::<NlAttr>() + payload.len()) as u16,
        nla_type: attr_type,
    };
    let start = buf.len();
    buf.extend_from_slice(unsafe {
        slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlAttr>())
    });
    buf.extend_from_slice(payload);
    let aligned = nla_align(buf.len() - start);
    let pad = aligned - (buf.len() - start);
    buf.extend_from_slice(&vec![0u8; pad]);
}

fn nla_align(len: usize) -> usize {
    const NLA_ALIGNTO: usize = 4;
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

fn SOL_XDP() -> c_int {
    // From linux/socket.h
    283
}

fn errno_msg(ctx: &str) -> String {
    let err = std::io::Error::last_os_error();
    format!("{ctx}: {err}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn umem_frame_base_respects_headroom() {
        let mut umem = Umem {
            base: ptr::null_mut(),
            len: 0,
            frame_size: 2048,
            headroom: 256,
            hugepages: false,
            numa_node: None,
            free_list: Vec::new(),
            fill: RingU64 {
                producer: ptr::null_mut(),
                consumer: ptr::null_mut(),
                desc: ptr::null_mut(),
                flags: ptr::null_mut(),
                size: 0,
                mask: 0,
            },
            comp: RingU64 {
                producer: ptr::null_mut(),
                consumer: ptr::null_mut(),
                desc: ptr::null_mut(),
                flags: ptr::null_mut(),
                size: 0,
                mask: 0,
            },
        };
        assert_eq!(umem.frame_base(256), 0);
        assert_eq!(umem.frame_base(512), 256);
        umem.headroom = 0;
        assert_eq!(umem.frame_base(512), 512);
    }

    #[test]
    fn xdp_attach_flags_default() {
        let flags = XdpAttachFlags::default();
        matches!(flags.mode, XdpAttachMode::Auto);
        assert!(flags.update_if_noexist);
    }

    #[test]
    fn build_xsk_redirect_prog_shape() {
        let insns = build_xsk_redirect_prog(3);
        assert_eq!(insns.len(), 6);
        assert_eq!(insns[0].code, BPF_LDX | BPF_MEM | BPF_W);
        assert_eq!(insns[1].code, BPF_LD | BPF_IMM | BPF_DW);
        assert_eq!(insns[4].code, BPF_JMP | BPF_CALL);
    }

    #[test]
    fn ensure_pinned_rejects_zero_entries() {
        let dir = PathBuf::from("/tmp");
        let err = ensure_pinned_xdp_program(&dir, "prog", "map", 0).unwrap_err();
        match err {
            AfXdpError::Config(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
}

#[cfg(target_os = "linux")]
pub use linux::{AfXdpDataplane, AfXdpFrame, XdpAttachFlags, XdpAttachMode};
