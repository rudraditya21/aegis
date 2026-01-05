//! Safe-ish wrapper over libpcap covering live/offline capture, device discovery, filters, and stats.

use libc::{c_char, c_int, c_uchar};
use std::ffi::{CStr, CString};
use std::ptr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct Capture {
    handle: *mut pcap_t,
}

#[derive(Debug)]
pub struct Packet<'a> {
    pub data: &'a [u8],
    pub ts: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub received: u32,
    pub dropped: u32,
    pub if_dropped: u32,
}

impl Capture {
    pub fn open_live(
        device: &str,
        snaplen: i32,
        promisc: bool,
        timeout_ms: i32,
    ) -> Result<Self, String> {
        let dev_c = CString::new(device).map_err(|_| "invalid device name")?;
        let mut errbuf = [0i8; 256];
        let handle = unsafe {
            pcap_open_live(
                dev_c.as_ptr(),
                snaplen,
                if promisc { 1 } else { 0 },
                timeout_ms,
                errbuf.as_mut_ptr(),
            )
        };
        if handle.is_null() {
            let msg = unsafe { cstr_to_string(errbuf.as_ptr()) };
            return Err(format!("pcap_open_live: {msg}"));
        }
        Ok(Capture { handle })
    }

    pub fn open_offline(path: &str) -> Result<Self, String> {
        let mut errbuf = [0i8; 256];
        let cpath = CString::new(path).map_err(|_| "invalid path")?;
        let handle = unsafe { pcap_open_offline(cpath.as_ptr(), errbuf.as_mut_ptr()) };
        if handle.is_null() {
            let msg = unsafe { cstr_to_string(errbuf.as_ptr()) };
            return Err(format!("pcap_open_offline: {msg}"));
        }
        Ok(Capture { handle })
    }

    pub fn next(&mut self) -> Result<Option<Packet<'_>>, String> {
        let mut header: *mut pcap_pkthdr = ptr::null_mut();
        let mut data_ptr: *const c_uchar = ptr::null();
        let rc = unsafe { pcap_next_ex(self.handle, &mut header, &mut data_ptr) };
        match rc {
            1 => {
                if header.is_null() || data_ptr.is_null() {
                    return Ok(None);
                }
                let hdr = unsafe { &*header };
                let secs = hdr.ts.tv_sec as u64;
                let usecs = hdr.ts.tv_usec as u32;
                let ts =
                    UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_micros(usecs as u64);
                let len = hdr.caplen as usize;
                let data = unsafe { std::slice::from_raw_parts(data_ptr, len) };
                Ok(Some(Packet { data, ts }))
            }
            0 => Ok(None),  // timeout
            -2 => Ok(None), // no more packets (offline)
            -1 => Err(unsafe { err_from_handle(self.handle) }),
            _ => Ok(None),
        }
    }

    pub fn stats(&mut self) -> Result<Stats, String> {
        let mut raw = pcap_stat {
            ps_recv: 0,
            ps_drop: 0,
            ps_ifdrop: 0,
        };
        let rc = unsafe { pcap_stats(self.handle, &mut raw) };
        if rc != 0 {
            return Err(unsafe { err_from_handle(self.handle) });
        }
        Ok(Stats {
            received: raw.ps_recv,
            dropped: raw.ps_drop,
            if_dropped: raw.ps_ifdrop,
        })
    }

    pub fn set_filter(&mut self, filter_expr: &str) -> Result<(), String> {
        let mut program = bpf_program {
            bf_len: 0,
            bf_insns: ptr::null_mut(),
        };
        let filter_c = CString::new(filter_expr).map_err(|_| "invalid filter string")?;
        let mask = 0xffffff00u32;
        let rc = unsafe { pcap_compile(self.handle, &mut program, filter_c.as_ptr(), 1, mask) };
        if rc != 0 {
            return Err(unsafe { err_from_handle(self.handle) });
        }
        let rc = unsafe { pcap_setfilter(self.handle, &mut program) };
        unsafe { pcap_freecode(&mut program) };
        if rc != 0 {
            return Err(unsafe { err_from_handle(self.handle) });
        }
        Ok(())
    }
}

pub fn list_devices() -> Result<Vec<Device>, String> {
    let mut alldevs: *mut pcap_if = ptr::null_mut();
    let mut errbuf = [0i8; 256];
    let rc = unsafe { pcap_findalldevs(&mut alldevs, errbuf.as_mut_ptr()) };
    if rc != 0 {
        let msg = unsafe { cstr_to_string(errbuf.as_ptr()) };
        return Err(format!("pcap_findalldevs: {msg}"));
    }
    let mut out = Vec::new();
    let mut cur = alldevs;
    while !cur.is_null() {
        unsafe {
            let dev = &*cur;
            let name = cstr_to_string(dev.name);
            let desc = if dev.description.is_null() {
                None
            } else {
                Some(cstr_to_string(dev.description))
            };
            out.push(Device {
                name,
                description: desc,
            });
            cur = dev.next;
        }
    }
    unsafe { pcap_freealldevs(alldevs) };
    Ok(out)
}

impl Drop for Capture {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { pcap_close(self.handle) };
        }
    }
}

unsafe impl Send for Capture {}
unsafe impl Sync for Capture {}

#[repr(C)]
struct pcap_t {
    _private: [u8; 0],
}

#[repr(C)]
struct timeval {
    tv_sec: libc::time_t,
    tv_usec: libc::suseconds_t,
}

#[repr(C)]
struct pcap_pkthdr {
    ts: timeval,
    caplen: u32,
    len: u32,
}

#[repr(C)]
struct pcap_if {
    next: *mut pcap_if,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut pcap_addr,
    flags: u32,
}

#[repr(C)]
struct pcap_addr {
    next: *mut pcap_addr,
    addr: *mut libc::sockaddr,
    netmask: *mut libc::sockaddr,
    broadaddr: *mut libc::sockaddr,
    dstaddr: *mut libc::sockaddr,
}

#[repr(C)]
struct pcap_stat {
    ps_recv: u32,
    ps_drop: u32,
    ps_ifdrop: u32,
}

#[repr(C)]
struct bpf_insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct bpf_program {
    bf_len: u32,
    bf_insns: *mut bpf_insn,
}

unsafe extern "C" {
    fn pcap_open_live(
        device: *const c_char,
        snaplen: c_int,
        promisc: c_int,
        to_ms: c_int,
        errbuf: *mut c_char,
    ) -> *mut pcap_t;
    fn pcap_open_offline(fname: *const c_char, errbuf: *mut c_char) -> *mut pcap_t;
    fn pcap_next_ex(
        p: *mut pcap_t,
        pkt_header: *mut *mut pcap_pkthdr,
        pkt_data: *mut *const c_uchar,
    ) -> c_int;
    fn pcap_close(p: *mut pcap_t);
    fn pcap_geterr(p: *mut pcap_t) -> *const c_char;
    fn pcap_findalldevs(alldevs: *mut *mut pcap_if, errbuf: *mut c_char) -> c_int;
    fn pcap_freealldevs(alldevs: *mut pcap_if);
    fn pcap_stats(p: *mut pcap_t, ps: *mut pcap_stat) -> c_int;
    fn pcap_compile(
        p: *mut pcap_t,
        program: *mut bpf_program,
        buf: *const c_char,
        optimize: c_int,
        mask: u32,
    ) -> c_int;
    fn pcap_setfilter(p: *mut pcap_t, program: *mut bpf_program) -> c_int;
    fn pcap_freecode(program: *mut bpf_program);
}

unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return "unknown".to_string();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

unsafe fn err_from_handle(handle: *mut pcap_t) -> String {
    unsafe { cstr_to_string(pcap_geterr(handle)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn capture_is_send_sync() {
        assert_send_sync::<Capture>();
    }

    #[test]
    fn device_equality_and_clone() {
        let a = Device {
            name: "eth0".to_string(),
            description: Some("primary".to_string()),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn stats_copy_and_compare() {
        let a = Stats {
            received: 1,
            dropped: 2,
            if_dropped: 3,
        };
        let b = a;
        assert_eq!(a, b);
    }
}
