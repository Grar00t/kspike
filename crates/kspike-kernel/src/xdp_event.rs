//! XDP Burp shared event schema.
//!
//! Used by both sides:
//!   - the eBPF program in `kspike-xdp-burp/bpf` (no_std)
//!   - the user-space loader in `kspike-xdp-burp`
//!
//! The structs are `#[repr(C)]` + POD so they cross the kernel/user boundary
//! via `read` from a RingBuf/PerfEventArray record.
//!
//! Two channels:
//!   EVENTS  (RingBuf)         → typed threats → ingested as `Signal`
//!   DEBUG   (PerfEventArray)  → raw flow observability → logs only

#![allow(clippy::new_without_default)]

/// Length of the family-agnostic IP bytes. 4 bytes → IPv4 (padded), 16 → IPv6.
pub const IP_BYTES: usize = 16;
/// Length of the `kind` taxonomy string (NUL-padded).
pub const KIND_BYTES: usize = 64;
/// Length of the `actor` string (NUL-padded).
pub const ACTOR_BYTES: usize = 64;
/// Debug message buffer.
pub const DEBUG_MSG_BYTES: usize = 128;

/// Address family tag — since eBPF can't carry enum discriminants cleanly,
/// we use `u8`.
pub mod af { pub const IPV4: u8 = 4; pub const IPV6: u8 = 6; }

/// Threat level tag — matches `kspike_core::ThreatLevel` ordering.
pub mod threat { pub const UNKNOWN: u8 = 0; pub const BENIGN: u8 = 1;
                 pub const SUSPICIOUS: u8 = 2; pub const HOSTILE: u8 = 3;
                 pub const CATASTROPHIC: u8 = 4; }

/// A threat signal emitted by the XDP program via the RingBuf channel.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XdpSignalEvent {
    pub af: u8,                       // 4 or 6
    pub threat: u8,                   // threat::*
    pub _pad0: [u8; 2],               // align
    pub src_ip:  [u8; IP_BYTES],      // left-justified; zero-pad
    pub dst_ip:  [u8; IP_BYTES],
    pub src_port: u16,
    pub dst_port: u16,
    pub confidence_milli: u16,        // confidence * 1000 (avoids f32 in eBPF)
    pub proportionality: u8,          // 1..10 (for striker hints; else 0)
    pub _pad1: u8,
    pub kind:  [u8; KIND_BYTES],
    pub actor: [u8; ACTOR_BYTES],
    pub payload_hash: u64,            // FNV-1a over the inspected window
    pub ts_ns: u64,                   // ktime_get_ns() from eBPF
}

/// A low-priority observability event via PerfEventArray.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XdpDebugEvent {
    pub af: u8,
    pub event_type: u8,               // 0=flow, 1=header, 2=stats
    pub _pad0: [u8; 2],
    pub src_ip:  [u8; IP_BYTES],
    pub dst_ip:  [u8; IP_BYTES],
    pub src_port: u16,
    pub dst_port: u16,
    pub pkt_len: u32,
    pub message: [u8; DEBUG_MSG_BYTES],
    pub ts_ns: u64,
}

// ─── user-space constructors / conversions ──────────────────────────────────
// These are compiled on both sides; the eBPF side doesn't use the `std`-y
// helpers — it writes the structs by hand.

impl XdpSignalEvent {
    #[cfg(feature = "std_helpers")]
    pub fn new_v4(kind: &str, src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr,
                  src_port: u16, dst_port: u16, threat: u8, confidence: f32) -> Self
    {
        let mut k = [0u8; KIND_BYTES];
        let kb = kind.as_bytes();
        k[..kb.len().min(KIND_BYTES)].copy_from_slice(&kb[..kb.len().min(KIND_BYTES)]);
        let mut src_ip = [0u8; IP_BYTES];
        let mut dst_ip = [0u8; IP_BYTES];
        src_ip[..4].copy_from_slice(&src.octets());
        dst_ip[..4].copy_from_slice(&dst.octets());
        Self {
            af: af::IPV4, threat, _pad0: [0;2],
            src_ip, dst_ip, src_port, dst_port,
            confidence_milli: (confidence.clamp(0.0,1.0) * 1000.0) as u16,
            proportionality: 0, _pad1: 0,
            kind: k, actor: [0; ACTOR_BYTES],
            payload_hash: 0, ts_ns: 0,
        }
    }
}

/// Read a signal out of a raw RingBuf frame. Validates the size.
pub fn decode_signal(bytes: &[u8]) -> Option<XdpSignalEvent> {
    if bytes.len() < core::mem::size_of::<XdpSignalEvent>() { return None; }
    // SAFETY: struct is POD / repr(C); we've verified the size.
    let ev: XdpSignalEvent = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const _) };
    Some(ev)
}

pub fn decode_debug(bytes: &[u8]) -> Option<XdpDebugEvent> {
    if bytes.len() < core::mem::size_of::<XdpDebugEvent>() { return None; }
    let ev: XdpDebugEvent = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const _) };
    Some(ev)
}

/// FNV-1a 64-bit. Used both sides so hashes compare across the boundary.
#[inline]
pub fn fnv1a64(buf: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mut i = 0;
    while i < buf.len() {
        h ^= buf[i] as u64;
        h = h.wrapping_mul(0x100000001b3);
        i += 1;
    }
    h
}

pub fn kind_str(k: &[u8; KIND_BYTES]) -> &str {
    let end = k.iter().position(|&b| b == 0).unwrap_or(KIND_BYTES);
    core::str::from_utf8(&k[..end]).unwrap_or("?")
}
