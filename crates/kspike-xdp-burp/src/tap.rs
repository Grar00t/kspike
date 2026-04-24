//! `XdpBurpTap` — the KernelTap that bridges the XDP program to the Engine.

use kspike_core::{Signal, SignalSource, ThreatLevel};
use kspike_kernel::{KernelTap, TapError, TapStatus, XdpSignalEvent, af, threat, kind_str};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct XdpBurpConfig {
    pub interface: String,      // e.g. "eth0"
    pub mode: AttachMode,
    pub ring_entries: u32,      // RingBuf capacity in bytes (pow2)
    pub sinkhole: Option<SinkholeIface>,
}

impl Default for XdpBurpConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".into(),
            mode: AttachMode::Skb,
            ring_entries: 1 << 20, // 1 MiB
            sinkhole: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    /// Generic, driver-agnostic (slow-ish, ubiquitous).
    Skb,
    /// Native driver mode (fast, limited NICs).
    Driver,
    /// Hardware offload (rare, highest speed).
    Offload,
}

#[derive(Debug, Clone)]
pub struct SinkholeIface {
    pub ifname: String,   // virtual veth leading to the honeypot
}

/// Tap backed by the XDP program.
///
/// In this build (no `aya_runtime` feature), `poll` pulls from an in-process
/// queue that the pcap-replay harness or a unit test can push to. With the
/// `aya_runtime` feature the queue is fed by the real RingBuf reader task.
pub struct XdpBurpTap {
    cfg: XdpBurpConfig,
    status: Mutex<TapStatus>,
    queue: Arc<Mutex<VecDeque<XdpSignalEvent>>>,
}

impl XdpBurpTap {
    pub fn new(cfg: XdpBurpConfig) -> Self {
        Self {
            cfg,
            status: Mutex::new(TapStatus::Idle),
            queue: Arc::new(Mutex::new(VecDeque::with_capacity(1024))),
        }
    }

    pub fn config(&self) -> &XdpBurpConfig { &self.cfg }

    /// Handle to push events — used by the replay harness and the aya reader.
    pub fn sink(&self) -> Arc<Mutex<VecDeque<XdpSignalEvent>>> { self.queue.clone() }

    pub fn mark_active(&self)   { *self.status.lock().unwrap() = TapStatus::Active; }
    pub fn mark_offline(&self)  { *self.status.lock().unwrap() = TapStatus::Offline; }
}

impl KernelTap for XdpBurpTap {
    fn name(&self) -> &'static str { "xdp.burp" }

    fn status(&self) -> TapStatus { *self.status.lock().unwrap() }

    fn poll(&mut self) -> Result<Vec<Signal>, TapError> {
        let mut out = Vec::new();
        let mut q = self.queue.lock().unwrap();
        while let Some(ev) = q.pop_front() {
            out.push(event_to_signal(&ev));
        }
        Ok(out)
    }
}

/// Translate a POD event into a fully-typed `Signal` for the engine.
pub fn event_to_signal(ev: &XdpSignalEvent) -> Signal {
    let kind = kind_str(&ev.kind).to_string();
    let src: IpAddr = match ev.af {
        af::IPV4 => IpAddr::V4(Ipv4Addr::new(ev.src_ip[0], ev.src_ip[1], ev.src_ip[2], ev.src_ip[3])),
        af::IPV6 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&ev.src_ip);
            IpAddr::V6(Ipv6Addr::from(o))
        }
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let dst: IpAddr = match ev.af {
        af::IPV4 => IpAddr::V4(Ipv4Addr::new(ev.dst_ip[0], ev.dst_ip[1], ev.dst_ip[2], ev.dst_ip[3])),
        af::IPV6 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&ev.dst_ip);
            IpAddr::V6(Ipv6Addr::from(o))
        }
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let threat_level = match ev.threat {
        threat::BENIGN       => ThreatLevel::Benign,
        threat::SUSPICIOUS   => ThreatLevel::Suspicious,
        threat::HOSTILE      => ThreatLevel::Hostile,
        threat::CATASTROPHIC => ThreatLevel::Catastrophic,
        _                    => ThreatLevel::Unknown,
    };
    let conf = (ev.confidence_milli as f32) / 1000.0;

    Signal::new(SignalSource::Network, kind)
        .actor(format!("{src}:{}", ev.src_port))
        .target(format!("{dst}:{}", ev.dst_port))
        .threat(threat_level)
        .confidence(conf)
        .with("src_ip",        serde_json::json!(src.to_string()))
        .with("dst_ip",        serde_json::json!(dst.to_string()))
        .with("src_port",      serde_json::json!(ev.src_port))
        .with("dst_port",      serde_json::json!(ev.dst_port))
        .with("payload_hash",  serde_json::json!(ev.payload_hash))
        .with("kernel_ts_ns",  serde_json::json!(ev.ts_ns))
        .with("af",            serde_json::json!(ev.af))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kspike_kernel::xdp_event::{IP_BYTES, KIND_BYTES, ACTOR_BYTES};

    #[test]
    fn event_roundtrips_to_signal() {
        let mut kind = [0u8; KIND_BYTES];
        let k = b"log4shell.jndi";
        kind[..k.len()].copy_from_slice(k);
        let mut src = [0u8; IP_BYTES]; src[..4].copy_from_slice(&[185,100,87,41]);
        let mut dst = [0u8; IP_BYTES]; dst[..4].copy_from_slice(&[10,0,0,5]);
        let ev = XdpSignalEvent {
            af: af::IPV4, threat: threat::HOSTILE, _pad0: [0;2],
            src_ip: src, dst_ip: dst, src_port: 44321, dst_port: 443,
            confidence_milli: 920, proportionality: 0, _pad1: 0,
            kind, actor: [0; ACTOR_BYTES], payload_hash: 0xdeadbeef, ts_ns: 42,
        };
        let s = event_to_signal(&ev);
        assert_eq!(s.kind, "log4shell.jndi");
        assert_eq!(s.actor.as_deref(), Some("185.100.87.41:44321"));
        assert!(matches!(s.threat, ThreatLevel::Hostile));
    }
}
