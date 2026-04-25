//! User-space tap that drains LSM events and emits Signals.

use crate::event::LsmEvent;
use kspike_core::{Signal, SignalSource, ThreatLevel};
use kspike_kernel::{KernelTap, TapError, TapStatus};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

pub struct LsmTap {
    queue: Arc<Mutex<VecDeque<LsmEvent>>>,
    status: Mutex<TapStatus>,
}

impl Default for LsmTap {
    fn default() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::with_capacity(1024))),
            status: Mutex::new(TapStatus::Idle),
        }
    }
}

impl LsmTap {
    pub fn new() -> Self { Self::default() }
    pub fn sink(&self) -> Arc<Mutex<VecDeque<LsmEvent>>> { self.queue.clone() }

    /// For tests / replay: inject an event as if it came from the LSM program.
    pub fn inject(&self, ev: LsmEvent) { self.queue.lock().unwrap().push_back(ev); }
}

impl KernelTap for LsmTap {
    fn name(&self) -> &'static str { "ebpf.lsm" }
    fn status(&self) -> TapStatus  { *self.status.lock().unwrap() }

    fn poll(&mut self) -> Result<Vec<Signal>, TapError> {
        *self.status.lock().unwrap() = TapStatus::Active;
        let mut q = self.queue.lock().unwrap();
        let mut out = Vec::with_capacity(q.len());
        while let Some(ev) = q.pop_front() {
            out.push(event_to_signal(&ev));
        }
        Ok(out)
    }
}

pub fn event_to_signal(ev: &LsmEvent) -> Signal {
    let comm = cstr(&ev.comm);
    let path = cstr(&ev.path);
    // For hook==3 (capable), the kind depends on which capability fired.
    let cap_name = cap_to_name(ev.cap);
    let (kind_str, threat, conf): (String, ThreatLevel, f32) = match ev.hook {
        1 => {
            // file_open severity grows with target sensitivity
            let p = path.as_str();
            let sensitive = p.contains("/etc/shadow") || p.contains("/etc/sudoers")
                         || p.contains("/.ssh/id_") || p.contains("/proc/kcore");
            if sensitive {
                ("lsm.file_open.sensitive".into(), ThreatLevel::Suspicious, 0.70)
            } else {
                ("lsm.file_open".into(), ThreatLevel::Unknown, 0.30)
            }
        }
        2 => ("lsm.bprm.exec".into(), ThreatLevel::Suspicious, 0.45),
        3 => (format!("lsm.capable.{cap_name}"),
              if matches!(ev.cap, 16 | 17 | 39) { ThreatLevel::Hostile } else { ThreatLevel::Suspicious },
              if matches!(ev.cap, 16) { 0.85 } else if matches!(ev.cap, 17 | 39) { 0.75 } else { 0.55 }),
        _ => ("lsm.unknown".into(), ThreatLevel::Unknown, 0.20),
    };
    let kind: &str = kind_str.as_str();
    Signal::new(SignalSource::Kernel, kind.to_string())
        .actor(format!("pid={} comm={comm}", ev.pid))
        .target(path.clone())
        .threat(threat)
        .confidence(conf)
        .with("uid", serde_json::json!(ev.uid))
        .with("gid", serde_json::json!(ev.gid))
        .with("cap", serde_json::json!(ev.cap))
        .with("kernel_ts_ns", serde_json::json!(ev.ts_ns))
        .with("path", serde_json::json!(path))
        .with("comm", serde_json::json!(comm))
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Linux capability number → readable name (subset relevant to KSpike).
fn cap_to_name(cap: u32) -> &'static str {
    match cap {
        12 => "net_admin",
        16 => "cap_sys_module",
        17 => "sys_rawio",
        19 => "sys_ptrace",
        21 => "sys_admin",
        39 => "cap_bpf",
        _  => "other",
    }
}
