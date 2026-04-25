//! /proc/modules + /sys/module/* integrity tap.
//! Detects:
//!   - new modules appearing
//!   - hidden modules (sysfs entry exists but /proc/modules doesn't list it)
//!   - refcnt anomalies (refcnt going up without a known triggering event)

use kspike_core::{Signal, SignalSource, ThreatLevel};
use kspike_kernel::{KernelTap, TapError, TapStatus};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

#[derive(Default)]
pub struct ModulesTap {
    last_proc: Mutex<HashSet<String>>,
    last_refcnt: Mutex<HashMap<String, i64>>,
    status: Mutex<TapStatus>,
}

impl ModulesTap {
    pub fn new() -> Self { Self::default() }

    fn read_proc() -> HashSet<String> {
        let mut out = HashSet::new();
        if let Ok(t) = std::fs::read_to_string("/proc/modules") {
            for line in t.lines() {
                if let Some(name) = line.split_whitespace().next() {
                    out.insert(name.to_string());
                }
            }
        }
        out
    }

    fn read_sysfs() -> HashMap<String, i64> {
        let mut out = HashMap::new();
        if let Ok(rd) = std::fs::read_dir("/sys/module") {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let rc_path = e.path().join("refcnt");
                if let Ok(s) = std::fs::read_to_string(&rc_path) {
                    if let Ok(v) = s.trim().parse::<i64>() {
                        out.insert(name, v);
                    }
                }
            }
        }
        out
    }
}

impl KernelTap for ModulesTap {
    fn name(&self) -> &'static str { "procfs.modules" }
    fn status(&self) -> TapStatus  { *self.status.lock().unwrap() }

    fn poll(&mut self) -> Result<Vec<Signal>, TapError> {
        *self.status.lock().unwrap() = TapStatus::Active;
        let proc_now = Self::read_proc();
        let sys_now  = Self::read_sysfs();

        let mut last_proc   = self.last_proc.lock().unwrap();
        let mut last_refcnt = self.last_refcnt.lock().unwrap();
        let mut out = Vec::new();

        // 1) New modules in /proc/modules
        for m in &proc_now {
            if !last_proc.contains(m) {
                out.push(Signal::new(SignalSource::Kernel, "kernel.module.new")
                    .actor(m.clone())
                    .threat(ThreatLevel::Suspicious)
                    .confidence(0.55)
                    .with("name", serde_json::json!(m)));
            }
        }
        // 2) Hidden modules: in sysfs but not in /proc/modules
        for m in sys_now.keys() {
            if !proc_now.contains(m) {
                // Some modules are built-in and lack a /proc/modules entry —
                // we look only for entries that have a refcnt file (loadable).
                out.push(Signal::new(SignalSource::Kernel, "kernel.rootkit.suspect.lkm_hidden")
                    .actor(m.clone())
                    .target("kernel:/proc/modules")
                    .threat(ThreatLevel::Hostile)
                    .confidence(0.78)
                    .with("name", serde_json::json!(m)));
            }
        }
        // 3) Refcnt anomalies (large jumps).
        for (m, rc) in &sys_now {
            if let Some(prev) = last_refcnt.get(m) {
                let delta = (*rc) - (*prev);
                if delta.abs() >= 4 {
                    out.push(Signal::new(SignalSource::Kernel, "kernel.module.refcnt_anomaly")
                        .actor(m.clone())
                        .threat(ThreatLevel::Suspicious)
                        .confidence(0.50)
                        .with("delta", serde_json::json!(delta))
                        .with("now", serde_json::json!(rc)));
                }
            }
        }

        *last_proc = proc_now;
        *last_refcnt = sys_now;
        Ok(out)
    }
}
