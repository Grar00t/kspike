//! /proc/net/tcp{,6} tap. Emits one `Signal` per *new* connection observed
//! since the previous poll. State changes are intentionally not flooded —
//! we report only LISTEN openings and ESTABLISHED transitions to remote peers.

use crate::parse::{parse_proc_tcp_addr, tcp_state_name};
use kspike_core::{Signal, SignalSource, ThreatLevel};
use kspike_kernel::{KernelTap, TapError, TapStatus};
use std::collections::HashSet;
use std::sync::Mutex;

pub struct TcpTap {
    seen: Mutex<HashSet<(String, String, &'static str)>>,
    status: Mutex<TapStatus>,
}

impl Default for TcpTap {
    fn default() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            status: Mutex::new(TapStatus::Idle),
        }
    }
}

impl TcpTap {
    pub fn new() -> Self { Self::default() }

    fn read_one(path: &str, family_label: &str) -> Vec<(String, String, &'static str)> {
        let mut out = Vec::new();
        let txt = match std::fs::read_to_string(path) {
            Ok(t) => t, Err(_) => return out,
        };
        for line in txt.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 { continue; }
            let local  = f[1];
            let remote = f[2];
            let state_h = f[3];
            let state = u8::from_str_radix(state_h, 16).unwrap_or(0);
            let name = tcp_state_name(state);
            // Only LISTEN openings + ESTABLISHED to remote.
            let interesting = name == "LISTEN" || name == "ESTABLISHED";
            if !interesting { continue; }
            let local_pp = match parse_proc_tcp_addr(local) {
                Some((a,p)) => format!("{a}:{p} ({family_label})"),
                None => continue,
            };
            let remote_pp = match parse_proc_tcp_addr(remote) {
                Some((a,p)) => format!("{a}:{p}"),
                None => continue,
            };
            out.push((local_pp, remote_pp, name));
        }
        out
    }
}

impl KernelTap for TcpTap {
    fn name(&self) -> &'static str { "procfs.tcp" }
    fn status(&self) -> TapStatus  { *self.status.lock().unwrap() }

    fn poll(&mut self) -> Result<Vec<Signal>, TapError> {
        *self.status.lock().unwrap() = TapStatus::Active;
        let mut snapshot = Self::read_one("/proc/net/tcp",  "v4");
        snapshot.extend(Self::read_one("/proc/net/tcp6", "v6"));

        let mut new_set = HashSet::new();
        for s in &snapshot { new_set.insert(s.clone()); }

        let mut out = Vec::new();
        let mut seen = self.seen.lock().unwrap();
        for s in &new_set {
            if seen.contains(s) { continue; }
            let (local, remote, state) = s;
            let kind = match *state {
                "LISTEN"      => "proc.tcp.listen",
                "ESTABLISHED" => "proc.tcp.established",
                _             => "proc.tcp.state",
            };
            out.push(Signal::new(SignalSource::Kernel, kind)
                .actor(remote.clone())
                .target(local.clone())
                .threat(ThreatLevel::Unknown)
                .confidence(0.4)
                .with("state", serde_json::json!(state)));
        }
        *seen = new_set;
        Ok(out)
    }
}
