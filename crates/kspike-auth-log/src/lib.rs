//! `/var/log/auth.log` (or journald-equivalent) tap.
//!
//! Recognises:
//!   • sshd "Failed password" + "Invalid user"        → ssh.auth.fail
//!   • sshd "Accepted publickey/password"             → ssh.auth.ok
//!   • sudo "authentication failure"                  → sudo.auth.fail
//!   • PAM "session opened/closed for user"           → pam.session
//!
//! Aggregates failures per (user, src_ip) over a sliding window and emits a
//! single high-confidence `ssh.auth.fail.burst` once a threshold is hit.

use chrono::{DateTime, Utc};
use kspike_core::{Signal, SignalSource, ThreatLevel};
use kspike_kernel::{KernelTap, TapError, TapStatus};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Mutex;

pub struct AuthLogTap {
    path: PathBuf,
    pos: Mutex<u64>,
    bursts: Mutex<HashMap<(String, String), (u64, DateTime<Utc>)>>,
    status: Mutex<TapStatus>,
    burst_threshold: u64,
    burst_window_seconds: i64,
}

impl AuthLogTap {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            pos: Mutex::new(0),
            bursts: Mutex::new(HashMap::new()),
            status: Mutex::new(TapStatus::Idle),
            burst_threshold: 10,
            burst_window_seconds: 60,
        }
    }

    pub fn ubuntu() -> Self { Self::new("/var/log/auth.log") }
    pub fn rhel()   -> Self { Self::new("/var/log/secure") }
}

impl KernelTap for AuthLogTap {
    fn name(&self) -> &'static str { "auth_log" }
    fn status(&self) -> TapStatus  { *self.status.lock().unwrap() }

    fn poll(&mut self) -> Result<Vec<Signal>, TapError> {
        *self.status.lock().unwrap() = TapStatus::Active;
        let mut f = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(_) => { return Ok(vec![]); }   // silently absent on non-Linux
        };
        let mut pos = self.pos.lock().unwrap();
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if *pos > len { *pos = 0; }            // log rotated
        f.seek(SeekFrom::Start(*pos))?;
        let mut rdr = BufReader::new(f);
        let mut out = Vec::new();
        let mut bursts = self.bursts.lock().unwrap();
        let now = Utc::now();
        let mut new_pos = *pos;
        for line in rdr.by_ref().lines() {
            let line = match line { Ok(l) => l, Err(_) => break };
            new_pos += (line.len() + 1) as u64;
            if let Some(sig) = classify(&line, &now, &mut bursts,
                                        self.burst_threshold,
                                        self.burst_window_seconds)
            {
                out.push(sig);
            }
        }
        *pos = new_pos;
        Ok(out)
    }
}

fn classify(
    line: &str,
    now: &DateTime<Utc>,
    bursts: &mut HashMap<(String, String), (u64, DateTime<Utc>)>,
    threshold: u64,
    window_secs: i64,
) -> Option<Signal>
{
    if line.contains("sshd[") {
        if line.contains("Failed password") || line.contains("Invalid user") {
            let user = extract_after(line, "for ").or_else(|| extract_after(line, "user ")).unwrap_or("?".into());
            let ip   = extract_after(line, "from ").unwrap_or("?".into());
            let key  = (user.clone(), ip.clone());
            let ent = bursts.entry(key.clone()).or_insert((0, *now));
            ent.0 += 1;
            let in_window = (*now - ent.1).num_seconds() <= window_secs;
            if !in_window { ent.0 = 1; ent.1 = *now; }
            if ent.0 >= threshold {
                let attempts = ent.0;
                ent.0 = 0; ent.1 = *now;       // reset
                return Some(
                    Signal::new(SignalSource::AuthLog, "ssh.auth.fail.burst")
                        .actor(ip)
                        .target("sshd")
                        .threat(ThreatLevel::Hostile)
                        .confidence(0.93)
                        .with("attempts", serde_json::json!(attempts))
                        .with("user", serde_json::json!(user))
                );
            }
            return Some(
                Signal::new(SignalSource::AuthLog, "ssh.auth.fail")
                    .actor(ip)
                    .target("sshd")
                    .threat(ThreatLevel::Suspicious)
                    .confidence(0.55)
            );
        }
        if line.contains("Accepted publickey") || line.contains("Accepted password") {
            let user = extract_after(line, "for ").unwrap_or("?".into());
            let ip   = extract_after(line, "from ").unwrap_or("?".into());
            return Some(
                Signal::new(SignalSource::AuthLog, "ssh.auth.ok")
                    .actor(ip).target(format!("user:{user}"))
                    .threat(ThreatLevel::Benign).confidence(0.90)
            );
        }
    }
    if line.contains("sudo") && line.contains("authentication failure") {
        let ruser = extract_after(line, "ruser=").unwrap_or("?".into());
        return Some(
            Signal::new(SignalSource::AuthLog, "sudo.auth.fail")
                .actor(ruser).target("sudo")
                .threat(ThreatLevel::Suspicious).confidence(0.65)
        );
    }
    if line.contains("session opened for user") {
        let user = extract_after(line, "user ").unwrap_or("?".into());
        return Some(
            Signal::new(SignalSource::AuthLog, "pam.session.open")
                .actor(user).threat(ThreatLevel::Benign).confidence(0.40)
        );
    }
    None
}

fn extract_after(s: &str, tag: &str) -> Option<String> {
    let i = s.find(tag)? + tag.len();
    let rest = &s[i..];
    let end = rest.find(|c: char| c.is_whitespace() || c == ',').unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_failed_password() {
        let line = "Apr 24 22:11:00 host sshd[1234]: Failed password for invalid user admin from 198.51.100.99 port 33222 ssh2";
        let mut b = HashMap::new();
        let s = classify(line, &Utc::now(), &mut b, 10, 60).unwrap();
        assert_eq!(s.kind, "ssh.auth.fail");
        assert_eq!(s.actor.as_deref(), Some("198.51.100.99"));
    }
}
