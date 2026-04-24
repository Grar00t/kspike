//! Credential-dump canary.
//!
//! MSF original:  post/windows/gather/hashdump, post/windows/gather/credentials/*
//! KSpike mirror: defender.cred.dump_canary
//!
//! We plant fake credentials (usernames + passwords) into memory regions the
//! attacker will scan. The fakes NEVER grant access. If they ever appear in
//! an outbound packet, an auth attempt, or a suspicious file write — the
//! attacker is caught red-handed, and we know which placement was bitten.

use kspike_core::prelude::*;
use kspike_kernel::canary::{CanaryToken, MemoryCanary};
use std::sync::Arc;

pub struct CredDumpCanaryDefender {
    meta: ModuleMeta,
    registry: Arc<MemoryCanary>,
}

impl CredDumpCanaryDefender {
    pub fn new(registry: Arc<MemoryCanary>) -> Self {
        // Plant a starter set of fake credentials on construction.
        for (placement, user) in [
            ("lsass.stub.Administrator", "Administrator"),
            ("lsass.stub.svc_backup",    "svc-backup"),
            ("lsass.stub.helpdesk",      "helpdesk.admin"),
            ("dpapi.stub.aws_access",    "AKIA00CANARY000000"),
            ("browser.stub.chrome",      "canary@example.local"),
        ] {
            registry.plant(CanaryToken::as_credential(placement, user));
        }
        Self {
            meta: ModuleMeta {
                name: "defender.cred.dump_canary".into(),
                kind: ModuleKind::Defender,
                version: "0.1.0".into(),
                description: "Plants fake credentials + scans outbound flows for any usage.".into(),
                author: "gratech".into(),
                risk_level: 1,
                limits: KnownLimits::new().add(Limitation {
                    id: "memory-only-scan".into(),
                    description: "v0.1 only scans flows passed as signals; OS memory scan is v0.2.".into(),
                    confidence_penalty: 0.10,
                    mitigation: Some("integrate with eBPF LSM hooks in v0.2".into()),
                }),
                tags: vec!["deception".into(), "credentials".into(), "lsass".into()],
            },
            registry,
        }
    }
}

impl Default for CredDumpCanaryDefender {
    fn default() -> Self { Self::new(Arc::new(MemoryCanary::new())) }
}

impl Module for CredDumpCanaryDefender {
    fn meta(&self) -> &ModuleMeta { &self.meta }
    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        // Scan any flow payload (or auth attempt) for canary needles.
        let candidate_bytes: Option<Vec<u8>> = if let Some(h) = s.data.get("bytes_hex").and_then(|v| v.as_str()) {
            decode_hex(h)
        } else if let Some(t) = s.data.get("text").and_then(|v| v.as_str()) {
            Some(t.as_bytes().to_vec())
        } else if let Some(u) = s.data.get("auth_user").and_then(|v| v.as_str()) {
            Some(u.as_bytes().to_vec())
        } else { None };

        let Some(buf) = candidate_bytes else { return Ok(ModuleVerdict::Ignore); };
        let hits = self.registry.scan(&buf);
        if hits.is_empty() { return Ok(ModuleVerdict::Ignore); }

        Ok(ModuleVerdict::Defend {
            action: "quarantine_and_page_operator".into(),
            target: s.actor.clone().unwrap_or_else(|| "unknown".into()),
            confidence: self.meta.limits.humble(0.99), // canary = near-certain attacker
        })
    }

    fn apply(&self, v: &ModuleVerdict, _: Option<&str>) -> Result<serde_json::Value> {
        if let ModuleVerdict::Defend { action, target, .. } = v {
            warn!("[defender.cred.dump_canary] ★ canary bitten by {target}");
            return Ok(serde_json::json!({
                "module": self.meta.name, "action": action, "target": target,
                "canaries_planted": self.registry.all().len(),
                "page_operator": true, "applied": true,
            }));
        }
        Ok(serde_json::json!({ "applied": false }))
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len()/2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = hv(b[i])?; let lo = hv(b[i+1])?;
        out.push((hi<<4)|lo);
    }
    Some(out)
}
fn hv(c: u8) -> Option<u8> { match c {
    b'0'..=b'9' => Some(c-b'0'),
    b'a'..=b'f' => Some(c-b'a'+10),
    b'A'..=b'F' => Some(c-b'A'+10), _ => None,
}}
