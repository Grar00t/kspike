//! Canary-token deception module (Thinkst-style).
//!
//! MSF equivalent: (none — this is a pure defensive/deceptive construct.)
//! KSpike module:  deception.canary_token
//!
//! We register DNS, URL, and file tripwires — any access to them anywhere
//! on the host or network implies hostile reconnaissance or data theft.

use kspike_core::prelude::*;
use kspike_kernel::canary::{CanaryToken, MemoryCanary};
use std::sync::Arc;

pub struct CanaryTokenDeception {
    meta: ModuleMeta,
    registry: Arc<MemoryCanary>,
}

impl CanaryTokenDeception {
    pub fn new(registry: Arc<MemoryCanary>) -> Self {
        for (placement, bait) in [
            ("dns.canary.gratech.local", b"kspike-canary-dns.gratech.local".as_slice()),
            ("url.canary.s3",            b"https://s3.amazonaws.com/kspike-canary-bucket/keys.zip"),
            ("file.canary.passwords.xlsx", b"Passwords_2026_FINAL.xlsx"),
            ("file.canary.backup.zip",     b"backup_2026_gratech_FULL.zip"),
        ] {
            registry.plant(CanaryToken::new(placement, bait.to_vec()));
        }
        Self {
            meta: ModuleMeta {
                name: "deception.canary_token".into(),
                kind: ModuleKind::Deception,
                version: "0.1.0".into(),
                description: "Registers DNS/URL/file tripwires; any touch implies hostile recon.".into(),
                author: "gratech".into(),
                risk_level: 0,
                limits: KnownLimits::new().add(Limitation {
                    id: "dns-resolver-noise".into(),
                    description: "Some recursive resolvers prefetch any recently seen name, causing false positives.".into(),
                    confidence_penalty: 0.10,
                    mitigation: Some("ignore resolver-originating lookups from trusted CIDRs".into()),
                }),
                tags: vec!["deception".into(), "canary".into(), "tripwire".into()],
            },
            registry,
        }
    }
}

impl Default for CanaryTokenDeception {
    fn default() -> Self { Self::new(Arc::new(MemoryCanary::new())) }
}

impl Module for CanaryTokenDeception {
    fn meta(&self) -> &ModuleMeta { &self.meta }
    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        // Any signal with a text/bytes payload → scan for our needles.
        let cand: Option<Vec<u8>> = if let Some(t) = s.data.get("text").and_then(|v| v.as_str()) {
            Some(t.as_bytes().to_vec())
        } else if let Some(q) = s.data.get("dns_query").and_then(|v| v.as_str()) {
            Some(q.as_bytes().to_vec())
        } else if let Some(u) = s.data.get("url").and_then(|v| v.as_str()) {
            Some(u.as_bytes().to_vec())
        } else { None };

        let Some(buf) = cand else { return Ok(ModuleVerdict::Ignore); };
        let hits = self.registry.scan(&buf);
        if hits.is_empty() { return Ok(ModuleVerdict::Ignore); }

        let placements: Vec<String> = hits.iter().map(|t| t.placement.clone()).collect();
        Ok(ModuleVerdict::Report {
            note: format!("canary tripped: {placements:?} by {:?}", s.actor),
            confidence: self.meta.limits.humble(0.97),
        })
    }
    fn apply(&self, v: &ModuleVerdict, _: Option<&str>) -> Result<serde_json::Value> {
        Ok(serde_json::json!({ "module": self.meta.name, "applied": v }))
    }
}
