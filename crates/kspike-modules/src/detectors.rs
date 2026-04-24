//! Detectors — passive observers. They only emit `Report` verdicts.

use kspike_core::prelude::*;

/// Detects repeated failed auth attempts from the same actor inside a window.
pub struct SshBruteforceDetector {
    meta: ModuleMeta,
}

impl Default for SshBruteforceDetector {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "detector.ssh_bruteforce".into(),
                kind: ModuleKind::Detector,
                version: "0.1.0".into(),
                description: "Reports high-velocity SSH auth failures.".into(),
                author: "gratech".into(),
                risk_level: 0,
                limits: KnownLimits::new()
                    .add(Limitation {
                        id: "ipv6-nat".into(),
                        description: "False-positives possible on shared IPv6 NAT.".into(),
                        confidence_penalty: 0.10,
                        mitigation: Some("require 20+ attempts rather than 10".into()),
                    }),
                tags: vec!["ssh".into(), "auth".into()],
            },
        }
    }
}

impl Module for SshBruteforceDetector {
    fn meta(&self) -> &ModuleMeta { &self.meta }

    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        if !s.kind.starts_with("ssh.auth.fail") {
            return Ok(ModuleVerdict::Ignore);
        }
        let attempts = s.data.get("attempts").and_then(|v| v.as_u64()).unwrap_or(1);
        if attempts >= 10 {
            Ok(ModuleVerdict::Report {
                note: format!("ssh bruteforce suspected: {} attempts from {:?}",
                              attempts, s.actor),
                confidence: self.meta.limits.humble(0.92),
            })
        } else {
            Ok(ModuleVerdict::Ignore)
        }
    }

    fn apply(&self, verdict: &ModuleVerdict, _authz: Option<&str>) -> Result<serde_json::Value> {
        Ok(serde_json::json!({ "module": self.meta.name, "applied": verdict }))
    }
}
