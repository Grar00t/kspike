//! Strikers — offensive modules. EVERY striker requires judge authorization
//! (passed as `authz: Some(&str)` into `apply`). `apply` MUST refuse if
//! authz is None, even if somehow invoked directly.

use kspike_core::prelude::*;

// ─────────────────────────────────────────────────────────────────────────────
// Striker 1: C2 burn — sinks the attacker's command-and-control channel.
// ─────────────────────────────────────────────────────────────────────────────

pub struct C2BurnStriker {
    meta: ModuleMeta,
}

impl Default for C2BurnStriker {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "striker.c2_burn".into(),
                kind: ModuleKind::Striker,
                version: "0.1.0".into(),
                description: "Black-holes an identified attacker C2 via null-route + DNS poison.".into(),
                author: "gratech".into(),
                risk_level: 7,
                limits: KnownLimits::new()
                    .add(Limitation {
                        id: "attribution-uncertainty".into(),
                        description: "C2 identity may be spoofed; burning a decoy harms nothing we can reach anyway, but wastes an action.".into(),
                        confidence_penalty: 0.25,
                        mitigation: Some("require 2 independent corroborations".into()),
                    })
                    .add(Limitation {
                        id: "shared-infra".into(),
                        description: "C2 may share hosting with legitimate services.".into(),
                        confidence_penalty: 0.25,
                        mitigation: Some("prefer domain-level sinkhole over IP-level".into()),
                    }),
                tags: vec!["c2".into(), "network".into(), "offensive".into()],
            },
        }
    }
}

impl Module for C2BurnStriker {
    fn meta(&self) -> &ModuleMeta { &self.meta }

    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        if !s.kind.starts_with("c2.confirmed") { return Ok(ModuleVerdict::Ignore); }
        let Some(target) = &s.target else { return Ok(ModuleVerdict::Ignore); };
        let conf = self.meta.limits.humble(s.raw_confidence);
        Ok(ModuleVerdict::RequestStrike {
            action: "blackhole_route_and_dns_sink".into(),
            target: target.clone(),
            justification: format!("confirmed C2 channel at {target} with humble confidence {conf:.2}"),
            confidence: conf,
            proportionality: 4,
        })
    }

    fn apply(&self, verdict: &ModuleVerdict, authz: Option<&str>) -> Result<serde_json::Value> {
        let Some(note) = authz else {
            return Err(KSpikeError::RoeViolation(
                "striker.c2_burn called without judge authorization".into()));
        };
        if let ModuleVerdict::RequestStrike { action, target, .. } = verdict {
            warn!("[striker.c2_burn] authorized_by={note} action={action} target={target}");
            return Ok(serde_json::json!({
                "module": self.meta.name, "action": action, "target": target,
                "authorized_by": note,
                "steps": [
                    {"op":"route", "cmd":"ip route add blackhole <target>"},
                    {"op":"dns",   "cmd":"unbound-control local_zone <target> static"}
                ],
                "applied": true
            }));
        }
        Ok(serde_json::json!({ "applied": false }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Striker 2: Traceback beacon — plants a tracker that exposes attacker infra
// via outbound callbacks (legal gray; requires risk_level 8 and dual auth).
// ─────────────────────────────────────────────────────────────────────────────

pub struct TracebackBeaconStriker {
    meta: ModuleMeta,
}

impl Default for TracebackBeaconStriker {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "striker.traceback_beacon".into(),
                kind: ModuleKind::Striker,
                version: "0.1.0".into(),
                description: "Plants a canary document that beacons attacker's exfil path on open.".into(),
                author: "gratech".into(),
                risk_level: 8,
                limits: KnownLimits::new()
                    .add(Limitation {
                        id: "legal-gray".into(),
                        description: "Beacons crossing borders may breach other jurisdictions' laws.".into(),
                        confidence_penalty: 0.30,
                        mitigation: Some("restrict to passive-only beacons (no payload)".into()),
                    })
                    .add(Limitation {
                        id: "innocent-open".into(),
                        description: "A non-attacker opening the canary triggers a false trace.".into(),
                        confidence_penalty: 0.20,
                        mitigation: Some("embed only in attacker-facing honeypots".into()),
                    }),
                tags: vec!["deception".into(), "forensics".into(), "offensive".into()],
            },
        }
    }
}

impl Module for TracebackBeaconStriker {
    fn meta(&self) -> &ModuleMeta { &self.meta }

    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        if !s.kind.starts_with("exfil.suspected") { return Ok(ModuleVerdict::Ignore); }
        let Some(target) = &s.target else { return Ok(ModuleVerdict::Ignore); };
        Ok(ModuleVerdict::RequestStrike {
            action: "deploy_canary_beacon".into(),
            target: target.clone(),
            justification: "exfil path hypothesised; beacon will confirm or clear".into(),
            confidence: self.meta.limits.humble(s.raw_confidence),
            proportionality: 3,
        })
    }

    fn apply(&self, verdict: &ModuleVerdict, authz: Option<&str>) -> Result<serde_json::Value> {
        let Some(note) = authz else {
            return Err(KSpikeError::RoeViolation(
                "striker.traceback_beacon called without judge authorization".into()));
        };
        if let ModuleVerdict::RequestStrike { action, target, .. } = verdict {
            warn!("[striker.traceback_beacon] authorized_by={note} action={action} target={target}");
            return Ok(serde_json::json!({
                "module": self.meta.name, "action": action, "target": target,
                "authorized_by": note,
                "canary_id": format!("cnr-{:x}", rand_id()),
                "beacon_mode": "passive_dns_only",
                "applied": true
            }));
        }
        Ok(serde_json::json!({ "applied": false }))
    }
}

fn rand_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}
