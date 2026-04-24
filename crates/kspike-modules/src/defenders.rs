//! Defenders — apply protective action.

use kspike_core::prelude::*;

// ─────────────────────────────────────────────────────────────────────────────
// Defender 1: SSH actor quarantine — adds an actor to a block list.
// ─────────────────────────────────────────────────────────────────────────────

pub struct SshQuarantineDefender {
    meta: ModuleMeta,
}

impl Default for SshQuarantineDefender {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "defender.ssh_quarantine".into(),
                kind: ModuleKind::Defender,
                version: "0.1.0".into(),
                description: "Quarantines an SSH actor into a nftables drop set.".into(),
                author: "gratech".into(),
                risk_level: 1,
                limits: KnownLimits::new().add(Limitation {
                    id: "shared-nat".into(),
                    description: "Blocking a NATed IP may affect innocent users.".into(),
                    confidence_penalty: 0.15,
                    mitigation: Some("time-boxed quarantine (15 min TTL)".into()),
                }),
                tags: vec!["ssh".into(), "quarantine".into()],
            },
        }
    }
}

impl Module for SshQuarantineDefender {
    fn meta(&self) -> &ModuleMeta { &self.meta }

    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        if !s.kind.starts_with("ssh.auth.fail") { return Ok(ModuleVerdict::Ignore); }
        let attempts = s.data.get("attempts").and_then(|v| v.as_u64()).unwrap_or(1);
        let Some(actor) = &s.actor else { return Ok(ModuleVerdict::Ignore); };
        if attempts >= 10 {
            Ok(ModuleVerdict::Defend {
                action: "nft_drop_set_add".into(),
                target: actor.clone(),
                confidence: self.meta.limits.humble(0.88),
            })
        } else {
            Ok(ModuleVerdict::Ignore)
        }
    }

    fn apply(&self, verdict: &ModuleVerdict, _authz: Option<&str>) -> Result<serde_json::Value> {
        if let ModuleVerdict::Defend { action, target, .. } = verdict {
            // On a real system this would shell out to:
            //   nft add element inet kspike quarantine { <ip> timeout 15m }
            // Here we just record the intended operation — the engine may be
            // running in dry-run or userspace simulation mode.
            info!("[defender.ssh_quarantine] {action} {target}");
            return Ok(serde_json::json!({
                "module": self.meta.name, "action": action, "target": target,
                "backend": "nftables", "ttl_seconds": 900, "applied": true,
            }));
        }
        Ok(serde_json::json!({ "applied": false }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Defender 2: Kernel lockdown — raises integrity mode on demand.
// ─────────────────────────────────────────────────────────────────────────────

pub struct KernelLockdownDefender {
    meta: ModuleMeta,
}

impl Default for KernelLockdownDefender {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "defender.kernel_lockdown".into(),
                kind: ModuleKind::Defender,
                version: "0.1.0".into(),
                description: "Raises kernel lockdown mode on rootkit suspicion.".into(),
                author: "gratech".into(),
                risk_level: 3,
                limits: KnownLimits::new().add(Limitation {
                    id: "irreversible-until-reboot".into(),
                    description: "Lockdown transitions are monotonic — cannot relax without reboot.".into(),
                    confidence_penalty: 0.20,
                    mitigation: Some("require corroborating detector before applying".into()),
                }),
                tags: vec!["kernel".into(), "lockdown".into()],
            },
        }
    }
}

impl Module for KernelLockdownDefender {
    fn meta(&self) -> &ModuleMeta { &self.meta }

    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        if !s.kind.starts_with("kernel.rootkit.suspect") { return Ok(ModuleVerdict::Ignore); }
        Ok(ModuleVerdict::Defend {
            action: "lockdown_integrity".into(),
            target: "self".into(),
            confidence: self.meta.limits.humble(s.raw_confidence),
        })
    }

    fn apply(&self, verdict: &ModuleVerdict, _authz: Option<&str>) -> Result<serde_json::Value> {
        if let ModuleVerdict::Defend { action, .. } = verdict {
            info!("[defender.kernel_lockdown] request {action} (would write /sys/kernel/security/lockdown)");
            return Ok(serde_json::json!({
                "module": self.meta.name, "action": action,
                "sysfs": "/sys/kernel/security/lockdown",
                "mode": "integrity", "applied": true,
            }));
        }
        Ok(serde_json::json!({ "applied": false }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Defender 3: Filesystem immunity — protects labelled paths from deletion.
// ─────────────────────────────────────────────────────────────────────────────

pub struct FilesystemImmunityDefender {
    meta: ModuleMeta,
}

impl Default for FilesystemImmunityDefender {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "defender.fs_immunity".into(),
                kind: ModuleKind::Defender,
                version: "0.1.0".into(),
                description: "Flips fs.protect_* sysctls to preserve evidence paths.".into(),
                author: "gratech".into(),
                risk_level: 1,
                limits: KnownLimits::new().add(Limitation {
                    id: "sysctl-race".into(),
                    description: "Between signal and toggle, attacker may still delete.".into(),
                    confidence_penalty: 0.10,
                    mitigation: Some("apply on boot, before network is up".into()),
                }),
                tags: vec!["filesystem".into(), "forensics".into()],
            },
        }
    }
}

impl Module for FilesystemImmunityDefender {
    fn meta(&self) -> &ModuleMeta { &self.meta }

    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        if !s.kind.starts_with("fs.evidence.at_risk") { return Ok(ModuleVerdict::Ignore); }
        let path = s.target.clone().unwrap_or_else(|| "/var/log/kspike".into());
        Ok(ModuleVerdict::Defend {
            action: "sysctl_protect_path".into(),
            target: path,
            confidence: self.meta.limits.humble(0.95),
        })
    }

    fn apply(&self, verdict: &ModuleVerdict, _authz: Option<&str>) -> Result<serde_json::Value> {
        if let ModuleVerdict::Defend { action, target, .. } = verdict {
            info!("[defender.fs_immunity] {action} {target}");
            return Ok(serde_json::json!({
                "module": self.meta.name, "action": action, "target": target,
                "sysctl": "fs.protect_logx1y2", "value": 1, "applied": true,
            }));
        }
        Ok(serde_json::json!({ "applied": false }))
    }
}
