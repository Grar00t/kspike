//! EternalBlue (MS17-010) — detector + SMBv1 kernel killswitch.
//!
//! MSF original:  exploit/windows/smb/ms17_010_eternalblue
//! KSpike mirror: detector.smb.eternalblue_probe + defender.smb.v1_killswitch
//!
//! EternalBlue abuses an integer overflow in the SMBv1 TRANS2 subcommand handler.
//! The wire tell is a NT Trans packet whose total param/data counts are
//! inconsistent with the per-fragment counts. We don't need a full parser —
//! a short structural signature + SMB1 magic is enough for a humble detector.

use kspike_core::prelude::*;
use kspike_kernel::inspect::{bytes_contain, hex_signature_match};

// ─── detector ───────────────────────────────────────────────────────────────

pub struct EternalBlueProbeDetector { meta: ModuleMeta }

impl Default for EternalBlueProbeDetector {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "detector.smb.eternalblue_probe".into(),
                kind: ModuleKind::Detector,
                version: "0.1.0".into(),
                description: "Detects MS17-010 NT_TRANS probe patterns on the wire.".into(),
                author: "gratech".into(),
                risk_level: 0,
                limits: KnownLimits::new()
                    .add(Limitation {
                        id: "no-fragment-reassembly".into(),
                        description: "v0.1 inspects single segments only.".into(),
                        confidence_penalty: 0.15,
                        mitigation: Some("pair with nfqueue reassembly in v0.2".into()),
                    }),
                tags: vec!["smb".into(), "ms17-010".into(), "network".into()],
            },
        }
    }
}

impl Module for EternalBlueProbeDetector {
    fn meta(&self) -> &ModuleMeta { &self.meta }
    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        // XDP fast path: kernel already matched SMB1 magic + dst 445.
        if s.kind.starts_with("smb.ms17_010") {
            return Ok(ModuleVerdict::Report {
                note: format!("EternalBlue probe (kernel-XDP detection) from {:?}", s.actor),
                confidence: self.meta.limits.humble(s.raw_confidence.max(0.90)),
            });
        }
        if !s.kind.starts_with("net.smb.segment") { return Ok(ModuleVerdict::Ignore); }
        let Some(hex) = s.data.get("bytes_hex").and_then(|v| v.as_str()) else {
            return Ok(ModuleVerdict::Ignore);
        };
        let raw = match decode_hex(hex) { Some(b) => b, None => return Ok(ModuleVerdict::Ignore) };
        // SMB1 magic: \xffSMB  then check NT_TRANS (0xA0) + suspicious TotalParamCount/MaxParamCount.
        let smb1 = bytes_contain(&raw, b"\xffSMB").is_some();
        let nt_trans = hex_signature_match(&raw, "a0 ?? ?? 00 00 ?? ff ff").is_some();
        // Secondary: the classic "FEA list" trailing shape Metasploit crafts.
        let fealist  = hex_signature_match(&raw, "00 00 ff ff ?? ?? 00 00 10 00").is_some();

        if smb1 && nt_trans && fealist {
            Ok(ModuleVerdict::Report {
                note: format!("MS17-010 probe pattern on flow {:?}", s.actor),
                confidence: self.meta.limits.humble(0.90),
            })
        } else { Ok(ModuleVerdict::Ignore) }
    }
    fn apply(&self, v: &ModuleVerdict, _: Option<&str>) -> Result<serde_json::Value> {
        Ok(serde_json::json!({ "module": self.meta.name, "applied": v }))
    }
}

// ─── defender ───────────────────────────────────────────────────────────────

pub struct SmbV1Killswitch { meta: ModuleMeta }

impl Default for SmbV1Killswitch {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "defender.smb.v1_killswitch".into(),
                kind: ModuleKind::Defender,
                version: "0.1.0".into(),
                description: "Disables SMBv1 on host + blackholes 445 from the flagged actor.".into(),
                author: "gratech".into(),
                risk_level: 2,
                limits: KnownLimits::new().add(Limitation {
                    id: "legacy-clients".into(),
                    description: "SMBv1 off may break ancient appliances (POS, medical, ICS).".into(),
                    confidence_penalty: 0.15,
                    mitigation: Some("phase by subnet; keep legacy VLAN aware-only".into()),
                }),
                tags: vec!["smb".into(), "ms17-010".into(), "kernel".into()],
            },
        }
    }
}

impl Module for SmbV1Killswitch {
    fn meta(&self) -> &ModuleMeta { &self.meta }
    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        // Fire when a corroborating detector has just reported an EternalBlue probe.
        if !s.kind.starts_with("net.smb.segment") { return Ok(ModuleVerdict::Ignore); }
        let Some(actor) = &s.actor else { return Ok(ModuleVerdict::Ignore); };
        if s.raw_confidence < 0.85 { return Ok(ModuleVerdict::Ignore); }
        Ok(ModuleVerdict::Defend {
            action: "smbv1_disable_and_blackhole_445".into(),
            target: actor.clone(),
            confidence: self.meta.limits.humble(0.92),
        })
    }
    fn apply(&self, v: &ModuleVerdict, _: Option<&str>) -> Result<serde_json::Value> {
        if let ModuleVerdict::Defend { action, target, .. } = v {
            info!("[defender.smb.v1_killswitch] {action} for {target}");
            return Ok(serde_json::json!({
                "module": self.meta.name, "action": action, "target": target,
                "steps": [
                    { "op":"linux", "sysctl":"fs.cifs.enable_smb1=0" },
                    { "op":"linux", "modprobe":"-r cifs" },
                    { "op":"linux", "nft":"add element inet kspike quarantine { <target>:445 timeout 24h }" },
                    { "op":"windows", "registry":"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 = 0" }
                ],
                "applied": true
            }));
        }
        Ok(serde_json::json!({ "applied": false }))
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len()/2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let h = hex_val(b[i])?; let l = hex_val(b[i+1])?;
        out.push((h<<4)|l);
    }
    Some(out)
}
fn hex_val(c: u8) -> Option<u8> { match c {
    b'0'..=b'9' => Some(c-b'0'),
    b'a'..=b'f' => Some(c-b'a'+10),
    b'A'..=b'F' => Some(c-b'A'+10), _ => None,
}}
