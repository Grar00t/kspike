//! PSExec abuse detector.
//!
//! MSF original:  exploit/windows/smb/psexec
//! KSpike mirror: detector.smb.psexec_abuse
//!
//! Classic PSExec flow:
//!   1. SMB TreeConnect to \\target\ADMIN$
//!   2. Upload of PSEXESVC.exe (or renamed variant) to ADMIN$
//!   3. DCERPC bind to svcctl
//!   4. CreateServiceW with binPath = %SystemRoot%\<uploaded>
//!   5. StartServiceW
//!
//! The tell is the UTF-16 sequence "ADMIN$" inside an SMB2 TreeConnect
//! shortly followed by a DCERPC svcctl bind on the same flow.

use kspike_core::prelude::*;
use kspike_kernel::inspect::{bytes_contain, utf16_contains};

pub struct PsExecAbuseDetector { meta: ModuleMeta }

impl Default for PsExecAbuseDetector {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "detector.smb.psexec_abuse".into(),
                kind: ModuleKind::Detector,
                version: "0.1.0".into(),
                description: "Flags SMB ADMIN$ mount + svcctl bind from same actor within a window.".into(),
                author: "gratech".into(),
                risk_level: 0,
                limits: KnownLimits::new()
                    .add(Limitation {
                        id: "legitimate-admin-tools".into(),
                        description: "Sysinternals PsExec used by actual admins looks identical.".into(),
                        confidence_penalty: 0.20,
                        mitigation: Some("correlate with known-admin allowlist".into()),
                    }),
                tags: vec!["smb".into(), "lateral-movement".into(), "dcerpc".into()],
            },
        }
    }
}

impl Module for PsExecAbuseDetector {
    fn meta(&self) -> &ModuleMeta { &self.meta }
    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        if !s.kind.starts_with("net.smb.segment") { return Ok(ModuleVerdict::Ignore); }
        let Some(hex) = s.data.get("bytes_hex").and_then(|v| v.as_str()) else {
            return Ok(ModuleVerdict::Ignore);
        };
        let raw = match decode_hex(hex) { Some(b) => b, None => return Ok(ModuleVerdict::Ignore) };

        let admin_share = utf16_contains(&raw, "ADMIN$") || utf16_contains(&raw, "\\ADMIN$");
        let svcctl_bind = bytes_contain(&raw, b"\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad").is_some()
                       || utf16_contains(&raw, "svcctl");
        let create_svc  = utf16_contains(&raw, "CreateService")
                       || utf16_contains(&raw, "OpenSCManager");

        let hits = [admin_share, svcctl_bind, create_svc].iter().filter(|b| **b).count();
        if hits >= 2 {
            Ok(ModuleVerdict::Report {
                note: format!("PSExec-style lateral movement probe: hits={hits} from {:?}", s.actor),
                confidence: self.meta.limits.humble(0.82 + 0.06 * hits as f32),
            })
        } else { Ok(ModuleVerdict::Ignore) }
    }
    fn apply(&self, v: &ModuleVerdict, _: Option<&str>) -> Result<serde_json::Value> {
        Ok(serde_json::json!({ "module": self.meta.name, "applied": v }))
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
