//! Kerberoasting detector.
//!
//! MSF / Impacket tools: GetUserSPNs.py, Rubeus
//! KSpike mirror: detector.ad.kerberoasting
//!
//! An attacker requests TGS service tickets (AS-REP / TGS-REP) for accounts
//! with weak passwords, then cracks them offline. The wire tell:
//!   • Kerberos KRB_TGS_REQ sequence of ≥ N ticket requests for different
//!     Service Principal Names from the same user within a short window.
//!   • Encryption types including RC4-HMAC (0x17) — deprecated but common for
//!     roastable accounts.

use kspike_core::prelude::*;
use kspike_kernel::inspect::{bytes_contain, hex_signature_match};

pub struct KerberoastDetector { meta: ModuleMeta }

impl Default for KerberoastDetector {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "detector.ad.kerberoasting".into(),
                kind: ModuleKind::Detector,
                version: "0.1.0".into(),
                description: "Flags bursts of TGS-REQ for multiple SPNs w/ RC4 from a single user.".into(),
                author: "gratech".into(),
                risk_level: 0,
                limits: KnownLimits::new()
                    .add(Limitation {
                        id: "no-ad-context".into(),
                        description: "v0.1 doesn't know which SPNs are service accounts vs users.".into(),
                        confidence_penalty: 0.15,
                        mitigation: Some("enrich with AD context in v0.2 (LDAP pull of servicePrincipalName set)".into()),
                    }),
                tags: vec!["kerberos".into(), "active-directory".into(), "ticket".into()],
            },
        }
    }
}

impl Module for KerberoastDetector {
    fn meta(&self) -> &ModuleMeta { &self.meta }
    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        if !s.kind.starts_with("net.kerberos.tgs_req") { return Ok(ModuleVerdict::Ignore); }
        let spn_count  = s.data.get("distinct_spns").and_then(|v| v.as_u64()).unwrap_or(0);
        let rc4_ratio  = s.data.get("etype_rc4_ratio").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
        let window_sec = s.data.get("window_seconds").and_then(|v| v.as_u64()).unwrap_or(60);
        let has_krbtgt_encoding = s.data.get("bytes_hex").and_then(|v| v.as_str())
            .and_then(decode_hex)
            .map(|b| hex_signature_match(&b, "a0 03 02 01 05 a1 03 02 01 0c").is_some() // Kerb PVNO=5, MSG-TYPE=TGS-REQ(12)
                  || bytes_contain(&b, b"krbtgt").is_some())
            .unwrap_or(false);

        let heat: f32 = (spn_count.min(20) as f32 / 20.0) * 0.5
                      + rc4_ratio * 0.4
                      + (if has_krbtgt_encoding {0.10} else {0.0});

        if spn_count >= 5 && window_sec <= 300 && heat >= 0.45 {
            Ok(ModuleVerdict::Report {
                note: format!("kerberoasting suspected: {spn_count} SPNs in {window_sec}s, rc4_ratio={rc4_ratio:.2}"),
                confidence: self.meta.limits.humble(heat.min(0.95)),
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
