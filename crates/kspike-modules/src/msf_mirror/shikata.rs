//! Shikata-ga-nai polymorphic shellcode detector.
//!
//! MSF original:  x86/shikata_ga_nai encoder
//! KSpike mirror: detector.mem.shikata_polymorphic
//!
//! shikata_ga_nai's decoder stub is polymorphic in register choice and in key
//! bytes, but its prologue shape is canonical:
//!
//!   FPU instr (fldpi/fnstenv)   → leaks EIP to stack
//!   pop <reg>                   → captures EIP
//!   xor ECX, ECX                → loop counter
//!   mov CL, <len>               → length
//!   xor DWORD PTR [reg + off], K
//!   add reg, 4
//!   loop <short>
//!
//! Bytes typical of the stub:
//!   d9 eb 9b          (fldpi; fwait — variant 1)
//!   d9 74 24 f4       (fnstenv [esp-0xC] — variant 2)
//!   5b / 59 / 5e / 5f (pop ebx/ecx/esi/edi)
//!   31 c9 / 33 c9     (xor ecx, ecx)
//!   b1 ??             (mov cl, imm8)
//!   81 73 13 ?? ?? ?? ??  (xor dword ptr [ebx+0x13], imm32 — key)
//!   83 c3 04          (add ebx, 4)
//!   e2 f4             (loop short -12)

use kspike_core::prelude::*;
use kspike_kernel::inspect::hex_signature_match;

pub struct ShikataPolymorphicDetector { meta: ModuleMeta }

impl Default for ShikataPolymorphicDetector {
    fn default() -> Self {
        Self {
            meta: ModuleMeta {
                name: "detector.mem.shikata_polymorphic".into(),
                kind: ModuleKind::Detector,
                version: "0.1.0".into(),
                description: "Detects the canonical shikata_ga_nai decoder-stub shape.".into(),
                author: "gratech".into(),
                risk_level: 0,
                limits: KnownLimits::new()
                    .add(Limitation {
                        id: "variant-coverage".into(),
                        description: "v0.1 recognises the two most common prologues; newer iterations or manual hand-editing will slip by.".into(),
                        confidence_penalty: 0.15,
                        mitigation: Some("accept-as-signal, corroborate with RWX page creation".into()),
                    }),
                tags: vec!["shellcode".into(), "encoder".into(), "x86".into()],
            },
        }
    }
}

impl Module for ShikataPolymorphicDetector {
    fn meta(&self) -> &ModuleMeta { &self.meta }
    fn evaluate(&self, s: &Signal) -> Result<ModuleVerdict> {
        if !s.kind.starts_with("mem.rwx.scan") && !s.kind.starts_with("net.http") {
            return Ok(ModuleVerdict::Ignore);
        }
        let Some(hex) = s.data.get("bytes_hex").and_then(|v| v.as_str()) else {
            return Ok(ModuleVerdict::Ignore);
        };
        let raw = match decode_hex(hex) { Some(b) => b, None => return Ok(ModuleVerdict::Ignore) };

        // Prologue variant 1: fldpi;fwait + pop.
        let v1 = hex_signature_match(&raw,
            "d9 eb 9b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e2 ??").is_some();
        // Prologue variant 2: fnstenv + pop + loop tail.
        let v2 = hex_signature_match(&raw,
            "d9 74 24 f4 5b 81 73 13 ?? ?? ?? ?? 83 c3 04 e2 f4").is_some();

        if v1 || v2 {
            Ok(ModuleVerdict::Report {
                note: format!("shikata_ga_nai decoder stub detected (v1={v1} v2={v2})"),
                confidence: self.meta.limits.humble(if v2 { 0.93 } else { 0.85 }),
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
