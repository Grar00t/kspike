//! `CasperJudge` — composes on top of another Judge. Casper can only tighten:
//! if Casper answers "DENY" it wins; if it answers "UNCERTAIN" the inner
//! Judge's ruling stands; if Casper says "ALLOW" that doesn't override a
//! prior denial.

use kspike_core::prelude::*;
use kspike_judge::{Judge, JudgeRuling, RulingContext};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct CasperReq {
    pub module: String,
    pub verdict_kind: String,     // "ignore" | "report" | "defend" | "strike"
    pub target: Option<String>,
    pub confidence: f32,
    pub proportionality: u8,
    pub risk_level: u8,
    pub attack_certainty: f32,
    pub target_legitimacy: f32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CasperResp {
    pub decision: String,         // "allow" | "deny" | "uncertain"
    pub rationale: String,
}

pub struct CasperJudge {
    inner: Arc<dyn Judge>,
    model_path: String,
    initialised: std::sync::Once,
}

impl CasperJudge {
    pub fn new(inner: Arc<dyn Judge>, model_path: impl Into<String>) -> Self {
        Self { inner, model_path: model_path.into(), initialised: std::sync::Once::new() }
    }

    fn ensure_init(&self) {
        self.initialised.call_once(|| {
            if crate::ffi::available() {
                if let Err(e) = crate::ffi::init(&self.model_path) {
                    tracing::warn!("casper init failed, falling back to uncertain: {e}");
                }
            }
        });
    }
}

impl Judge for CasperJudge {
    fn rule(&self, meta: &ModuleMeta, verdict: &ModuleVerdict, ctx: &RulingContext) -> JudgeRuling {
        let base = self.inner.rule(meta, verdict, ctx);
        if !base.allowed {
            // Already denied; let it stand, annotate.
            return JudgeRuling { reason: format!("{} | casper: not consulted", base.reason), ..base };
        }
        self.ensure_init();
        if !crate::ffi::available() {
            return JudgeRuling { reason: format!("{} | casper: stub (feature link_casper off)", base.reason), ..base };
        }
        let kind = match verdict {
            ModuleVerdict::Ignore => "ignore",
            ModuleVerdict::Report { .. } => "report",
            ModuleVerdict::Defend { .. } => "defend",
            ModuleVerdict::RequestStrike { .. } => "strike",
        };
        let target = match verdict {
            ModuleVerdict::Defend { target, .. } => Some(target.clone()),
            ModuleVerdict::RequestStrike { target, .. } => Some(target.clone()),
            _ => None,
        };
        let (confidence, proportionality) = match verdict {
            ModuleVerdict::Defend { confidence, .. } => (*confidence, 0),
            ModuleVerdict::RequestStrike { confidence, proportionality, .. } => (*confidence, *proportionality),
            ModuleVerdict::Report { confidence, .. } => (*confidence, 0),
            ModuleVerdict::Ignore => (0.0, 0),
        };
        let req = CasperReq {
            module: meta.name.clone(),
            verdict_kind: kind.into(),
            target,
            confidence,
            proportionality,
            risk_level: meta.risk_level,
            attack_certainty: ctx.attack_certainty,
            target_legitimacy: ctx.target_legitimacy,
        };
        let Ok(req_json) = serde_json::to_string(&req) else {
            return base;
        };
        match crate::ffi::evaluate(&req_json) {
            Ok(out) => match serde_json::from_str::<CasperResp>(&out) {
                Ok(r) => match r.decision.as_str() {
                    "deny" => JudgeRuling {
                        allowed: false,
                        reason: format!("{} | casper DENY: {}", base.reason, r.rationale),
                        conditions_met: base.conditions_met,
                        required_dual_auth: base.required_dual_auth,
                        ts: chrono::Utc::now(),
                    },
                    "allow" | "uncertain" | _ => JudgeRuling {
                        reason: format!("{} | casper: {} ({})", base.reason, r.decision, r.rationale),
                        ..base
                    },
                },
                Err(e) => JudgeRuling { reason: format!("{} | casper: parse err {e}", base.reason), ..base },
            },
            Err(e) => JudgeRuling { reason: format!("{} | casper: call err {e}", base.reason), ..base },
        }
    }
}
