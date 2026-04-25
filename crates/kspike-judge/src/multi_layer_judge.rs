//! Multi-Layer Judge Orchestrator
//!
//! Combines all 5 layers into a coherent decision pipeline:
//!   1. rule_parser: operator-editable rules
//!   2. constraint_solver: linear constraint feasibility
//!   3. hybrid_reasoner: knowledge base queries
//!   4. khz_judge: KHZ-Q balance (Φ threshold)
//!   5. proof_generator: cryptographic audit trail

use crate::rule_parser::{RuleParser, RuleContext, RuleDecision};
use crate::constraint_solver::{ConstraintSolver, ConstraintContext};
use crate::hybrid_reasoner::{HybridReasoner, KnowledgeBase};
use crate::proof_generator::{ProofGenerator, AuditTrail};
use crate::judge::{Judge, JudgeRuling, RulingContext, KhzJudge};
use kspike_core::prelude::{ModuleMeta, ModuleVerdict};
use serde::{Deserialize, Serialize};
use chrono::Utc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiLayerEvaluation {
    /// Layer 1 result
    pub layer1_rule_decision: Option<RuleDecision>,
    /// Layer 2 result
    pub layer2_constraint_feasible: bool,
    /// Layer 3 result
    pub layer3_justified: bool,
    /// Layer 4 result (KHZ)
    pub layer4_phi_approved: bool,
    /// Layer 5 result (proof hash)
    pub layer5_proof_hash: Option<String>,
    /// Final combined decision
    pub final_allowed: bool,
    pub final_reason: String,
}

pub struct MultiLayerJudge {
    // Layer 1
    rule_parser: RuleParser,
    // Layer 2 (stateless, uses ConstraintSolver directly)
    // Layer 3
    hybrid_reasoner: HybridReasoner,
    // Layer 4
    khz_judge: KhzJudge,
    // Layer 5
    proof_generator: ProofGenerator,
    audit_trail: AuditTrail,
}

impl MultiLayerJudge {
    pub fn new(
        rule_parser: RuleParser,
        knowledge_base: KnowledgeBase,
        khz_judge: KhzJudge,
    ) -> Self {
        let hybrid_reasoner = HybridReasoner::new(knowledge_base);
        Self {
            rule_parser,
            hybrid_reasoner,
            khz_judge,
            proof_generator: ProofGenerator::new(),
            audit_trail: AuditTrail::new(),
        }
    }

    /// Evaluate through all 5 layers.
    pub fn evaluate_multi_layer(
        &mut self,
        meta: &ModuleMeta,
        verdict: &ModuleVerdict,
        ctx: &RulingContext,
        request_json: &str,
    ) -> (JudgeRuling, MultiLayerEvaluation) {
        let mut eval = MultiLayerEvaluation {
            layer1_rule_decision: None,
            layer2_constraint_feasible: false,
            layer3_justified: false,
            layer4_phi_approved: false,
            layer5_proof_hash: None,
            final_allowed: false,
            final_reason: String::new(),
        };

        // Layer 1: Rule Parser
        let rule_ctx = RuleContext {
            module_name: meta.name.clone(),
            verdict_kind: self.verdict_label(verdict).to_string(),
            target: self.extract_target(verdict),
            risk_level: meta.risk_level,
        };

        if let Some(rule_decision) = self.rule_parser.evaluate_rules(&rule_ctx) {
            eval.layer1_rule_decision = Some(rule_decision);
            match rule_decision {
                RuleDecision::Deny => {
                    let reason = format!(
                        "Layer 1 (Rule Parser): hard rule denies '{}'",
                        meta.name
                    );
                    return self.finalize_denial(
                        reason,
                        eval,
                        request_json,
                        meta,
                    );
                }
                RuleDecision::Allow => {
                    // Continue to next layer
                }
                RuleDecision::Uncertain => {
                    // Continue to next layer
                }
            }
        }

        // Layer 2: Constraint Solver
        let constraint_ctx = ConstraintContext {
            strike_count: if self.is_strike(verdict) { 1.0 } else { 0.0 },
            risk_level: meta.risk_level as f32,
            proportionality: self.extract_proportionality(verdict),
            certainty: ctx.attack_certainty,
            legitimacy: ctx.target_legitimacy,
            harm_total: 0.35, // Will be computed from vectors in real impl
            necessity_total: 0.68,
        };

        eval.layer2_constraint_feasible = ConstraintSolver::is_feasible(&constraint_ctx);
        if !eval.layer2_constraint_feasible {
            let reason = "Layer 2 (Constraint Solver): constraints not satisfiable".to_string();
            return self.finalize_denial(reason, eval, request_json, meta);
        }

        // Layer 3: Hybrid Reasoner (Query knowledge base)
        let goal = format!("justified_strike({}, {})", meta.name, self.verdict_label(verdict));
        let query_result = self.hybrid_reasoner.query(&goal);
        eval.layer3_justified = query_result.proved && query_result.confidence >= 0.5;

        if !eval.layer3_justified && self.is_strike(verdict) {
            let reason = format!(
                "Layer 3 (Hybrid Reasoner): cannot prove justified strike (conf={})",
                query_result.confidence
            );
            return self.finalize_denial(reason, eval, request_json, meta);
        }

        // Layer 4: KHZ Judge
        let khz_ruling = self.khz_judge.rule(meta, verdict, ctx);
        eval.layer4_phi_approved = khz_ruling.allowed;

        if !khz_ruling.allowed {
            eval.final_allowed = false;
            eval.final_reason = format!("Layer 4 (KHZ Judge): {}", khz_ruling.reason);
            let proof = self.proof_generator.generate_proof(
                format!("dec-{}", uuid()),
                meta.name.clone(),
                "deny".to_string(),
                eval.final_reason.clone(),
                request_json,
            );
            eval.layer5_proof_hash = Some(proof.proof_hash.clone());
            self.audit_trail.add_record(proof);
            return (
                JudgeRuling {
                    allowed: false,
                    reason: eval.final_reason.clone(),
                    conditions_met: khz_ruling.conditions_met,
                    required_dual_auth: khz_ruling.required_dual_auth,
                    ts: Utc::now(),
                },
                eval,
            );
        }

        // Layer 5: Proof Generator
        let proof = self.proof_generator.generate_proof(
            format!("dec-{}", uuid()),
            meta.name.clone(),
            "allow".to_string(),
            khz_ruling.reason.clone(),
            request_json,
        );
        eval.layer5_proof_hash = Some(proof.proof_hash.clone());
        self.audit_trail.add_record(proof);

        eval.final_allowed = true;
        eval.final_reason = format!("All 5 layers approved: {}", khz_ruling.reason);

        (
            JudgeRuling {
                allowed: true,
                reason: eval.final_reason.clone(),
                conditions_met: khz_ruling.conditions_met,
                required_dual_auth: khz_ruling.required_dual_auth,
                ts: Utc::now(),
            },
            eval,
        )
    }

    fn finalize_denial(
        &mut self,
        reason: String,
        mut eval: MultiLayerEvaluation,
        request_json: &str,
        meta: &ModuleMeta,
    ) -> (JudgeRuling, MultiLayerEvaluation) {
        eval.final_allowed = false;
        eval.final_reason = reason.clone();

        let proof = self.proof_generator.generate_proof(
            format!("dec-{}", uuid()),
            meta.name.clone(),
            "deny".to_string(),
            reason.clone(),
            request_json,
        );
        eval.layer5_proof_hash = Some(proof.proof_hash.clone());
        self.audit_trail.add_record(proof);

        (
            JudgeRuling {
                allowed: false,
                reason,
                conditions_met: [false; 4],
                required_dual_auth: false,
                ts: Utc::now(),
            },
            eval,
        )
    }

    pub fn audit_trail(&self) -> &AuditTrail {
        &self.audit_trail
    }

    fn is_strike(&self, verdict: &ModuleVerdict) -> bool {
        matches!(verdict, ModuleVerdict::RequestStrike { .. })
    }

    fn verdict_label(&self, v: &ModuleVerdict) -> &'static str {
        match v {
            ModuleVerdict::Ignore => "ignore",
            ModuleVerdict::Report { .. } => "report",
            ModuleVerdict::Defend { .. } => "defend",
            ModuleVerdict::RequestStrike { .. } => "strike",
        }
    }

    fn extract_target(&self, verdict: &ModuleVerdict) -> Option<String> {
        match verdict {
            ModuleVerdict::Defend { target, .. } => Some(target.clone()),
            ModuleVerdict::RequestStrike { target, .. } => Some(target.clone()),
            _ => None,
        }
    }

    fn extract_proportionality(&self, verdict: &ModuleVerdict) -> f32 {
        match verdict {
            ModuleVerdict::RequestStrike { proportionality, .. } => *proportionality as f32,
            _ => 0.0,
        }
    }
}

fn uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_parser::RuleParser;
    use crate::hybrid_reasoner::KnowledgeBase;
    use crate::judge::StaticJudge;
    use crate::roe::Roe;

    #[test]
    fn test_multi_layer_flow() {
        let rule_parser = RuleParser::new();
        let kb = KnowledgeBase::new();
        let static_judge = StaticJudge::new(Roe::default_roe());
        let khz_judge = KhzJudge::new(static_judge, 0.50);
        let mlj = MultiLayerJudge::new(rule_parser, kb, khz_judge);

        // Just verify construction works
        assert!(mlj.audit_trail().records().is_empty());
    }
}
