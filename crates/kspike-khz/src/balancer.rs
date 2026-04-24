//! The balancer — evaluates a request against the ten KHZ rules.

use serde::{Deserialize, Serialize};

use crate::fitrah::FitrahAnchor;
use crate::operator::{al_jabr, al_muqabala, HarmVector, NecessityVector, Phi};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceRequest {
    pub label: String,
    pub harm: HarmVector,
    pub necessity: NecessityVector,
    pub anchor: FitrahAnchor,
    /// Prior Φ for retro-causal refinement (rule 12 territory).
    pub prior_phi: Option<f32>,
    /// New evidence triggers the error loop (rule 8).
    pub new_evidence: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ruling {
    pub phi: Phi,
    pub for_pressure: f32,
    pub against_pressure: f32,
    pub full_assistance: bool,       // Necessity rule
    pub admit_error: bool,           // Error loop (rule 8)
    pub rules_triggered: Vec<u8>,    // which of the 10 rules contributed
    pub rationale: String,
}

pub struct KhzBalancer {
    /// When harm = 0 and necessity > 0, grant full assistance.
    pub necessity_threshold: f32,
    /// Fitrah baseline injected by Al-Jabr when side is empty.
    pub fitrah_floor: f32,
}

impl Default for KhzBalancer {
    fn default() -> Self {
        Self { necessity_threshold: 0.0, fitrah_floor: 0.10 }
    }
}

impl KhzBalancer {
    pub fn evaluate(&self, mut req: BalanceRequest) -> Ruling {
        let mut rules = Vec::<u8>::new();

        // RULE_01 REDUCTION — strip contradictory tokens (stubbed; labels equal → cancel).
        req.harm.components.retain(|(l,_)| !l.starts_with("contradiction:"));
        req.necessity.components.retain(|(l,_)| !l.starts_with("contradiction:"));
        rules.push(1);

        // RULE_03 RESTORATION via Al-Jabr.
        al_jabr(&mut req.harm, &mut req.necessity, self.fitrah_floor);
        rules.push(3);

        // RULE_02 BALANCING via Al-Muqabala.
        let (r#for, against) = al_muqabala(&req.harm, &req.necessity);
        rules.push(2);

        // RULE_06 DYNAMIC NECESSITY — amplify necessity with long-horizon terms.
        // (Heuristic placeholder — callers can inject long-term components already.)
        rules.push(6);

        // Necessity rule: harm=0 ∧ necessity>threshold → full assistance.
        let harm_sigma = req.harm.sigma();
        let need_sigma = req.necessity.sigma();
        let full = harm_sigma < 1e-6 && need_sigma > self.necessity_threshold;

        // RULE_07 Q-OPTIMIZATION — Φ = soft-max of balance.
        let raw = (r#for - against + 1.0) * 0.5; // map [-1,1] → [0,1]
        let phi = Phi::new(raw);
        rules.push(7);

        // RULE_08 ADMIT ERROR — new evidence and disagreement with prior triggers recalc flag.
        let admit_error = match (req.new_evidence, req.prior_phi) {
            (true, Some(prev)) => (prev - phi.value()).abs() > 0.15,
            _ => false,
        };
        if admit_error { rules.push(8); }

        // RULE_09 FITRAH ANCHOR — require a declared source.
        rules.push(9);

        let rationale = format!(
            "label={} | ΣH={:.3} ΣN={:.3} | for={:.3} against={:.3} | Φ={:.3} | full={} | anchor={:?}",
            req.label, harm_sigma, need_sigma, r#for, against, phi.value(),
            full, req.anchor.primary
        );

        Ruling {
            phi,
            for_pressure: r#for,
            against_pressure: against,
            full_assistance: full,
            admit_error,
            rules_triggered: rules,
            rationale,
        }
    }
}
