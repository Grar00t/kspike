//! Layer 2: Constraint Solver
//!
//! Encodes the request as a system of linear constraints and determines
//! feasibility. Constraints are drawn from the ROE conditions and thresholds.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintSystem {
    constraints: Vec<LinearConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearConstraint {
    pub name: String,
    pub expression: String, // e.g., "x_strike + risk/10 + prop/10 ≤ certainty + legitimacy"
    pub lower_bound: Option<f32>,
    pub upper_bound: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintContext {
    pub strike_count: f32,          // 0.0 or 1.0
    pub risk_level: f32,            // 0..10
    pub proportionality: f32,       // 0..10
    pub certainty: f32,             // 0..1
    pub legitimacy: f32,            // 0..1
    pub harm_total: f32,            // summed harm vector
    pub necessity_total: f32,       // summed necessity vector
}

pub struct ConstraintSolver;

impl ConstraintSolver {
    /// Check if all constraints are satisfiable given the context.
    pub fn is_feasible(ctx: &ConstraintContext) -> bool {
        // Constraint 1: Strike legitimacy check
        // x_strike + risk/10 + prop/10 ≤ certainty + legitimacy
        let c1 = ctx.strike_count + (ctx.risk_level / 10.0) + (ctx.proportionality / 10.0)
            <= ctx.certainty + ctx.legitimacy;

        // Constraint 2: Confidence must be sufficient for strikes
        // confidence ≥ 0.85 for strikes (implicit in StaticJudge)
        let c2 = ctx.certainty >= 0.85 || ctx.strike_count == 0.0;

        // Constraint 3: Harm-necessity balance
        // necessity ≥ harm (or approximately balanced)
        let c3 = ctx.necessity_total >= (ctx.harm_total * 0.8); // 80% threshold

        c1 && c2 && c3
    }

    /// Build a constraint system for a verdict request.
    pub fn build_system(ctx: &ConstraintContext) -> ConstraintSystem {
        let mut constraints = vec![
            LinearConstraint {
                name: "strike_legitimacy".to_string(),
                expression: format!(
                    "x_strike({}) + risk({}) + prop({}) ≤ certainty({}) + legitimacy({})",
                    ctx.strike_count, ctx.risk_level, ctx.proportionality,
                    ctx.certainty, ctx.legitimacy
                ),
                lower_bound: None,
                upper_bound: Some(1.0),
            },
            LinearConstraint {
                name: "confidence_threshold".to_string(),
                expression: format!("certainty({}) ≥ 0.85", ctx.certainty),
                lower_bound: Some(0.85),
                upper_bound: None,
            },
            LinearConstraint {
                name: "harm_necessity_balance".to_string(),
                expression: format!(
                    "necessity({}) ≥ 0.8 * harm({})",
                    ctx.necessity_total, ctx.harm_total
                ),
                lower_bound: Some(ctx.harm_total * 0.8),
                upper_bound: None,
            },
        ];

        // Add optional constraints based on strike context
        if ctx.strike_count > 0.0 {
            constraints.push(LinearConstraint {
                name: "strike_proportionality".to_string(),
                expression: format!("proportionality({}) ≤ 5", ctx.proportionality),
                lower_bound: None,
                upper_bound: Some(5.0),
            });
        }

        ConstraintSystem { constraints }
    }

    /// Verbose check with detailed constraint evaluation.
    pub fn evaluate_verbose(ctx: &ConstraintContext) -> ConstraintEvaluation {
        let c1 = ctx.strike_count + (ctx.risk_level / 10.0) + (ctx.proportionality / 10.0)
            <= ctx.certainty + ctx.legitimacy;
        let c2 = ctx.certainty >= 0.85 || ctx.strike_count == 0.0;
        let c3 = ctx.necessity_total >= (ctx.harm_total * 0.8);
        let c4 = ctx.proportionality <= 5.0 || ctx.strike_count == 0.0;

        ConstraintEvaluation {
            feasible: c1 && c2 && c3 && c4,
            constraints: vec![
                ("strike_legitimacy".to_string(), c1),
                ("confidence_threshold".to_string(), c2),
                ("harm_necessity_balance".to_string(), c3),
                ("proportionality_limit".to_string(), c4),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintEvaluation {
    pub feasible: bool,
    pub constraints: Vec<(String, bool)>,
}

impl ConstraintSystem {
    pub fn constraints(&self) -> &[LinearConstraint] {
        &self.constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_feasibility() {
        let ctx = ConstraintContext {
            strike_count: 0.0,
            risk_level: 3.0,
            proportionality: 0.0,
            certainty: 0.85,
            legitimacy: 0.85,
            harm_total: 0.35,
            necessity_total: 0.68,
        };
        assert!(ConstraintSolver::is_feasible(&ctx));
    }

    #[test]
    fn test_constraint_infeasibility() {
        let ctx = ConstraintContext {
            strike_count: 1.0,
            risk_level: 8.0,
            proportionality: 8.0,
            certainty: 0.65,
            legitimacy: 0.75,
            harm_total: 1.0,
            necessity_total: 0.5,
        };
        assert!(!ConstraintSolver::is_feasible(&ctx));
    }
}
