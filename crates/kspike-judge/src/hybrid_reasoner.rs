//! Layer 3: Hybrid Reasoner
//!
//! Uses symbolic queries against a knowledge base to determine if a verdict
//! is justified. Implements simple Prolog-like query resolution with depth limits.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeBase {
    facts: Vec<Fact>,
    rules: Vec<InferenceRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    pub predicate: String, // e.g., "attack_ongoing(target)"
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRule {
    pub head: String,                    // conclusion predicate
    pub body: Vec<String>,               // premises (predicates to check)
    pub confidence_multiplier: f32,      // how much confidence to multiply
}

pub struct HybridReasoner {
    kb: KnowledgeBase,
    max_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub goal: String,
    pub proved: bool,
    pub confidence: f32,
    pub proof_depth: usize,
    pub derivation: Vec<String>,
}

impl KnowledgeBase {
    pub fn new() -> Self {
        Self {
            facts: Vec::new(),
            rules: Vec::new(),
        }
    }

    pub fn add_fact(&mut self, predicate: impl Into<String>, confidence: f32) {
        self.facts.push(Fact {
            predicate: predicate.into(),
            confidence: confidence.clamp(0.0, 1.0),
        });
    }

    pub fn add_rule(&mut self, head: impl Into<String>, body: Vec<String>, multiplier: f32) {
        self.rules.push(InferenceRule {
            head: head.into(),
            body,
            confidence_multiplier: multiplier.clamp(0.0, 1.0),
        });
    }

    pub fn facts(&self) -> &[Fact] {
        &self.facts
    }

    pub fn rules(&self) -> &[InferenceRule] {
        &self.rules
    }
}

impl Default for KnowledgeBase {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridReasoner {
    pub fn new(kb: KnowledgeBase) -> Self {
        Self { kb, max_depth: 64 }
    }

    /// Query the knowledge base: can we prove the goal?
    pub fn query(&self, goal: &str) -> QueryResult {
        let mut derivation = Vec::new();
        let (proved, confidence, depth) = self.query_recursive(goal, &mut derivation, 0);
        QueryResult {
            goal: goal.to_string(),
            proved,
            confidence,
            proof_depth: depth,
            derivation,
        }
    }

    fn query_recursive(
        &self,
        goal: &str,
        derivation: &mut Vec<String>,
        depth: usize,
    ) -> (bool, f32, usize) {
        if depth > self.max_depth {
            return (false, 0.0, depth);
        }

        derivation.push(format!("[depth={}] query: {}", depth, goal));

        // Direct fact match
        for fact in &self.kb.facts {
            if self.unify(goal, &fact.predicate) {
                derivation.push(format!("  ✓ fact matched: {} (conf={})", fact.predicate, fact.confidence));
                return (true, fact.confidence, depth + 1);
            }
        }

        // Try inference rules
        for rule in &self.kb.rules {
            if self.unify(goal, &rule.head) {
                // Try to prove all body predicates
                let mut combined_conf = 1.0;
                let mut all_proved = true;

                for premise in &rule.body {
                    let (proved, conf, _) = self.query_recursive(premise, derivation, depth + 1);
                    if !proved {
                        all_proved = false;
                        break;
                    }
                    combined_conf *= conf;
                }

                if all_proved {
                    let final_conf = combined_conf * rule.confidence_multiplier;
                    derivation.push(format!(
                        "  ✓ rule {} proved with confidence {}",
                        rule.head, final_conf
                    ));
                    return (true, final_conf, depth + 1);
                }
            }
        }

        derivation.push(format!("  ✗ goal failed: {}", goal));
        (false, 0.0, depth + 1)
    }

    /// Simple unification: exact match or variable binding.
    fn unify(&self, goal: &str, fact: &str) -> bool {
        // Naive: just check if the predicate name matches (no complex unification)
        let goal_pred = goal.split('(').next().unwrap_or("");
        let fact_pred = fact.split('(').next().unwrap_or("");
        goal_pred == fact_pred
    }

    /// Load a simple KB from text format: "predicate(arg) : confidence"
    pub fn from_text(content: &str) -> anyhow::Result<Self> {
        let mut kb = KnowledgeBase::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 {
                let predicate = parts[0].trim();
                if let Ok(conf) = parts[1].trim().parse::<f32>() {
                    kb.add_fact(predicate, conf);
                }
            }
        }
        Ok(Self::new(kb))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_query() {
        let mut kb = KnowledgeBase::new();
        kb.add_fact("attack_ongoing(attacker)", 0.9);
        let reasoner = HybridReasoner::new(kb);
        let result = reasoner.query("attack_ongoing(attacker)");
        assert!(result.proved);
        assert!(result.confidence >= 0.8);
    }

    #[test]
    fn test_rule_inference() {
        let mut kb = KnowledgeBase::new();
        kb.add_fact("network_probe(attacker)", 0.85);
        kb.add_rule(
            "attack_ongoing(attacker)",
            vec!["network_probe(attacker)".to_string()],
            0.95,
        );
        let reasoner = HybridReasoner::new(kb);
        let result = reasoner.query("attack_ongoing(attacker)");
        assert!(result.proved);
    }
}
