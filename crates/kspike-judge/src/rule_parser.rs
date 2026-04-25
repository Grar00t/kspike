//! Layer 1: Rule Parser
//!
//! Loads and parses operator-editable rules from NRULE format.
//! Rules are ordered by specificity and evaluated top-to-bottom.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub pattern: RulePattern,
    pub decision: RuleDecision,
    pub priority: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RulePattern {
    /// Match module by name prefix
    Module(String),
    /// Match verdict kind
    VerdictKind(String),
    /// Match target pattern (CIDR or glob)
    Target(String),
    /// Composite: ALL must match
    And(Vec<RulePattern>),
    /// Composite: ANY must match
    Or(Vec<RulePattern>),
    /// Never matches (denial)
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDecision {
    Allow,
    Deny,
    Uncertain,
}

pub struct RuleParser {
    rules: Vec<Rule>,
}

impl RuleParser {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn from_nrule_text(content: &str) -> anyhow::Result<Self> {
        let mut rules = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(rule) = Self::parse_line(line) {
                rules.push(rule);
            }
        }
        rules.sort_by_key(|r| std::cmp::Reverse(r.priority));
        Ok(Self { rules })
    }

    fn parse_line(line: &str) -> anyhow::Result<Rule> {
        let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        if parts.len() < 4 {
            anyhow::bail!("rule must have: id|name|pattern|decision");
        }
        let decision = match parts[3] {
            "allow" => RuleDecision::Allow,
            "deny" => RuleDecision::Deny,
            "uncertain" => RuleDecision::Uncertain,
            d => anyhow::bail!("invalid decision: {}", d),
        };
        Ok(Rule {
            id: parts[0].to_string(),
            name: parts[1].to_string(),
            pattern: RulePattern::Module(parts[2].to_string()),
            decision,
            priority: 100,
        })
    }

    pub fn evaluate_rules(&self, context: &RuleContext) -> Option<RuleDecision> {
        for rule in &self.rules {
            if self.matches_pattern(&rule.pattern, context) {
                return Some(rule.decision);
            }
        }
        None
    }

    fn matches_pattern(&self, pattern: &RulePattern, ctx: &RuleContext) -> bool {
        match pattern {
            RulePattern::Module(m) => ctx.module_name.starts_with(m),
            RulePattern::VerdictKind(v) => &ctx.verdict_kind == v,
            RulePattern::Target(t) => ctx.target.as_ref().map(|tgt| tgt.contains(t)).unwrap_or(false),
            RulePattern::And(pats) => pats.iter().all(|p| self.matches_pattern(p, ctx)),
            RulePattern::Or(pats) => pats.iter().any(|p| self.matches_pattern(p, ctx)),
            RulePattern::Never => false,
        }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

#[derive(Debug, Clone)]
pub struct RuleContext {
    pub module_name: String,
    pub verdict_kind: String,
    pub target: Option<String>,
    pub risk_level: u8,
}

impl Default for RuleParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rules() {
        let nrule = r#"
# Comment line
R001 | Forbidden Module | defender.kernel_module | deny
R002 | Allowed Reporter | *reporter* | allow
        "#;
        let parser = RuleParser::from_nrule_text(nrule).unwrap();
        assert_eq!(parser.rules().len(), 2);
    }
}
