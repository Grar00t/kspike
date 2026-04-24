//! Epistemic humility layer.
//!
//! From the Casper Charter:
//!   "وفوق كل ذي علم عليم" — above every knower, there is one who knows more.
//!
//! Every KSpike module MUST declare what it does NOT know, where it can fail,
//! and under what conditions its verdict should be distrusted. A module that
//! claims certainty is, by charter, untrustworthy.

use serde::{Deserialize, Serialize};

/// A single declared limitation of a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limitation {
    /// Short identifier e.g. "false-positive-on-ipv6".
    pub id: String,
    /// Human-readable description (Arabic or English).
    pub description: String,
    /// Severity: how much this limitation should lower confidence.
    /// Range 0.0 (negligible) → 1.0 (this module may be wrong entirely).
    pub confidence_penalty: f32,
    /// Optional known workaround or compensating control.
    pub mitigation: Option<String>,
}

/// The full set of a module's self-declared limitations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnownLimits {
    pub items: Vec<Limitation>,
}

impl KnownLimits {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn add(mut self, l: Limitation) -> Self {
        self.items.push(l);
        self
    }

    /// Aggregate penalty in [0.0, 1.0]; clamped.
    pub fn total_penalty(&self) -> f32 {
        let raw: f32 = self.items.iter().map(|l| l.confidence_penalty).sum();
        raw.clamp(0.0, 1.0)
    }

    /// Adjust a module's raw confidence by its known limitations.
    /// Returns the humble confidence.
    pub fn humble(&self, raw_confidence: f32) -> f32 {
        (raw_confidence * (1.0 - self.total_penalty())).clamp(0.0, 1.0)
    }
}
