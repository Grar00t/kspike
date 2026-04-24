//! The Module trait — every capability in KSpike implements this.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::humility::KnownLimits;
use crate::signal::Signal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleKind {
    /// Passive observation.
    Detector,
    /// Takes defensive action (block, quarantine, harden).
    Defender,
    /// Takes offensive action (counter-strike, disable attacker infra).
    /// Must pass through the Judge before firing.
    Striker,
    /// Deception — honeypots, canaries.
    Deception,
    /// Forensics — evidence capture, post-incident.
    Forensic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMeta {
    pub name: String,           // e.g. "defender.ssh_bruteforce"
    pub kind: ModuleKind,
    pub version: String,
    pub description: String,
    pub author: String,
    /// Higher-risk modules require higher judge clearance.
    /// 0 = benign (auto-run). 10 = requires explicit operator + quorum.
    pub risk_level: u8,
    pub limits: KnownLimits,
    /// Tags used by the judge and the CLI filters.
    pub tags: Vec<String>,
}

/// The verdict a module returns after evaluating a signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleVerdict {
    /// Nothing to do.
    Ignore,
    /// Report but do not act.
    Report { note: String, confidence: f32 },
    /// Apply a named defense.
    Defend { action: String, target: String, confidence: f32 },
    /// Request an offensive action (judge-gated).
    RequestStrike {
        action: String,
        target: String,
        justification: String,
        confidence: f32,
        proportionality: u8, // 1..10, intended force
    },
}

/// Every module implements this.
pub trait Module: Send + Sync {
    fn meta(&self) -> &ModuleMeta;

    /// Evaluate a signal and return a verdict.
    /// Must be pure-ish: no unilateral action. All action is gated by the engine.
    fn evaluate(&self, signal: &Signal) -> Result<ModuleVerdict>;

    /// Hook called when the engine allows this module to apply its verdict.
    /// `authorization` is non-empty for strikes.
    fn apply(&self, verdict: &ModuleVerdict, authorization: Option<&str>) -> Result<serde_json::Value>;

    /// Self-test — modules can declare their health. The engine runs this
    /// at startup and periodically.
    fn self_test(&self) -> Result<()> {
        Ok(())
    }
}
