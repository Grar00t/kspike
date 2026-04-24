//! Signals: raw observations fed into the KSpike pipeline.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Observed, not yet judged.
    Unknown,
    /// Behavior is inside tolerance.
    Benign,
    /// Anomalous but not confirmed hostile.
    Suspicious,
    /// Confirmed hostile with evidence.
    Hostile,
    /// Active exfiltration / destruction in progress.
    Catastrophic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalSource {
    Syscall,
    Network,
    Filesystem,
    Process,
    Memory,
    Kernel,
    AuthLog,
    User,
    Peer, // from another KSpike node (community IOC)
    Ai,   // from Casper reasoning
}

/// A single observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub id: uuid::Uuid,
    pub ts: DateTime<Utc>,
    pub source: SignalSource,
    pub kind: String,   // free-form taxonomy, e.g. "ssh.bruteforce.attempt"
    pub actor: Option<String>, // e.g. source IP, pid, user
    pub target: Option<String>,
    pub threat: ThreatLevel,
    pub raw_confidence: f32, // 0..1, pre-humility
    pub data: BTreeMap<String, serde_json::Value>,
}

impl Signal {
    pub fn new(source: SignalSource, kind: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            ts: Utc::now(),
            source,
            kind: kind.into(),
            actor: None,
            target: None,
            threat: ThreatLevel::Unknown,
            raw_confidence: 0.5,
            data: BTreeMap::new(),
        }
    }

    pub fn actor(mut self, a: impl Into<String>) -> Self {
        self.actor = Some(a.into());
        self
    }

    pub fn target(mut self, t: impl Into<String>) -> Self {
        self.target = Some(t.into());
        self
    }

    pub fn threat(mut self, t: ThreatLevel) -> Self {
        self.threat = t;
        self
    }

    pub fn confidence(mut self, c: f32) -> Self {
        self.raw_confidence = c.clamp(0.0, 1.0);
        self
    }

    pub fn with(mut self, k: impl Into<String>, v: serde_json::Value) -> Self {
        self.data.insert(k.into(), v);
        self
    }
}
