//! Daemon wire protocol.

use kspike_core::Signal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    Ingest { signal: Signal },
    ListModules,
    /// Plant a canary token (placement, needle_hex).
    PlantCanary { placement: String, needle_hex: String },
    /// Read last N ledger records.
    LedgerTail { n: usize },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<kspike_modules::EngineStats>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ledger: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_id: Option<String>,
}

impl Response {
    pub fn ok_empty() -> Self {
        Self { ok: true, error: None, stats: None, outcomes: vec![],
               modules: vec![], ledger: vec![], canary_id: None }
    }
    pub fn err(e: impl Into<String>) -> Self {
        let mut r = Self::ok_empty();
        r.ok = false; r.error = Some(e.into());
        r
    }
}

// Manual impl of Serialize for EngineStats (it has no derive) — we cheat via JSON.
mod stats_serde {
    // not needed: `kspike_modules::EngineStats` is `Debug + Clone + Default`.
    // We serialize it via a small shim in the server before sending.
}
