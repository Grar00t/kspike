//! ETW provider scaffold.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwLevel { Critical, Error, Warning, Info, Verbose }

pub struct EtwProvider {
    pub guid: &'static str,         // e.g. "{KSPIKE-ETW-PROVIDER-1}"
    pub name: &'static str,         // e.g. "Gratech-KSpike"
}

impl Default for EtwProvider {
    fn default() -> Self {
        Self {
            guid: "{2025-04-25-KSPIKE-ETW-A}",
            name: "Gratech-KSpike",
        }
    }
}

impl EtwProvider {
    /// Format a kspike-shaped event for ETW emission. The actual `EventWrite`
    /// call is feature-gated.
    pub fn format(&self, level: EtwLevel, kind: &str, payload: &serde_json::Value) -> String {
        format!(r#"{{"provider":"{}","level":"{:?}","kind":"{}","payload":{}}}"#,
                self.name, level, kind, payload)
    }
}
