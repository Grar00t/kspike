//! WSL2 bridge: turns a Windows-side ETW/WFP event (received over a named
//! pipe / socket / UNIX socket on WSL2) into a kspike_core::Signal.

use kspike_core::{Signal, SignalSource, ThreatLevel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WslBridgePayload {
    pub provider: String,
    pub kind: String,        // e.g. "windows.etw.process.create"
    pub actor: Option<String>,
    pub target: Option<String>,
    pub threat: Option<String>,
    pub confidence: Option<f32>,
    #[serde(default)]
    pub data: serde_json::Map<String, serde_json::Value>,
}

pub fn wsl_bridge_signal(p: WslBridgePayload) -> Signal {
    let threat = match p.threat.as_deref() {
        Some("benign") => ThreatLevel::Benign,
        Some("suspicious") => ThreatLevel::Suspicious,
        Some("hostile") => ThreatLevel::Hostile,
        Some("catastrophic") => ThreatLevel::Catastrophic,
        _ => ThreatLevel::Unknown,
    };
    let mut s = Signal::new(SignalSource::Kernel, p.kind)
        .threat(threat)
        .confidence(p.confidence.unwrap_or(0.5));
    if let Some(a) = p.actor  { s = s.actor(a); }
    if let Some(t) = p.target { s = s.target(t); }
    s = s.with("provider", serde_json::json!(p.provider));
    for (k, v) in p.data { s = s.with(k, v); }
    s
}
