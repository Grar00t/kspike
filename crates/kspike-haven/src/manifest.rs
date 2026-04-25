//! Boot manifest — operator declares once, HAVEN enforces forever.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootManifest {
    pub version: String,
    pub operator: String,
    pub service_mode: ServiceMode,
    pub network_posture: NetworkPosture,
    pub interfaces: Vec<String>,
    pub roe_path: String,
    pub ledger_path: String,
    pub niyah_locale: String,
    /// Phalanx peers we publish to and subscribe from.
    pub phalanx_peers: Vec<String>,
}

impl Default for BootManifest {
    fn default() -> Self {
        Self {
            version: "1.0".into(),
            operator: "operator@haven.local".into(),
            service_mode: ServiceMode::Defensive,
            network_posture: NetworkPosture::DefenseInDepth,
            interfaces: vec!["eth0".into()],
            roe_path: "/etc/kspike/roe.toml".into(),
            ledger_path: "/var/lib/kspike/ledger.jsonl".into(),
            niyah_locale: "ar".into(),
            phalanx_peers: vec!["unix:///run/phalanx.bus".into()],
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceMode {
    /// Engine runs, modules evaluate, but apply() is a no-op (audit-only).
    Audit,
    /// Defenders fire freely; strikers fully disabled.
    Defensive,
    /// Strikers permitted with full ROE/Judge/KHZ chain.
    DefensiveWithStrike,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPosture {
    /// Nothing in or out except declared exemptions.
    DenyByDefault,
    /// Full XDP + procfs + auth-log + LSM stack engaged.
    DefenseInDepth,
    /// Like defense_in_depth, but auto-wires Phalanx peers to share IOCs.
    Federation,
}
