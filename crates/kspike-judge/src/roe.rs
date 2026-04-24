//! Rules of Engagement — data-driven configuration.
//!
//! Loaded from `roe.toml`. Operator-editable. Every change is itself an
//! evidence-sealed event (handled by the engine, not this module).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoeConfig {
    pub version: String,
    pub operator: String,
    pub posture: Posture,
    pub strike: StrikeConditions,
    pub forbidden_targets: Vec<String>,
    pub allowed_hours_utc: Option<(u8, u8)>,
    pub require_dual_authorization_above: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Posture {
    /// Observe only. Even defenders just report.
    PassiveObserver,
    /// Defenders fire freely; strikers fully disabled.
    DefensiveOnly,
    /// Strikers permitted with full four-condition check (default).
    DefensiveWithActiveResponse,
    /// Strikers permitted with relaxed exhaustion check for high-velocity attacks.
    Preemptive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrikeConditions {
    /// Minimum confidence that an attack is occurring. Default 0.85.
    pub min_attack_certainty: f32,
    /// Minimum number of failed defender attempts before escalation.
    /// 0 means "no exhaustion required" (only valid under Preemptive).
    pub min_defender_attempts: u8,
    /// Attacker identity must be pinned to at least this confidence.
    pub min_target_legitimacy: f32,
    /// Maximum proportionality units allowed (1..10).
    pub max_proportionality: u8,
    /// Require the target to also appear on a community/KPeer IOC feed.
    pub require_external_corroboration: bool,
}

impl Default for RoeConfig {
    fn default() -> Self {
        Self {
            version: "0.1".into(),
            operator: "unknown".into(),
            posture: Posture::DefensiveWithActiveResponse,
            strike: StrikeConditions {
                min_attack_certainty: 0.85,
                min_defender_attempts: 1,
                min_target_legitimacy: 0.90,
                max_proportionality: 5,
                require_external_corroboration: false,
            },
            forbidden_targets: vec![
                // Infrastructure we never strike, even if provoked.
                "127.0.0.0/8".into(),
                "169.254.0.0/16".into(),
                "224.0.0.0/4".into(),
                "*.gov.sa".into(),
                "*.gov".into(),
                "*.mil".into(),
                "*.edu".into(),
                "*.hospital".into(),
                "*.icrc.org".into(),
            ],
            allowed_hours_utc: None,
            require_dual_authorization_above: 7,
        }
    }
}

pub struct Roe(pub RoeConfig);

impl Roe {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let txt = std::fs::read_to_string(path)?;
        let cfg: RoeConfig = toml::from_str(&txt)?;
        Ok(Self(cfg))
    }

    pub fn default_roe() -> Self {
        Self(RoeConfig::default())
    }

    pub fn is_forbidden(&self, target: &str) -> bool {
        self.0.forbidden_targets.iter().any(|pat| match_glob(pat, target))
    }
}

fn match_glob(pattern: &str, s: &str) -> bool {
    // tiny glob: supports '*' prefix only.
    if let Some(rest) = pattern.strip_prefix('*') {
        s.ends_with(rest)
    } else {
        pattern == s
    }
}
