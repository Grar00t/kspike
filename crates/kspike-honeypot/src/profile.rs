//! Profile schema.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily { Windows, Linux, Mac, Bsd, Embedded }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Maximum seconds to keep an attacker engaged.
    pub max_engagement_seconds: u64,
    /// Maximum bytes of simulated data to deliver before tearing down.
    pub max_bytes: u64,
    /// On teardown, return this string (usually a generic connection-reset).
    pub teardown_hint: String,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self { max_engagement_seconds: 600, max_bytes: 1_048_576,
               teardown_hint: "connection reset".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotProfile {
    pub name: String,
    pub os: OsFamily,
    pub hostname: String,
    pub banner: String,
    pub open_ports: Vec<u16>,
    pub fake_fs_sample: Vec<String>,      // visible paths (never real paths)
    pub fake_users: Vec<String>,          // fake account names
    pub retention: RetentionPolicy,
    /// Safety: paths we MUST NEVER pretend to serve, even as bait,
    /// because mis-classification could hurt a real organisation.
    pub forbidden_leaks: Vec<String>,
}
