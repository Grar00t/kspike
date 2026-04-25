//! Phalanx Protocol — the inter-service bus on HAVEN OS.
//!
//! Plain JSON-Lines over UNIX sockets. Each peer mounts the bus and reads
//! every publish; subscribers filter on `topic`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhalanxMessage {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub publisher: String,            // "kspike", "phalanx-fw", "haven-dns", ...
    pub topic: String,                // "ioc.add", "strike.authorised", "evidence.sealed"
    pub payload: serde_json::Value,   // arbitrary JSON
    pub signer_fpr: String,
    pub signature: String,            // hex Ed25519 over canonical JSON of (ts|publisher|topic|payload)
}

pub struct PhalanxBus {
    pub socket_paths: Vec<String>,
}

impl PhalanxBus {
    pub fn new(paths: impl IntoIterator<Item = String>) -> Self {
        Self { socket_paths: paths.into_iter().collect() }
    }

    /// Format a message for the wire (one JSON line). Real send/receive
    /// happens in the daemon's tokio loop.
    pub fn format(msg: &PhalanxMessage) -> String {
        let mut s = serde_json::to_string(msg).unwrap_or_else(|_| "{}".into());
        s.push('\n');
        s
    }

    /// Topics KSpike publishes to (informational; subscribers filter).
    pub fn topics_published() -> &'static [&'static str] {
        &["ioc.add", "strike.authorised", "evidence.sealed", "roe.amendment"]
    }

    /// Topics KSpike subscribes to.
    pub fn topics_subscribed() -> &'static [&'static str] {
        &["ioc.add", "peer.attestation", "haven.posture.change"]
    }
}
