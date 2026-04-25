//! Signed key log — append-only record of which `signer_fpr` belongs to
//! which peer, with operator-supplied attestations.
//!
//! Format (JSON-Lines, identical style to evidence ledger):
//!
//!   { "ts": "...", "signer_fpr": "17667...", "pubkey_hex": "...",
//!     "attestation": "<arbitrary text>", "attested_by": "<fpr-of-attester>" }
//!
//! A peer is **trusted** only if its key appears in the local key log AND
//! the attester is in the operator's hand-rolled trust root (typically
//! their own fingerprint, or a small set).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLogEntry {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub signer_fpr: String,
    pub pubkey_hex: String,
    pub attestation: String,
    pub attested_by: String,
}

#[derive(Debug, Default)]
pub struct KeyLog {
    by_fpr: HashMap<String, KeyLogEntry>,
}

impl KeyLog {
    pub fn load(path: &Path) -> Result<Self> {
        let mut k = KeyLog::default();
        let txt = match std::fs::read_to_string(path) {
            Ok(t) => t, Err(_) => return Ok(k),
        };
        for line in txt.lines() {
            if line.trim().is_empty() { continue; }
            let e: KeyLogEntry = serde_json::from_str(line)?;
            k.by_fpr.insert(e.signer_fpr.clone(), e);
        }
        Ok(k)
    }

    pub fn append(path: &Path, entry: &KeyLogEntry) -> Result<()> {
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).ok(); }
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(f, "{}", serde_json::to_string(entry)?)?;
        Ok(())
    }

    pub fn lookup(&self, fpr: &str) -> Option<&KeyLogEntry> { self.by_fpr.get(fpr) }
    pub fn is_attested_by(&self, fpr: &str, root: &str) -> bool {
        match self.by_fpr.get(fpr) {
            Some(e) => e.attested_by == root,
            None => false,
        }
    }
}
