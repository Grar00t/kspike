//! Immutable, cryptographically-sealed evidence ledger.
//!
//! Every action the framework takes — defense, strike, even a judge denial —
//! is sealed into a hash-chained, Ed25519-signed record.
//!
//! Rationale: if the operator is later accused of wrongdoing, the ledger is
//! the defense. If the framework itself misbehaves, the ledger is the proof.
//! There are NO private code paths. Everything is on the record.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::{KSpikeError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: uuid::Uuid,
    pub ts: DateTime<Utc>,
    pub seq: u64,
    /// Category: "signal", "verdict", "strike", "defense", "judge", "roe".
    pub category: String,
    /// Free-form structured payload.
    pub payload: serde_json::Value,
    /// Hash of the previous record (hex). Empty string for genesis.
    pub prev_hash: String,
    /// Blake3 hash of (seq || ts || category || payload || prev_hash).
    pub self_hash: String,
    /// Ed25519 signature over self_hash, hex-encoded.
    pub signature: String,
    /// Public key fingerprint of the signer, hex-encoded (blake3 of pubkey).
    pub signer_fpr: String,
}

/// A signer abstraction — could be file-backed, HSM-backed, etc.
pub trait Signer: Send + Sync {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn public(&self) -> VerifyingKey;
}

pub struct InMemorySigner {
    key: SigningKey,
}

impl InMemorySigner {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&bytes),
        }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

impl Signer for InMemorySigner {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(msg);
        sig.to_bytes().to_vec()
    }

    fn public(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

pub struct EvidenceLedger {
    signer: Box<dyn Signer>,
    state: Mutex<LedgerState>,
    path: Option<PathBuf>,
}

struct LedgerState {
    seq: u64,
    last_hash: String,
}

impl EvidenceLedger {
    pub fn new(signer: Box<dyn Signer>, path: Option<PathBuf>) -> Self {
        Self {
            signer,
            state: Mutex::new(LedgerState { seq: 0, last_hash: String::new() }),
            path,
        }
    }

    pub fn seal(&self, category: impl Into<String>, payload: serde_json::Value) -> Result<EvidenceRecord> {
        let mut st = self.state.lock().unwrap();
        let seq = st.seq + 1;
        let ts = Utc::now();
        let category = category.into();
        let prev_hash = st.last_hash.clone();

        let body = serde_json::json!({
            "seq": seq,
            "ts": ts,
            "category": &category,
            "payload": &payload,
            "prev_hash": &prev_hash,
        });
        let body_bytes = serde_json::to_vec(&body).map_err(KSpikeError::Serde)?;
        let self_hash = blake3::hash(&body_bytes).to_hex().to_string();

        let sig = self.signer.sign(self_hash.as_bytes());
        let signature = hex::encode(sig);
        let signer_fpr = hex::encode(blake3::hash(self.signer.public().as_bytes()).as_bytes())
            [..16].to_string();

        let rec = EvidenceRecord {
            id: uuid::Uuid::new_v4(),
            ts,
            seq,
            category,
            payload,
            prev_hash,
            self_hash: self_hash.clone(),
            signature,
            signer_fpr,
        };

        st.seq = seq;
        st.last_hash = self_hash;

        if let Some(p) = &self.path {
            append_jsonl(p, &rec)?;
        }
        Ok(rec)
    }

    /// Verify a ledger file end-to-end: hash chain + signatures.
    pub fn verify_file(path: &Path, pubkey: &VerifyingKey) -> Result<usize> {
        let data = std::fs::read_to_string(path)?;
        let mut prev = String::new();
        let mut n = 0usize;
        for line in data.lines() {
            if line.trim().is_empty() { continue; }
            let rec: EvidenceRecord = serde_json::from_str(line)?;
            if rec.prev_hash != prev {
                return Err(KSpikeError::Evidence(format!("chain break at seq {}", rec.seq)));
            }
            let body = serde_json::json!({
                "seq": rec.seq,
                "ts": rec.ts,
                "category": &rec.category,
                "payload": &rec.payload,
                "prev_hash": &rec.prev_hash,
            });
            let body_bytes = serde_json::to_vec(&body)?;
            let computed = blake3::hash(&body_bytes).to_hex().to_string();
            if computed != rec.self_hash {
                return Err(KSpikeError::Evidence(format!("hash mismatch at seq {}", rec.seq)));
            }
            let sig_bytes = hex::decode(&rec.signature)
                .map_err(|e| KSpikeError::Evidence(format!("bad hex sig: {e}")))?;
            let sig = Signature::from_slice(&sig_bytes)
                .map_err(|e| KSpikeError::Evidence(format!("bad sig: {e}")))?;
            pubkey.verify(rec.self_hash.as_bytes(), &sig)
                .map_err(|e| KSpikeError::Evidence(format!("sig verify fail at seq {}: {e}", rec.seq)))?;
            prev = rec.self_hash;
            n += 1;
        }
        Ok(n)
    }
}

fn append_jsonl(path: &Path, rec: &EvidenceRecord) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(rec)?;
    writeln!(f, "{}", line)?;
    Ok(())
}

// Tiny hex helper — no dep.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let b = bytes.as_ref();
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push(HEX[(byte >> 4) as usize] as char);
            s.push(HEX[(byte & 0x0f) as usize] as char);
        }
        s
    }
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 { return Err("odd hex len".into()); }
        let mut out = Vec::with_capacity(s.len() / 2);
        let b = s.as_bytes();
        for i in (0..b.len()).step_by(2) {
            let hi = hex_val(b[i]).ok_or("bad hex")?;
            let lo = hex_val(b[i+1]).ok_or("bad hex")?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }
    fn hex_val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
}
