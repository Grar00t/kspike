//! Layer 5: Proof Generator
//!
//! Generates SHA-256 hashes and maintains cryptographic audit trails.
//! Every decision is sealed with a proof hash and timestamp.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRecord {
    /// Unique identifier for this decision
    pub decision_id: String,
    /// SHA-256 hash of (request || decision || rationale)
    pub proof_hash: String,
    /// Timestamp when decision was made
    pub timestamp: DateTime<Utc>,
    /// Reference to previous proof (chain)
    pub previous_hash: Option<String>,
    /// The decision that was made
    pub decision: String,
    /// Rationale for the decision
    pub rationale: String,
    /// Module that requested this decision
    pub module: String,
}

pub struct ProofGenerator {
    previous_hash: Option<String>,
}

impl ProofGenerator {
    pub fn new() -> Self {
        Self { previous_hash: None }
    }

    /// Generate a proof record for a decision.
    pub fn generate_proof(
        &mut self,
        decision_id: String,
        module: String,
        decision: String,
        rationale: String,
        request_json: &str,
    ) -> ProofRecord {
        let timestamp = Utc::now();

        // Build proof content: request || decision || rationale
        let proof_content = format!("{}\n{}\n{}", request_json, decision, rationale);

        // Hash with previous_hash for chain
        let hash_input = if let Some(ref prev) = self.previous_hash {
            format!("{}\n{}", prev, proof_content)
        } else {
            proof_content
        };

        let mut hasher = Sha256::new();
        hasher.update(hash_input.as_bytes());
        let proof_hash = format!("{:x}", hasher.finalize());

        let record = ProofRecord {
            decision_id,
            proof_hash: proof_hash.clone(),
            timestamp,
            previous_hash: self.previous_hash.clone(),
            decision,
            rationale,
            module,
        };

        // Update chain
        self.previous_hash = Some(proof_hash);

        record
    }

    /// Verify a proof record against its content.
    pub fn verify_proof(record: &ProofRecord, request_json: &str) -> bool {
        let proof_content = format!("{}\n{}\n{}", request_json, record.decision, record.rationale);
        let mut hasher = Sha256::new();
        hasher.update(proof_content.as_bytes());
        let computed_hash = format!("{:x}", hasher.finalize());
        computed_hash == record.proof_hash
    }

    /// Get the current chain head hash.
    pub fn chain_head(&self) -> Option<&str> {
        self.previous_hash.as_deref()
    }
}

impl Default for ProofGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    pub records: Vec<ProofRecord>,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self { records: Vec::new() }
    }

    pub fn add_record(&mut self, record: ProofRecord) {
        self.records.push(record);
    }

    /// Verify the integrity of the entire trail.
    /// Each record's previous_hash must match the prior record's proof_hash.
    pub fn verify_chain_integrity(&self) -> bool {
        for i in 1..self.records.len() {
            let current = &self.records[i];
            let previous = &self.records[i - 1];
            if current.previous_hash.as_ref() != Some(&previous.proof_hash) {
                return false;
            }
        }
        true
    }

    pub fn records(&self) -> &[ProofRecord] {
        &self.records
    }

    /// Get all records for a specific module.
    pub fn records_for_module(&self, module: &str) -> Vec<&ProofRecord> {
        self.records.iter().filter(|r| r.module == module).collect()
    }
}

impl Default for AuditTrail {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_generation() {
        let mut generator = ProofGenerator::new();
        let record = generator.generate_proof(
            "dec-001".to_string(),
            "defender.test".to_string(),
            "allow".to_string(),
            "test rationale".to_string(),
            r#"{"module":"test"}"#,
        );
        assert!(!record.proof_hash.is_empty());
        assert_eq!(record.proof_hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_proof_verification() {
        let mut generator = ProofGenerator::new();
        let req_json = r#"{"module":"test"}"#;
        let record = generator.generate_proof(
            "dec-001".to_string(),
            "defender.test".to_string(),
            "allow".to_string(),
            "test rationale".to_string(),
            req_json,
        );
        assert!(ProofGenerator::verify_proof(&record, req_json));
    }

    #[test]
    fn test_audit_trail_chain() {
        let mut trail = AuditTrail::new();
        let mut generator = ProofGenerator::new();

        for i in 0..3 {
            let record = generator.generate_proof(
                format!("dec-{:03}", i),
                "module.test".to_string(),
                "allow".to_string(),
                format!("rationale {}", i),
                r#"{"n":1}"#,
            );
            trail.add_record(record);
        }

        assert!(trail.verify_chain_integrity());
    }
}
