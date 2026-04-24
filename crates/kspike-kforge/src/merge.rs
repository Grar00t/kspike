//! Verify-then-merge of a Segment into the local peer mirror.

use crate::frame::Segment;
use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    Merged { records: usize },
    Rejected { reason: String },
}

/// Validate every record's hash-chain + signature, then append to
/// `<base>/<signer_fpr>.jsonl`. Does NOT trust records from a peer who cannot
/// present a contiguous chain from their previous tip.
///
/// NOTE: this is a skeleton. A full implementation would:
///   1) fetch the peer's public key out-of-band (K-Forge VCS signed key log).
///   2) deserialise each line as `EvidenceRecord`, check `prev_hash` continuity
///      with the stored peer-tip, recompute `self_hash`, verify signature.
///   3) write atomically into `<base>/<signer_fpr>.jsonl`.
pub fn merge_segment(base: &Path, seg: &Segment) -> Result<VerifyOutcome> {
    std::fs::create_dir_all(base)?;
    let dst = base.join(format!("{}.jsonl", seg.signer_fpr));
    // Skeleton-only: count lines, don't verify.
    let n = seg.records_jsonl.lines().filter(|l| !l.trim().is_empty()).count();
    if n == 0 {
        return Ok(VerifyOutcome::Rejected { reason: "empty segment".into() });
    }
    // In production: parse+verify each record here.
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&dst)?;
    f.write_all(seg.records_jsonl.as_bytes())?;
    if !seg.records_jsonl.ends_with('\n') { f.write_all(b"\n")?; }
    Ok(VerifyOutcome::Merged { records: n })
}
