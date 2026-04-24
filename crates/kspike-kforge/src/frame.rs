//! Wire frames — JSON-over-line, same style as the daemon.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    Advert(Advert),
    FetchReq(FetchReq),
    Segment(Segment),
    Bye,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advert {
    /// 16-hex fingerprint of the peer's signing pubkey.
    pub signer_fpr: String,
    /// Hex of the peer's latest evidence record `self_hash`.
    pub latest_self_hash: String,
    /// Highest `seq` the peer has sealed.
    pub latest_seq: u64,
    /// Optional human label (never used for trust).
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchReq {
    pub signer_fpr: String,
    /// Requester wants records with `seq > since_seq`.
    pub since_seq: u64,
    /// Maximum records to return in one segment.
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub signer_fpr: String,
    /// JSON-Lines of `EvidenceRecord` values, already signed by the origin.
    pub records_jsonl: String,
}
