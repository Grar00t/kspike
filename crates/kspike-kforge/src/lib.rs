//! K-Forge gossip — P2P replication of evidence ledger segments.
//!
//! Design (v0.4 skeleton):
//!
//!   • Each kspiked node owns a signing key (already used by the ledger).
//!   • Nodes that opt-in advertise their latest `self_hash` + signer_fpr
//!     to peers on TCP `:4893` (kspike default).
//!   • A peer whose local chain is behind requests the missing segment.
//!   • Segments are validated end-to-end (`EvidenceLedger::verify_file`)
//!     before being merged into a local mirror at `/var/lib/kspike/peers/`.
//!
//! This crate implements the wire framing and the verify-then-merge path.
//! The actual peer discovery (mDNS, explicit peer list, or hand-off via
//! K-Forge VCS) is pluggable.

pub mod frame;
pub mod peer;
pub mod merge;
pub mod discovery;
pub mod keylog;
pub mod backpressure;

pub use frame::{Frame, Advert, FetchReq, Segment};
pub use peer::{Peer, PeerList};
pub use merge::{merge_segment, VerifyOutcome};
pub use discovery::{load_peers, save_peers};
pub use keylog::{KeyLog, KeyLogEntry};
pub use backpressure::TokenBucket;
