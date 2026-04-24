//! Peer bookkeeping.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub signer_fpr: String,
    pub addr: SocketAddr,
    pub label: Option<String>,
    /// Latest `seq` we've successfully verified for this peer.
    pub verified_seq: u64,
}

#[derive(Debug, Default)]
pub struct PeerList {
    inner: HashMap<String, Peer>,
}

impl PeerList {
    pub fn add(&mut self, p: Peer) { self.inner.insert(p.signer_fpr.clone(), p); }
    pub fn get(&self, fpr: &str) -> Option<&Peer> { self.inner.get(fpr) }
    pub fn all(&self) -> impl Iterator<Item = &Peer> { self.inner.values() }
    pub fn update_seq(&mut self, fpr: &str, seq: u64) {
        if let Some(p) = self.inner.get_mut(fpr) {
            if seq > p.verified_seq { p.verified_seq = seq; }
        }
    }
}
