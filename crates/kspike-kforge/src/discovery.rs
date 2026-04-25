//! Peer discovery — currently file-based, mDNS-ready.
//!
//! Loads peers from `/etc/kspike/peers.json`:
//!
//! ```json
//! [
//!   { "signer_fpr": "17667b3d2e4d935e",
//!     "addr": "10.0.0.42:4893",
//!     "label": "haven-node-01",
//!     "verified_seq": 0
//!   }
//! ]
//! ```
//!
//! Future: an `mdns` feature will publish/discover under `_kspike._tcp.local.`
//! using the same record schema.

use crate::peer::{Peer, PeerList};
use anyhow::Result;
use std::path::Path;

pub fn load_peers(path: &Path) -> Result<PeerList> {
    let mut list = PeerList::default();
    let txt = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Ok(list),    // empty list if file absent
    };
    let peers: Vec<Peer> = serde_json::from_str(&txt)?;
    for p in peers { list.add(p); }
    Ok(list)
}

pub fn save_peers(path: &Path, list: &PeerList) -> Result<()> {
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).ok(); }
    let v: Vec<&Peer> = list.all().collect();
    std::fs::write(path, serde_json::to_string_pretty(&v)?)?;
    Ok(())
}
