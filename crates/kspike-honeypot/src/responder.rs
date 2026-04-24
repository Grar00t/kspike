//! Canned-response logic. The real network I/O happens in `kspike-xdp-burp`'s
//! sinkhole interface; this crate just owns the *content* of the deception.

use crate::profile::HoneypotProfile;

pub trait Responder: Send + Sync {
    fn on_hello(&self, profile: &HoneypotProfile) -> Vec<u8>;
    fn on_query(&self, profile: &HoneypotProfile, query: &[u8]) -> Vec<u8>;
    fn on_teardown(&self, profile: &HoneypotProfile) -> Vec<u8> {
        profile.retention.teardown_hint.as_bytes().to_vec()
    }
}

/// A trivial responder that just returns the profile's declared banner.
pub struct Canned;

impl Responder for Canned {
    fn on_hello(&self, p: &HoneypotProfile) -> Vec<u8> { p.banner.as_bytes().to_vec() }
    fn on_query(&self, p: &HoneypotProfile, _q: &[u8]) -> Vec<u8> {
        // Keep it boring: attackers rely on novelty to navigate a target.
        format!("{}\r\n", p.hostname).into_bytes()
    }
}
