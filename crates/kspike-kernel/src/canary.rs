//! Memory & file canaries — bait that reveals the attacker the moment they bite.
//!
//! A canary token is a fake credential / path / URL we deliberately plant into
//! places an attacker will look (LSASS-like structs, browser password stores,
//! ~/.aws/credentials, /etc/shadow-stub). If that exact token ever appears in
//! a outbound flow, an auth attempt, or a hash dump, we know who opened the
//! trap and we own their presence in our system.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryToken {
    pub id: String,
    /// Short human tag for the placement, e.g. "lsass.fake.admin".
    pub placement: String,
    /// The exact bytes that are bait. Any appearance of these bytes on the
    /// wire, in a log, or in an auth attempt flags a hostile action.
    pub needle: Vec<u8>,
    /// If the canary is a faked credential, this is the fake username.
    pub fake_user: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl CanaryToken {
    pub fn new(placement: impl Into<String>, needle: Vec<u8>) -> Self {
        Self {
            id: format!("cnr-{:x}", rand_u64()),
            placement: placement.into(),
            needle,
            fake_user: None,
            created_at: chrono::Utc::now(),
        }
    }

    pub fn as_credential(placement: impl Into<String>, user: impl Into<String>) -> Self {
        let u = user.into();
        let pw = format!("!cnr!{}!{}", &u, rand_u64());
        let needle = format!("{u}:{pw}").into_bytes();
        let mut t = Self::new(placement, needle);
        t.fake_user = Some(u);
        t
    }
}

fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ns = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    ns ^ 0x9E3779B97F4A7C15
}

/// Central canary registry — modules add tokens, taps ask "did this byte
/// sequence match any canary?".
pub struct MemoryCanary {
    tokens: RwLock<HashMap<String, CanaryToken>>,
}

impl MemoryCanary {
    pub fn new() -> Self { Self { tokens: RwLock::new(HashMap::new()) } }

    pub fn plant(&self, t: CanaryToken) -> String {
        let id = t.id.clone();
        self.tokens.write().unwrap().insert(id.clone(), t);
        id
    }

    /// Check a buffer for any known canary needle. Returns matching token ids.
    pub fn scan(&self, buf: &[u8]) -> Vec<CanaryToken> {
        let toks = self.tokens.read().unwrap();
        toks.values()
            .filter(|t| crate::inspect::bytes_contain(buf, &t.needle).is_some())
            .cloned()
            .collect()
    }

    pub fn all(&self) -> Vec<CanaryToken> {
        self.tokens.read().unwrap().values().cloned().collect()
    }
}

impl Default for MemoryCanary { fn default() -> Self { Self::new() } }
