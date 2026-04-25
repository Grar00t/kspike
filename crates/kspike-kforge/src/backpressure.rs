//! Per-peer back-pressure: simple token bucket so a misbehaving peer can
//! never overwhelm the local merger.

use std::time::{Duration, Instant};

pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self { capacity, tokens: capacity, refill_per_sec, last: Instant::now() }
    }

    pub fn allow(&mut self, cost: f64) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
        if self.tokens >= cost { self.tokens -= cost; true } else { false }
    }

    pub fn cooldown(&self) -> Duration {
        if self.tokens >= 1.0 { Duration::ZERO }
        else { Duration::from_secs_f64((1.0 - self.tokens) / self.refill_per_sec) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bucket_runs_dry_then_recovers() {
        let mut b = TokenBucket::new(3.0, 1.0);
        assert!(b.allow(1.0)); assert!(b.allow(1.0)); assert!(b.allow(1.0));
        assert!(!b.allow(1.0));   // exhausted
        std::thread::sleep(Duration::from_millis(1100));
        assert!(b.allow(1.0));
    }
}
