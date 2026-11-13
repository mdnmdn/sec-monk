//! Token-bucket rate limiter and failed-login throttle.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_KEYS: usize = 10_000;

fn evict_oldest<V>(map: &mut HashMap<String, V>, stamp: impl Fn(&V) -> Instant) {
    if map.len() <= MAX_KEYS {
        return;
    }
    // Drop the oldest 10% (at least the overflow) in one pass so an attack does not make every call O(n).
    let drop_n = (map.len() - MAX_KEYS).max(MAX_KEYS / 10);
    let mut entries: Vec<(Instant, String)> =
        map.iter().map(|(k, v)| (stamp(v), k.clone())).collect();
    entries.sort_by_key(|(t, _)| *t);
    for (_, k) in entries.into_iter().take(drop_n) {
        map.remove(&k);
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Token bucket per string key (key id or client address). Capacity = `rate_per_minute`, refilled continuously.
/// A rate of 0 refuses every call.
#[derive(Debug)]
pub struct RateLimiter {
    rate_per_minute: u32,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// New limiter allowing `rate_per_minute` calls per minute per key (with a burst of the same size).
    pub fn new(rate_per_minute: u32) -> RateLimiter {
        RateLimiter {
            rate_per_minute,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take one token for `key`; false when the bucket is empty.
    pub fn check(&self, key: &str, now: Instant) -> bool {
        let cap = f64::from(self.rate_per_minute);
        let per_s = cap / 60.0;
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let b = map.entry(key.to_string()).or_insert(Bucket {
            tokens: cap,
            last: now,
        });
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * per_s).min(cap);
        b.last = now;
        let ok = b.tokens >= 1.0;
        if ok {
            b.tokens -= 1.0;
        }
        evict_oldest(&mut map, |b| b.last);
        ok
    }
}

#[derive(Debug, Default)]
struct Failures {
    times: Vec<Instant>,
    blocked_until: Option<Instant>,
    last: Option<Instant>,
}

/// Throttle for failed `exchange` attempts per client address: 10 failures within 5 minutes block the
/// address for 5 minutes.
#[derive(Debug, Default)]
pub struct LoginThrottle {
    map: Mutex<HashMap<String, Failures>>,
}

impl LoginThrottle {
    const MAX_FAILURES: usize = 10;
    const WINDOW: Duration = Duration::from_secs(300);
    const BLOCK: Duration = Duration::from_secs(300);

    /// New empty throttle.
    pub fn new() -> LoginThrottle {
        LoginThrottle::default()
    }

    /// True while the address is blocked.
    pub fn is_blocked(&self, client: &str, now: Instant) -> bool {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.get(client)
            .and_then(|f| f.blocked_until)
            .is_some_and(|u| now < u)
    }

    /// Record a failed attempt; may start a block.
    pub fn record_failure(&self, client: &str, now: Instant) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let f = map.entry(client.to_string()).or_default();
        f.times
            .retain(|t| now.saturating_duration_since(*t) < Self::WINDOW);
        f.times.push(now);
        f.last = Some(now);
        if f.times.len() >= Self::MAX_FAILURES {
            f.blocked_until = Some(now + Self::BLOCK);
            f.times.clear();
        }
        evict_oldest(&mut map, |f| f.last.unwrap_or_else(Instant::now));
    }

    /// Forget the failures of an address after a successful login.
    pub fn record_success(&self, client: &str) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if map.get(client).is_some_and(|f| f.blocked_until.is_none()) {
            map.remove(client);
        }
    }
}
