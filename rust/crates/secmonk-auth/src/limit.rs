//! Token-bucket rate limiter and failed-login throttle.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_KEYS: usize = 10_000;
const SECS_PER_MINUTE: u64 = 60;

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
        let per_s = cap / SECS_PER_MINUTE as f64;
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

/// Failure counter per string key: `max` failures within `window` block the key for `block`.
#[derive(Debug)]
struct FailureCounter {
    max: usize,
    window: Duration,
    block: Duration,
    map: HashMap<String, Failures>,
}

impl FailureCounter {
    fn new(max: usize, window: Duration, block: Duration) -> Self {
        FailureCounter {
            max,
            window,
            block,
            map: HashMap::new(),
        }
    }

    fn is_blocked(&self, key: &str, now: Instant) -> bool {
        self.map
            .get(key)
            .and_then(|f| f.blocked_until)
            .is_some_and(|u| now < u)
    }

    fn record_failure(&mut self, key: &str, now: Instant) {
        let window = self.window;
        let f = self.map.entry(key.to_string()).or_default();
        f.times
            .retain(|t| now.saturating_duration_since(*t) < window);
        f.times.push(now);
        f.last = Some(now);
        if f.times.len() >= self.max {
            f.blocked_until = Some(now + self.block);
            f.times.clear();
        }
        evict_oldest(&mut self.map, |f| f.last.unwrap_or_else(Instant::now));
    }

    /// Forget the failures of a key that is not blocked (an active block is never lifted early).
    fn clear(&mut self, key: &str, now: Instant) {
        let active = self
            .map
            .get(key)
            .and_then(|f| f.blocked_until)
            .is_some_and(|u| now < u);
        if !active {
            self.map.remove(key);
        }
    }
}

#[derive(Debug)]
struct ThrottleState {
    /// `(client, credential id)`: a burst against one key id blocks that id from that client only.
    pairs: FailureCounter,
    /// `client`: a looser cap over every credential id (a guesser rotating ids).
    clients: FailureCounter,
}

/// Throttle for failed authentications (logins and direct credentials on protected routes).
///
/// - per `(client, credential id)` (the API key id, or the subject of a session token, when the credential is
///   well-formed): [`LoginThrottle::PAIR_MAX_FAILURES`] failures within 5 minutes block that id from that client
///   for 5 minutes; the other keys of the same address keep working;
/// - per client: [`LoginThrottle::CLIENT_MAX_FAILURES`] failures within 5 minutes (whatever the id, or with no
///   id at all) block the address for 5 minutes.
///
/// A success forgets the pair's failures unless the pair is blocked; it never touches the per-client counter.
#[derive(Debug)]
pub struct LoginThrottle {
    state: Mutex<ThrottleState>,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        LoginThrottle::new()
    }
}

fn pair_key(client: &str, id: &str) -> String {
    format!("{client}\u{0}{id}")
}

impl LoginThrottle {
    /// Failures of one `(client, credential id)` within [`LoginThrottle::WINDOW`] that block the pair.
    pub const PAIR_MAX_FAILURES: usize = 10;
    /// Failures of one client (any credential) within [`LoginThrottle::WINDOW`] that block the client.
    pub const CLIENT_MAX_FAILURES: usize = 100;
    /// The counting window.
    pub const WINDOW: Duration = Duration::from_secs(5 * SECS_PER_MINUTE);
    /// How long a block lasts.
    pub const BLOCK: Duration = Duration::from_secs(5 * SECS_PER_MINUTE);

    /// New empty throttle.
    pub fn new() -> LoginThrottle {
        LoginThrottle {
            state: Mutex::new(ThrottleState {
                pairs: FailureCounter::new(Self::PAIR_MAX_FAILURES, Self::WINDOW, Self::BLOCK),
                clients: FailureCounter::new(Self::CLIENT_MAX_FAILURES, Self::WINDOW, Self::BLOCK),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ThrottleState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// True while the client, or the `(client, id)` pair, is blocked.
    pub fn is_blocked(&self, client: &str, id: Option<&str>, now: Instant) -> bool {
        let st = self.lock();
        st.clients.is_blocked(client, now)
            || id.is_some_and(|id| st.pairs.is_blocked(&pair_key(client, id), now))
    }

    /// Record a failed attempt; may start a block of the pair and/or of the client.
    pub fn record_failure(&self, client: &str, id: Option<&str>, now: Instant) {
        let mut st = self.lock();
        st.clients.record_failure(client, now);
        if let Some(id) = id {
            st.pairs.record_failure(&pair_key(client, id), now);
        }
    }

    /// Forget the failures of the `(client, id)` pair after a success, unless it is blocked.
    pub fn record_success(&self, client: &str, id: Option<&str>, now: Instant) {
        if let Some(id) = id {
            self.lock().pairs.clear(&pair_key(client, id), now);
        }
    }
}
