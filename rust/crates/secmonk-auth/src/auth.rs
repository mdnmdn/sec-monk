//! The authenticator: key store + JWT signer + rate limits.

use std::path::Path;
use std::sync::RwLock;
use std::time::{Instant, SystemTime};

use crate::jwt::{IssuedToken, JwtSigner};
use crate::keys::{AuthVia, KeyStore, Principal};
use crate::limit::{LoginThrottle, RateLimiter};
use crate::timefmt::unix_secs;
use crate::{AuthError, Result};

/// Ties the key store, the JWT signer and the limiters together.
#[derive(Debug)]
pub struct Authenticator {
    store: RwLock<KeyStore>,
    signer: JwtSigner,
    limiter: RateLimiter,
    throttle: LoginThrottle,
}

impl Authenticator {
    /// Build from a loaded store, a signer and the per-key rate (calls per minute).
    pub fn new(store: KeyStore, signer: JwtSigner, rate_per_minute: u32) -> Authenticator {
        Authenticator {
            store: RwLock::new(store),
            signer,
            limiter: RateLimiter::new(rate_per_minute),
            throttle: LoginThrottle::new(),
        }
    }

    /// Re-read the keys file if its mtime changed. Returns true when it was reloaded.
    /// On a read error the old keys stay in force and the error is returned.
    pub fn reload(&self) -> Result<bool> {
        let path = {
            let store = self.store.read().unwrap_or_else(|e| e.into_inner());
            if !store.file_changed() {
                return Ok(false);
            }
            store.path().map(Path::to_path_buf)
        };
        let Some(path) = path else { return Ok(false) };
        let fresh = KeyStore::load(path)?;
        *self.store.write().unwrap_or_else(|e| e.into_inner()) = fresh;
        tracing::info!(target: "audit", "api key file reloaded");
        Ok(true)
    }

    fn refresh(&self) {
        if let Err(e) = self.reload() {
            tracing::warn!("keeping previous API keys, reload failed: {e}");
        }
    }

    /// The per-key rate limiter (the HTTP layer calls `check(key_id, Instant::now())`).
    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    /// The failed-exchange throttle.
    pub fn throttle(&self) -> &LoginThrottle {
        &self.throttle
    }

    /// Take a rate-limit token for the principal's key.
    pub fn check_rate(&self, principal: &Principal, now: Instant) -> Result<()> {
        if self.limiter.check(&principal.key_id, now) {
            Ok(())
        } else {
            Err(AuthError::RateLimited)
        }
    }

    /// Exchange an API key for a JWT.
    pub fn exchange(&self, api_key: &str, now: SystemTime) -> Result<IssuedToken> {
        self.refresh();
        let principal = self
            .store
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .verify(api_key, now)?;
        self.signer.issue(&principal, unix_secs(now))
    }

    /// [`Authenticator::exchange`] with the failed-login throttle for `client`.
    pub fn exchange_from(
        &self,
        client: &str,
        api_key: &str,
        now: SystemTime,
        at: Instant,
    ) -> Result<IssuedToken> {
        if self.throttle.is_blocked(client, at) {
            return Err(AuthError::RateLimited);
        }
        match self.exchange(api_key, now) {
            Ok(t) => {
                self.throttle.record_success(client);
                Ok(t)
            }
            Err(e) => {
                if e.is_credential_failure() {
                    self.throttle.record_failure(client, at);
                }
                Err(e)
            }
        }
    }

    /// Authenticate an `Authorization` header value: `Bearer <jwt>` or `ApiKey <key>` (scheme case-insensitive).
    pub fn authenticate(&self, header: &str, now: SystemTime) -> Result<Principal> {
        self.refresh();
        let header = header.trim();
        let (scheme, cred) = header
            .split_once(' ')
            .map(|(s, c)| (s, c.trim()))
            .ok_or_else(|| AuthError::Malformed("bad Authorization header".into()))?;
        if cred.is_empty() || cred.contains(' ') {
            return Err(AuthError::Malformed("bad Authorization header".into()));
        }
        if scheme.eq_ignore_ascii_case("bearer") {
            let claims = self.signer.verify(cred, unix_secs(now))?;
            let store = self.store.read().unwrap_or_else(|e| e.into_inner());
            let rec = store
                .active_record(&claims.sub, now)
                .ok_or(AuthError::Revoked)?;
            Ok(Principal {
                key_id: rec.id.clone(),
                name: rec.name.clone(),
                scopes: claims.scopes()?,
                via: AuthVia::Jwt,
                expires_at: Some(claims.exp),
            })
        } else if scheme.eq_ignore_ascii_case("apikey") {
            self.store
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .verify(cred, now)
        } else {
            Err(AuthError::Malformed(
                "unsupported Authorization scheme".into(),
            ))
        }
    }
}
