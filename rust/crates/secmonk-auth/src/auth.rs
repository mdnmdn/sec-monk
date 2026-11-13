//! The authenticator: an ordered chain of [`AuthProvider`]s, the session JWT signer and the rate limits.
//!
//! The HTTP layer talks only to [`Authenticator`]; strategies plug in as providers ([`crate::provider`]).

use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime};

use serde_json::Value;

use crate::jwt::{IssuedToken, JwtSigner};
use crate::keys::{API_KEY_PROVIDER, AuthVia, KeyStore, Principal};
use crate::limit::{LoginThrottle, RateLimiter};
use crate::provider::{AuthProvider, RequestContext};
use crate::timefmt::unix_secs;
use crate::{AuthError, Result};

/// The API keys of `api_keys.toml` as a provider: `Authorization: ApiKey smk_…` directly, and the `api_key` login
/// method (`{"method": "api_key", "api_key": "smk_…"}`, the default method of `POST /auth/token`).
#[derive(Debug)]
pub struct ApiKeyProvider {
    store: RwLock<KeyStore>,
}

impl ApiKeyProvider {
    /// A provider over a loaded key store.
    pub fn new(store: KeyStore) -> ApiKeyProvider {
        ApiKeyProvider {
            store: RwLock::new(store),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, KeyStore> {
        self.store.read().unwrap_or_else(|e| e.into_inner())
    }

    fn refresh(&self) {
        if let Err(e) = self.reload() {
            tracing::warn!("keeping previous API keys, reload failed: {e}");
        }
    }

    fn verify(&self, key: &str, now: SystemTime) -> Result<Principal> {
        self.refresh();
        self.read().verify(key, now)
    }
}

impl AuthProvider for ApiKeyProvider {
    fn name(&self) -> &str {
        API_KEY_PROVIDER
    }

    fn login_methods(&self) -> &[&str] {
        &[API_KEY_PROVIDER]
    }

    fn authenticate(&self, ctx: &RequestContext<'_>, now: SystemTime) -> Option<Result<Principal>> {
        let (scheme, cred) = match ctx.authorization_parts()? {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };
        if !scheme.eq_ignore_ascii_case("apikey") {
            return None;
        }
        Some(self.verify(cred, now))
    }

    fn login(&self, _method: &str, params: &Value, now: SystemTime) -> Result<Principal> {
        let key = params
            .get("api_key")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::Malformed("api_key is required".into()))?;
        self.verify(key, now)
    }

    fn revalidate(&self, subject: &str, now: SystemTime) -> Result<String> {
        self.refresh();
        self.read()
            .active_record(subject, now)
            .map(|r| r.name.clone())
            .ok_or(AuthError::Revoked)
    }

    fn reload(&self) -> Result<bool> {
        let path = {
            let store = self.read();
            if !store.file_changed() {
                return Ok(false);
            }
            match store.path() {
                Some(p) => p.to_path_buf(),
                None => return Ok(false),
            }
        };
        let fresh = KeyStore::load(&path)?;
        let count = fresh.list().len();
        *self.store.write().unwrap_or_else(|e| e.into_inner()) = fresh;
        tracing::info!(target: "audit", keys = count, "API keys reloaded");
        Ok(true)
    }
}

/// Ties the provider chain, the session JWT signer and the limiters together.
#[derive(Debug)]
pub struct Authenticator {
    providers: Vec<Arc<dyn AuthProvider>>,
    signer: JwtSigner,
    limiter: RateLimiter,
    throttle: LoginThrottle,
}

impl Authenticator {
    /// The API-key provider alone over a loaded store (today's server mode), a signer and the per-subject rate
    /// (calls per minute).
    pub fn new(store: KeyStore, signer: JwtSigner, rate_per_minute: u32) -> Authenticator {
        Authenticator::with_providers(
            vec![Arc::new(ApiKeyProvider::new(store))],
            signer,
            rate_per_minute,
        )
    }

    /// An ordered provider chain: for a direct request the first provider that recognizes the credential
    /// decides. Provider names must be unique (a duplicate is dropped with a warning).
    pub fn with_providers(
        providers: Vec<Arc<dyn AuthProvider>>,
        signer: JwtSigner,
        rate_per_minute: u32,
    ) -> Authenticator {
        let mut unique: Vec<Arc<dyn AuthProvider>> = Vec::with_capacity(providers.len());
        for p in providers {
            if unique.iter().any(|u| u.name() == p.name()) {
                tracing::warn!(provider = p.name(), "duplicate auth provider ignored");
                continue;
            }
            unique.push(p);
        }
        Authenticator {
            providers: unique,
            signer,
            limiter: RateLimiter::new(rate_per_minute),
            throttle: LoginThrottle::new(),
        }
    }

    /// Names of the providers, in chain order (`GET /auth/info`).
    pub fn provider_names(&self) -> Vec<&str> {
        self.providers.iter().map(|p| p.name()).collect()
    }

    /// Every login method the chain accepts (`GET /auth/info`).
    pub fn login_methods(&self) -> Vec<&str> {
        self.providers
            .iter()
            .flat_map(|p| p.login_methods().iter().copied())
            .collect()
    }

    fn provider(&self, name: &str) -> Option<&Arc<dyn AuthProvider>> {
        self.providers.iter().find(|p| p.name() == name)
    }

    /// Ask every provider to pick up changed backing data. Returns true when one reloaded. On an error the old
    /// data stays in force and the first error is returned after every provider was asked.
    pub fn reload(&self) -> Result<bool> {
        let mut changed = false;
        let mut first_err = None;
        for p in &self.providers {
            match p.reload() {
                Ok(c) => changed |= c,
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        first_err.map_or(Ok(changed), Err)
    }

    /// The per-subject rate limiter.
    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    /// The failed-login throttle.
    pub fn throttle(&self) -> &LoginThrottle {
        &self.throttle
    }

    /// Take a rate-limit token for the principal (keyed `provider:subject`).
    pub fn check_rate(&self, principal: &Principal, now: Instant) -> Result<()> {
        let key = format!("{}:{}", principal.provider, principal.key_id);
        if self.limiter.check(&key, now) {
            Ok(())
        } else {
            Err(AuthError::RateLimited)
        }
    }

    /// Verify a login and issue a session JWT. `method` selects the provider; `params` is the login body.
    pub fn login(&self, method: &str, params: &Value, now: SystemTime) -> Result<IssuedToken> {
        let provider = self
            .providers
            .iter()
            .find(|p| p.login_methods().contains(&method))
            .ok_or_else(|| AuthError::Malformed(format!("unsupported login method {method:?}")))?;
        let principal = provider.login(method, params, now)?;
        self.signer.issue(&principal, unix_secs(now))
    }

    /// [`Authenticator::login`] with the failed-login throttle for `client`.
    pub fn login_from(
        &self,
        client: &str,
        method: &str,
        params: &Value,
        now: SystemTime,
        at: Instant,
    ) -> Result<IssuedToken> {
        if self.throttle.is_blocked(client, at) {
            return Err(AuthError::RateLimited);
        }
        match self.login(method, params, now) {
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

    /// Exchange an API key for a JWT (the `api_key` login method).
    pub fn exchange(&self, api_key: &str, now: SystemTime) -> Result<IssuedToken> {
        self.login(
            API_KEY_PROVIDER,
            &serde_json::json!({ "api_key": api_key }),
            now,
        )
    }

    /// [`Authenticator::exchange`] with the failed-login throttle for `client`.
    pub fn exchange_from(
        &self,
        client: &str,
        api_key: &str,
        now: SystemTime,
        at: Instant,
    ) -> Result<IssuedToken> {
        self.login_from(
            client,
            API_KEY_PROVIDER,
            &serde_json::json!({ "api_key": api_key }),
            now,
            at,
        )
    }

    /// Authenticate a request: a `Bearer` session JWT of this server (revalidated with its issuing provider),
    /// else the first provider that recognizes the credential. `Missing` when nothing recognizes anything.
    pub fn authenticate_request(
        &self,
        ctx: &RequestContext<'_>,
        now: SystemTime,
    ) -> Result<Principal> {
        if let Some(parts) = ctx.authorization_parts() {
            let (scheme, cred) = parts?;
            if scheme.eq_ignore_ascii_case("bearer") {
                return self.session(cred, now);
            }
        }
        for p in &self.providers {
            if let Some(verdict) = p.authenticate(ctx, now) {
                return verdict;
            }
        }
        if ctx.authorization.is_some() {
            return Err(AuthError::Malformed(
                "unsupported Authorization scheme".into(),
            ));
        }
        Err(AuthError::Missing)
    }

    /// Authenticate an `Authorization` header value: `Bearer <jwt>` or `ApiKey <key>` (scheme case-insensitive).
    pub fn authenticate(&self, header: &str, now: SystemTime) -> Result<Principal> {
        self.authenticate_request(&RequestContext::new(Some(header), None), now)
    }

    fn session(&self, token: &str, now: SystemTime) -> Result<Principal> {
        let claims = self.signer.verify(token, unix_secs(now))?;
        // the issuing provider must still exist and still accept the subject (revocation kills sessions)
        let provider = self.provider(&claims.prv).ok_or(AuthError::Revoked)?;
        let name = provider.revalidate(&claims.sub, now)?;
        Ok(Principal {
            key_id: claims.sub.clone(),
            provider: claims.prv.clone(),
            name,
            scopes: claims.scopes()?,
            via: AuthVia::Jwt,
            expires_at: Some(claims.exp),
        })
    }
}
