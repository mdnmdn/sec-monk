//! The authenticator: an ordered chain of [`AuthProvider`]s, the session JWT signer and the rate limits.
//!
//! The HTTP layer talks only to [`Authenticator`]; strategies plug in as providers ([`crate::provider`]).

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, TryLockError};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;

use crate::jwt::{ISSUER, IssuedToken, JwtSigner, peek_issuer, peek_subject};
use crate::keys::{API_KEY_PROVIDER, AuthVia, Fingerprint, KeyStore, Principal, parse_api_key};
use crate::limit::{LoginThrottle, RateLimiter};
use crate::provider::{AuthProvider, RequestContext, Subject};
use crate::timefmt::unix_secs;
use crate::{AuthError, Result};

/// How often the keys file is looked at (one `stat` per interval, whatever the request rate).
pub const KEYS_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// How often a broken keys file is reported again while requests are refused.
const BROKEN_WARN_INTERVAL: Duration = Duration::from_secs(30);

/// The last load of the keys file failed: API-key authentication is refused until a load succeeds.
#[derive(Debug)]
struct Broken {
    error: String,
    /// The file as it was when it failed (re-parsed only once it changes again).
    seen: Option<Fingerprint>,
}

#[derive(Debug)]
struct Snapshot {
    store: KeyStore,
    broken: Option<Broken>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The API keys of `api_keys.toml` as a provider: `Authorization: ApiKey smk_…` directly, and the `api_key` login
/// method (`{"method": "api_key", "api_key": "smk_…"}`, the default method of `POST /auth/token`).
///
/// The file is looked at most once per [`KEYS_CHECK_INTERVAL`] (by whichever request comes first; concurrent
/// requests never wait for it and never reload twice) and re-read when its fingerprint (device, inode, length,
/// mtime) changed. Readers take the current snapshot (`Arc`) and never wait on parsing. A reload that fails
/// **fails closed**: API-key requests and API-key sessions are refused (503, an error logged at most every 30 s)
/// until the file loads again, so a revocation by hand edit is never silently ignored.
#[derive(Debug)]
pub struct ApiKeyProvider {
    current: RwLock<Arc<Snapshot>>,
    last_check: Mutex<Option<Instant>>,
    check_interval: Duration,
    last_warn: Mutex<Option<Instant>>,
}

impl ApiKeyProvider {
    /// A provider over a loaded key store.
    pub fn new(store: KeyStore) -> ApiKeyProvider {
        ApiKeyProvider {
            current: RwLock::new(Arc::new(Snapshot {
                store,
                broken: None,
            })),
            last_check: Mutex::new(Some(Instant::now())),
            check_interval: KEYS_CHECK_INTERVAL,
            last_warn: Mutex::new(None),
        }
    }

    /// The same provider with another minimum interval between two looks at the file (tests use zero).
    #[must_use]
    pub fn with_check_interval(mut self, interval: Duration) -> ApiKeyProvider {
        self.check_interval = interval;
        self
    }

    fn snapshot(&self) -> Arc<Snapshot> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn swap(&self, snap: Snapshot) {
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(snap);
    }

    /// Look at the file if the interval has passed and nobody else is looking right now.
    fn maybe_refresh(&self) {
        let now = Instant::now();
        let mut last = match self.last_check.try_lock() {
            Ok(g) => g,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => return, // another request is checking: use the current keys
        };
        if last.is_some_and(|t| now.saturating_duration_since(t) < self.check_interval) {
            return;
        }
        *last = Some(now);
        // errors are logged by reload_locked; the snapshot says whether to refuse
        let _ = self.reload_locked();
    }

    /// Re-read the file when it changed. The caller holds `last_check`.
    fn reload_locked(&self) -> Result<bool> {
        let snap = self.snapshot();
        let Some(path) = snap.store.path().map(Path::to_path_buf) else {
            return Ok(false);
        };
        let changed = match &snap.broken {
            Some(b) => Fingerprint::of_path(&path) != b.seen,
            None => snap.store.file_changed(),
        };
        if !changed {
            return match &snap.broken {
                Some(b) => Err(AuthError::Unavailable(b.error.clone())),
                None => Ok(false),
            };
        }
        let seen = Fingerprint::of_path(&path);
        match KeyStore::load(&path) {
            Ok(fresh) => {
                let count = fresh.list().len();
                let was_broken = snap.broken.is_some();
                self.swap(Snapshot {
                    store: fresh,
                    broken: None,
                });
                tracing::info!(target: "audit", keys = count, recovered = was_broken, "API keys reloaded");
                Ok(true)
            }
            Err(e) => {
                tracing::error!(
                    target: "audit",
                    path = ?path,
                    "API keys file failed to load; refusing API-key authentication until it loads: {e}"
                );
                *lock(&self.last_warn) = Some(Instant::now());
                self.swap(Snapshot {
                    store: snap.store.clone(),
                    broken: Some(Broken {
                        error: e.to_string(),
                        seen,
                    }),
                });
                Err(e)
            }
        }
    }

    /// The current keys, or the fail-closed refusal.
    fn usable(&self) -> Result<Arc<Snapshot>> {
        self.maybe_refresh();
        let snap = self.snapshot();
        if let Some(b) = &snap.broken {
            let now = Instant::now();
            let mut last = lock(&self.last_warn);
            if last.is_none_or(|t| now.saturating_duration_since(t) >= BROKEN_WARN_INTERVAL) {
                *last = Some(now);
                tracing::error!(
                    target: "audit",
                    "refusing API-key authentication: the API keys file failed to load: {}",
                    b.error
                );
            }
            return Err(AuthError::Unavailable(
                "API keys file failed to load".into(),
            ));
        }
        Ok(snap)
    }

    fn verify(&self, key: &str, now: SystemTime) -> Result<Principal> {
        self.usable()?.store.verify(key, now)
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

    fn revalidate(&self, subject: &str, now: SystemTime) -> Result<Subject> {
        self.usable()?
            .store
            .active_record(subject, now)
            .map(|r| Subject {
                name: r.name.clone(),
                scopes: r.scopes.clone(),
            })
            .ok_or(AuthError::Revoked)
    }

    fn reload(&self) -> Result<bool> {
        let mut last = lock(&self.last_check);
        *last = Some(Instant::now());
        let r = self.reload_locked();
        drop(last);
        r
    }
}

/// The throttle bucket of a credential: the API key id or the (unverified) subject of a session token, when the
/// credential is well-formed. Never the secret.
fn credential_id(ctx: &RequestContext<'_>) -> Option<String> {
    let (scheme, cred) = ctx.authorization_parts()?.ok()?;
    if scheme.eq_ignore_ascii_case("apikey") {
        parse_api_key(cred)
            .ok()
            .map(|(id, _)| format!("{API_KEY_PROVIDER}:{id}"))
    } else if scheme.eq_ignore_ascii_case("bearer") {
        peek_subject(cred).map(|s| format!("jwt:{s}"))
    } else {
        None
    }
}

fn login_credential_id(method: &str, params: &Value) -> Option<String> {
    if method != API_KEY_PROVIDER {
        return None;
    }
    let key = params.get("api_key").and_then(Value::as_str)?;
    parse_api_key(key)
        .ok()
        .map(|(id, _)| format!("{API_KEY_PROVIDER}:{id}"))
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

    /// Ask every provider to pick up changed backing data now. Returns true when one reloaded. The first error is
    /// returned after every provider was asked (the API-key provider then refuses until its file loads again).
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
        let key = format!("{}:{}", principal.provider, principal.subject);
        if self.limiter.check(&key, now) {
            Ok(())
        } else {
            Err(AuthError::RateLimited)
        }
    }

    /// Verify a login and issue a session JWT. `method` selects the provider; `params` is the login body.
    pub fn login(&self, method: &str, params: &Value, now: SystemTime) -> Result<IssuedToken> {
        self.login_inner(method, params, now).1
    }

    fn login_inner(
        &self,
        method: &str,
        params: &Value,
        now: SystemTime,
    ) -> (&str, Result<IssuedToken>) {
        let Some(provider) = self
            .providers
            .iter()
            .find(|p| p.login_methods().contains(&method))
        else {
            return (
                "-",
                Err(AuthError::Malformed(format!(
                    "unsupported login method {method:?}"
                ))),
            );
        };
        let r = provider
            .login(method, params, now)
            .and_then(|principal| self.signer.issue(&principal, unix_secs(now)));
        (provider.name(), r)
    }

    /// [`Authenticator::login`] with the failed-login throttle for `client` (see [`LoginThrottle`]); failures
    /// are audit-logged (client, provider, reason class; never the credential).
    pub fn login_from(
        &self,
        client: &str,
        method: &str,
        params: &Value,
        now: SystemTime,
        at: Instant,
    ) -> Result<IssuedToken> {
        let id = login_credential_id(method, params);
        if self.throttle.is_blocked(client, id.as_deref(), at) {
            audit_failure(client, "-", &AuthError::RateLimited, Some("/auth/token"));
            return Err(AuthError::RateLimited);
        }
        let (provider, r) = self.login_inner(method, params, now);
        match &r {
            Ok(_) => self.throttle.record_success(client, id.as_deref(), at),
            Err(e) => {
                if e.is_credential_failure() {
                    self.throttle.record_failure(client, id.as_deref(), at);
                }
                audit_failure(client, provider, e, Some("/auth/token"));
            }
        }
        r
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

    /// Authenticate a request: a `Bearer` session JWT of this server (`iss` = `secmonk`, revalidated with its
    /// issuing provider), else the first provider that recognizes the credential (any other `Bearer` token
    /// included). `Missing` when nothing recognizes anything. No throttle: see
    /// [`Authenticator::authenticate_from`].
    pub fn authenticate_request(
        &self,
        ctx: &RequestContext<'_>,
        now: SystemTime,
    ) -> Result<Principal> {
        self.authenticate_inner(ctx, now).1
    }

    /// [`Authenticator::authenticate_request`] for a protected route, with the failed-authentication throttle
    /// of `ctx.client` (the same one as the logins) and an audit line per failure (client, provider, reason
    /// class, path; never the credential). A missing credential is neither counted nor logged.
    pub fn authenticate_from(
        &self,
        ctx: &RequestContext<'_>,
        now: SystemTime,
        at: Instant,
    ) -> Result<Principal> {
        let client = ctx.client.unwrap_or("unknown");
        let id = credential_id(ctx);
        if ctx.authorization.is_some() && self.throttle.is_blocked(client, id.as_deref(), at) {
            audit_failure(client, "-", &AuthError::RateLimited, ctx.path);
            return Err(AuthError::RateLimited);
        }
        let (provider, r) = self.authenticate_inner(ctx, now);
        match &r {
            Ok(_) => self.throttle.record_success(client, id.as_deref(), at),
            Err(AuthError::Missing) => {}
            Err(e) => {
                if e.is_credential_failure() {
                    self.throttle.record_failure(client, id.as_deref(), at);
                }
                audit_failure(client, provider, e, ctx.path);
            }
        }
        r
    }

    fn authenticate_inner(
        &self,
        ctx: &RequestContext<'_>,
        now: SystemTime,
    ) -> (&str, Result<Principal>) {
        if let Some(parts) = ctx.authorization_parts() {
            let (scheme, cred) = match parts {
                Ok(p) => p,
                Err(e) => return ("-", Err(e)),
            };
            if scheme.eq_ignore_ascii_case("bearer") && peek_issuer(cred).as_deref() == Some(ISSUER)
            {
                return ("session", self.session(cred, now));
            }
        }
        for p in &self.providers {
            if let Some(verdict) = p.authenticate(ctx, now) {
                return (p.name(), verdict);
            }
        }
        if ctx.authorization.is_some() {
            return (
                "-",
                Err(AuthError::Malformed(
                    "unsupported Authorization scheme or token".into(),
                )),
            );
        }
        ("-", Err(AuthError::Missing))
    }

    /// Authenticate an `Authorization` header value: `Bearer <jwt>` or `ApiKey <key>` (scheme case-insensitive).
    pub fn authenticate(&self, header: &str, now: SystemTime) -> Result<Principal> {
        self.authenticate_request(&RequestContext::new(Some(header), None), now)
    }

    fn session(&self, token: &str, now: SystemTime) -> Result<Principal> {
        let claims = self.signer.verify(token, unix_secs(now))?;
        // the issuing provider must still exist and still accept the subject (revocation kills sessions)
        let provider = self.provider(&claims.prv).ok_or(AuthError::Revoked)?;
        let current = provider.revalidate(&claims.sub, now)?;
        // scopes removed from the subject since the login are gone from its sessions too
        let scopes = claims.scopes()?.intersection(&current.scopes);
        Ok(Principal {
            subject: claims.sub.clone(),
            provider: claims.prv.clone(),
            name: current.name,
            scopes,
            via: AuthVia::Jwt,
            expires_at: Some(claims.exp),
        })
    }
}

/// One audit line for a refused authentication: Debug-formatted fields (no log injection), never a credential.
fn audit_failure(client: &str, provider: &str, e: &AuthError, path: Option<&str>) {
    tracing::warn!(
        target: "audit",
        client = ?client,
        provider = ?provider,
        reason = e.reason_class(),
        path = ?path.unwrap_or("-"),
        "authentication refused"
    );
}
