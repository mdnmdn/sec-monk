//! [`RemoteNode`]: the three node services over HTTPS (`/node/v1`) with an API key exchanged for a JWT.
//!
//! The key is sent only to `POST {base}/auth/token`; the JWT is cached and renewed [`REFRESH_MARGIN`] before it
//! expires, or on a 401 (the call is then repeated once). Neither is ever logged or put in an error. Plain
//! `http://` is accepted for loopback hosts only. Redirects are never followed. Response bodies are read with a
//! limit ([`MAX_RESPONSE_BYTES`]). Calls with more than `MAX_COMPONENTS` components or `MAX_IDS` ids are split
//! and their answers merged.
//!
//! **Token lifetime.** The server sends `expires_at` (its clock) and no issue time, so the lifetime is measured on
//! the local monotonic clock from the moment the answer arrived: `expires_at - local now`, clamped by the JWT's own
//! `exp - iat` (its payload is decoded without verifying, for the timing only), so a client clock ahead of or
//! behind the server's neither renews forever nor keeps an expired token. **Single flight**: one exchange at a
//! time; callers that wait for it take its result, an error included (each of them gets the error; the next
//! call tries again).
//!
//! **Busy.** A 429 (or 503) with `Retry-After: <seconds>` is a `busy` error whose `data` is
//! `{"retry_after_s": n}` and whose hint names the delay; the client does not sleep on its own.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use http::Method;
use http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use secmonk_model::node::{
    ChangesRequest, ChangesResponse, FeedPage, FeedSinceRequest, FeedStatus, MAX_COMPONENTS,
    MAX_IDS, MatchComponentsRequest, MatchComponentsResponse, NodeInfo, SummariesRequest,
    SummariesResponse, VersionKind, Versions,
};
use secmonk_traits::node::{Feed, MatchService, VulnInfo};
use secmonk_traits::{ErrorCode, StepResult, WireError};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::wire::{CODE_UNAUTHORIZED, encode_query, wire_error_of_status};

/// Largest response body read (a feed page of 5 000 operations is a few MiB).
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
/// A token is renewed this long before it expires.
pub const REFRESH_MARGIN: Duration = Duration::from_secs(60);
/// Largest PEM file accepted as `ca_cert`.
const MAX_CA_BYTES: u64 = 1024 * 1024;
/// Error bodies are read up to this size.
const MAX_ERROR_BODY: usize = 64 * 1024;

/// How to reach a node.
#[derive(Clone)]
pub struct RemoteConfig {
    /// `https://host:port` (a path prefix is kept: a reverse proxy). `http://` only for a loopback host.
    pub base_url: String,
    /// The API key (`smk_...`) with the scopes the calls need.
    pub api_key: String,
    /// An extra PEM certificate to trust (a self-signed or private-CA node).
    pub ca_cert: Option<PathBuf>,
    /// Connect timeout and total timeout of one request.
    pub timeout: Duration,
}

impl std::fmt::Debug for RemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"***")
            .field("ca_cert", &self.ca_cert)
            .field("timeout", &self.timeout)
            .finish()
    }
}

struct Token {
    value: String,
    /// When it expires, on the local monotonic clock.
    deadline: Instant,
}

/// The token cache and the outcome of the last exchange (single flight, see the module doc).
#[derive(Default)]
struct TokenState {
    token: Option<Token>,
    /// Exchanges finished (with any outcome).
    attempts: u64,
    /// The error of the last exchange, when it failed (handed to the callers that waited for it).
    last_error: Option<WireError>,
}

/// The lifetime of a token received at local unix time `now_local`: `expires_at - now_local`, clamped by the JWT's
/// own `exp - iat` when its payload says (a client clock off the server's must not stretch it).
fn token_lifetime(expires_at: u64, now_local: u64, jwt: &str) -> Duration {
    let by_server = expires_at.saturating_sub(now_local);
    let by_claims = jwt_claims_lifetime(jwt);
    Duration::from_secs(by_claims.map_or(by_server, |c| by_server.min(c)))
}

/// `exp - iat` of a JWT's payload, decoded **without verifying** (only the timing is read; the server verifies).
fn jwt_claims_lifetime(jwt: &str) -> Option<u64> {
    use base64::Engine as _;
    let payload = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    let exp = v.get("exp")?.as_u64()?;
    let iat = v.get("iat")?.as_u64()?;
    exp.checked_sub(iat)
}

/// `Retry-After` in seconds (the delta-seconds form; an HTTP date is ignored).
fn retry_after_secs(h: Option<&HeaderValue>) -> Option<u64> {
    h?.to_str().ok()?.trim().parse().ok()
}

/// A `busy` error carrying the delay the node asked for.
fn busy_after(mut e: WireError, secs: u64) -> WireError {
    e.code = ErrorCode::Busy;
    e.hint = Some(format!("the node asks to retry after {secs} s"));
    e.data = Some(Box::new(json!({"retry_after_s": secs})));
    e
}

/// A remote node: [`MatchService`], [`VulnInfo`] and [`Feed`] over HTTPS.
pub struct RemoteNode {
    base: String,
    api_key: String,
    client: reqwest::Client,
    /// The cached token and the last exchange's outcome (a short lock, never held across a request).
    token: std::sync::Mutex<TokenState>,
    /// Held for the duration of one exchange: the single flight.
    exchange_lock: Mutex<()>,
    margin: Duration,
    exchanges: AtomicU64,
}

impl std::fmt::Debug for RemoteNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteNode")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

/// The text of a transport error with its causes (a certificate refusal is a cause, not the top message); no URL.
fn transport_text(e: reqwest::Error) -> (String, bool) {
    let timeout = e.is_timeout();
    let e = e.without_url();
    let mut text = e.to_string();
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
    while let Some(s) = src {
        text.push_str(": ");
        text.push_str(&s.to_string());
        src = s.source();
    }
    (text, timeout)
}

fn transport_error(e: reqwest::Error, what: &str) -> WireError {
    let (text, timeout) = transport_text(e);
    WireError::new(
        if timeout {
            ErrorCode::Timeout
        } else {
            ErrorCode::HostUnreachable
        },
        format!("{what}: {text}"),
    )
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    h.eq_ignore_ascii_case("localhost")
        || h.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl RemoteNode {
    /// A client for `cfg`. Refuses a malformed or credential-carrying URL, plain HTTP to a non-loopback host and an
    /// unreadable `ca_cert`; connects to nothing yet.
    pub fn new(cfg: RemoteConfig) -> StepResult<RemoteNode> {
        let uri: http::Uri = cfg
            .base_url
            .parse()
            .map_err(|_| WireError::invalid_params("node.upstream.url: not a URL"))?;
        let scheme = uri.scheme_str().unwrap_or("");
        let authority = uri
            .authority()
            .ok_or_else(|| WireError::invalid_params("node.upstream.url: no host"))?;
        if authority.as_str().contains('@') {
            return Err(WireError::invalid_params(
                "node.upstream.url: credentials in the URL are not accepted (use the API key setting)",
            ));
        }
        match scheme {
            "https" => {}
            "http" if is_loopback_host(authority.host()) => {}
            "http" => {
                return Err(WireError::invalid_params(
                    "node.upstream.url: plain http is accepted for loopback hosts only; use https",
                ));
            }
            _ => {
                return Err(WireError::invalid_params(
                    "node.upstream.url: expected an https:// URL",
                ));
            }
        }
        if cfg.api_key.trim().is_empty() {
            return Err(WireError::invalid_params("node.upstream: no API key"));
        }
        let mut b = reqwest::Client::builder()
            .user_agent(concat!("secmonk-node/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(cfg.timeout)
            .timeout(cfg.timeout);
        if let Some(path) = &cfg.ca_cert {
            let len = std::fs::metadata(path)
                .map_err(|e| {
                    WireError::invalid_params(format!(
                        "node.upstream.ca_cert {}: {e}",
                        path.display()
                    ))
                })?
                .len();
            if len > MAX_CA_BYTES {
                return Err(WireError::invalid_params(format!(
                    "node.upstream.ca_cert {}: file too large",
                    path.display()
                )));
            }
            let pem = std::fs::read(path).map_err(|e| {
                WireError::invalid_params(format!("node.upstream.ca_cert {}: {e}", path.display()))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
                WireError::invalid_params(format!(
                    "node.upstream.ca_cert {}: not a PEM certificate ({})",
                    path.display(),
                    e.without_url()
                ))
            })?;
            b = b.add_root_certificate(cert);
        }
        let client = b
            .build()
            .map_err(|e| WireError::internal("ClientError", e.without_url()))?;
        Ok(RemoteNode {
            base: cfg.base_url.trim_end_matches('/').to_owned(),
            api_key: cfg.api_key,
            client,
            token: std::sync::Mutex::new(TokenState::default()),
            exchange_lock: Mutex::new(()),
            margin: REFRESH_MARGIN,
            exchanges: AtomicU64::new(0),
        })
    }

    /// Renew tokens this long before they expire (default [`REFRESH_MARGIN`]; tests use a short one).
    #[must_use]
    pub fn with_refresh_margin(mut self, margin: Duration) -> RemoteNode {
        self.margin = margin;
        self
    }

    /// How many API-key-for-token exchanges this client has made (diagnostics, tests).
    pub fn token_exchanges(&self) -> u64 {
        self.exchanges.load(Ordering::Relaxed)
    }

    /// `GET /node/v1/info`: what the node is and offers.
    pub async fn info(&self) -> StepResult<NodeInfo> {
        self.get("info", &[]).await
    }

    // -------------------------------------------------------------------------------------------------------
    // auth

    fn state(&self) -> std::sync::MutexGuard<'_, TokenState> {
        self.token.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The cached token when it is valid for longer than the margin.
    fn cached(&self) -> Option<String> {
        let st = self.state();
        st.token
            .as_ref()
            .filter(|t| Instant::now() + self.margin < t.deadline)
            .map(|t| t.value.clone())
    }

    /// A valid token: the cached one, or the result of one exchange shared by every caller waiting for it.
    async fn token(&self) -> StepResult<String> {
        if let Some(t) = self.cached() {
            return Ok(t);
        }
        let seen = self.state().attempts;
        let _flight = self.exchange_lock.lock().await;
        {
            let st = self.state();
            // another caller exchanged while this one waited: take its outcome
            if st.attempts != seen {
                if let Some(e) = &st.last_error {
                    return Err(e.clone());
                }
                if let Some(t) = &st.token {
                    return Ok(t.value.clone());
                }
            }
        }
        if let Some(t) = self.cached() {
            return Ok(t);
        }
        let result = self.exchange().await;
        let mut st = self.state();
        st.attempts += 1;
        match result {
            Ok(t) => {
                let value = t.value.clone();
                st.token = Some(t);
                st.last_error = None;
                Ok(value)
            }
            Err(e) => {
                st.token = None;
                st.last_error = Some(e.clone());
                Err(e)
            }
        }
    }

    /// Forget `used` (only when it is still the cached one: another call may have renewed it already).
    fn invalidate(&self, used: &str) {
        let mut st = self.state();
        if st.token.as_ref().is_some_and(|t| t.value == used) {
            st.token = None;
        }
    }

    async fn exchange(&self) -> StepResult<Token> {
        self.exchanges.fetch_add(1, Ordering::Relaxed);
        let body = serde_json::to_vec(&json!({"method": "api_key", "api_key": self.api_key}))
            .map_err(|e| WireError::internal("EncodeError", e))?;
        let resp = self
            .client
            .post(format!("{}/auth/token", self.base))
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| transport_error(e, "token exchange"))?;
        let status = resp.status().as_u16();
        let retry_after = retry_after_secs(resp.headers().get(RETRY_AFTER));
        let bytes = read_limited(resp, MAX_ERROR_BODY).await?;
        let received = now_s();
        let arrived = Instant::now();
        if status != 200 {
            if matches!(status, 429 | 503)
                && let Some(secs) = retry_after
            {
                return Err(busy_after(wire_error_of_status(status, &bytes), secs));
            }
            let mut e = wire_error_of_status(status, &bytes);
            if status == 401 {
                e = WireError::new(
                    ErrorCode::Other(CODE_UNAUTHORIZED.into()),
                    "the node refused the API key",
                );
            } else if status == 404 {
                e = WireError::new(
                    ErrorCode::Other(crate::wire::CODE_NOT_FOUND.into()),
                    "the node has authentication off (no /auth/token); it does not need a key",
                );
            }
            return Err(e);
        }
        let v: Value = serde_json::from_slice(&bytes)
            .map_err(|_| WireError::internal("ProtocolError", "unreadable token response"))?;
        let value = v
            .get("token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| WireError::internal("ProtocolError", "token response without a token"))?
            .to_owned();
        let expires_at = v.get("expires_at").and_then(Value::as_u64).ok_or_else(|| {
            WireError::internal("ProtocolError", "token response without expires_at")
        })?;
        let lifetime = token_lifetime(expires_at, received, &value);
        Ok(Token {
            value,
            deadline: arrived + lifetime,
        })
    }

    // -------------------------------------------------------------------------------------------------------
    // calls

    async fn send_once(
        &self,
        method: &Method,
        url: &str,
        body: Option<&[u8]>,
        token: &str,
    ) -> StepResult<(u16, Vec<u8>, Option<u64>)> {
        let mut auth = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| WireError::internal("ProtocolError", "the token is not a header value"))?;
        auth.set_sensitive(true);
        let mut req = self
            .client
            .request(method.clone(), url)
            .header(AUTHORIZATION, auth);
        if let Some(b) = body {
            req = req
                .header(CONTENT_TYPE, "application/json")
                .body(b.to_vec());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| transport_error(e, "node request"))?;
        let status = resp.status().as_u16();
        let retry_after = retry_after_secs(resp.headers().get(RETRY_AFTER));
        let limit = if status == 200 {
            MAX_RESPONSE_BYTES
        } else {
            MAX_ERROR_BODY
        };
        let bytes = read_limited(resp, limit).await?;
        Ok((status, bytes, retry_after))
    }

    /// One call with the token handling: a 401 renews the token and repeats the call once.
    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<Vec<u8>>,
    ) -> StepResult<T> {
        let mut url = format!("{}/node/v1/{path}", self.base);
        if !query.is_empty() {
            url.push('?');
            url.push_str(&encode_query(query));
        }
        let mut renewed = false;
        loop {
            let token = self.token().await?;
            let (status, bytes, retry_after) = self
                .send_once(&method, &url, body.as_deref(), &token)
                .await?;
            if status == 401 && !renewed {
                renewed = true;
                self.invalidate(&token);
                continue;
            }
            if matches!(status, 429 | 503)
                && let Some(secs) = retry_after
            {
                return Err(busy_after(wire_error_of_status(status, &bytes), secs));
            }
            if status != 200 {
                return Err(wire_error_of_status(status, &bytes));
            }
            return serde_json::from_slice(&bytes).map_err(|e| {
                WireError::internal(
                    "ProtocolError",
                    format!("unexpected response of {path}: {e}"),
                )
            });
        }
    }

    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(String, String)],
    ) -> StepResult<T> {
        self.call(Method::GET, path, query, None).await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> StepResult<T> {
        let bytes = serde_json::to_vec(body).map_err(|e| WireError::internal("EncodeError", e))?;
        self.call(Method::POST, path, &[], Some(bytes)).await
    }
}

/// Read a response body, refusing more than `limit` bytes (declared or actual).
async fn read_limited(mut resp: reqwest::Response, limit: usize) -> StepResult<Vec<u8>> {
    let too_big = || {
        WireError::new(
            ErrorCode::Internal,
            format!("the node's response is over {limit} bytes; refused"),
        )
    };
    if resp
        .content_length()
        .is_some_and(|n| usize::try_from(n).map_or(true, |n| n > limit))
    {
        return Err(too_big());
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| transport_error(e, "reading the node's response"))?
    {
        if out.len() + chunk.len() > limit {
            return Err(too_big());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn q(name: &str, value: impl Into<String>) -> (String, String) {
    (name.to_owned(), value.into())
}

fn union_sorted(a: Vec<String>, b: Vec<String>) -> Vec<String> {
    a.into_iter()
        .chain(b)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[async_trait]
impl MatchService for RemoteNode {
    async fn match_components(
        &self,
        req: MatchComponentsRequest,
    ) -> StepResult<MatchComponentsResponse> {
        let MatchComponentsRequest {
            components,
            min_confidence,
        } = req;
        let mut merged: Option<MatchComponentsResponse> = None;
        let mut it = components.chunks(MAX_COMPONENTS);
        // an empty request is still one call (the answer carries the versions and the coverage)
        let first = it.next().unwrap_or(&[]);
        let chunks = std::iter::once(first).chain(it);
        for chunk in chunks {
            let body = json!({"components": chunk, "min_confidence": min_confidence});
            let body = strip_null(body);
            let r: MatchComponentsResponse = self.post("match/components", &body).await?;
            if let Some(res) = r
                .results
                .iter()
                .find(|res| res.matches.iter().any(|m| m.vuln_id.is_empty()))
            {
                return Err(WireError::internal(
                    "ProtocolError",
                    format!(
                        "match/components: a match without a vuln_id for {:?}",
                        res.key.chars().take(200).collect::<String>()
                    ),
                ));
            }
            match &mut merged {
                None => merged = Some(r),
                Some(m) => {
                    // the answer is stamped with the OLDEST version of each source over the chunks (a source that
                    // moved between two chunks: some answers are older, and a stamp must never claim newer data
                    // than every answer has). Record versions (timestamps) compare as text; a snapshot version
                    // (a label) that differs keeps the first chunk's, the one asked first. The matcher stays the
                    // first chunk's: a change shows in the next `match.changes`.
                    for (name, v) in r.as_of.sources {
                        match m.as_of.sources.get_mut(&name) {
                            None => {
                                m.as_of.sources.insert(name, v);
                            }
                            Some(cur) => {
                                let older = match (&cur.version, &v.version) {
                                    (_, None) => true,
                                    (None, Some(_)) => false,
                                    (Some(a), Some(b)) => v.kind == VersionKind::Record && b < a,
                                };
                                if older {
                                    *cur = v;
                                }
                            }
                        }
                    }
                    m.results.extend(r.results);
                    m.coverage.sources =
                        union_sorted(std::mem::take(&mut m.coverage.sources), r.coverage.sources);
                    m.coverage.ecosystems = union_sorted(
                        std::mem::take(&mut m.coverage.ecosystems),
                        r.coverage.ecosystems,
                    );
                }
            }
        }
        merged.ok_or_else(|| WireError::internal("ProtocolError", "no answer"))
    }

    async fn changes(&self, req: ChangesRequest) -> StepResult<ChangesResponse> {
        self.post("match/changes", &req).await
    }

    async fn versions(&self) -> StepResult<Versions> {
        let info = self.info().await?;
        Ok(Versions::new(&info.matcher, info.sources))
    }
}

fn strip_null(mut v: Value) -> Value {
    if let Value::Object(m) = &mut v {
        m.retain(|_, x| !x.is_null());
    }
    v
}

#[async_trait]
impl VulnInfo for RemoteNode {
    async fn summaries(&self, ids: &[String]) -> StepResult<SummariesResponse> {
        let mut out = SummariesResponse {
            summaries: Vec::new(),
            missing: Vec::new(),
        };
        for chunk in ids.chunks(MAX_IDS) {
            let r: SummariesResponse = self
                .post(
                    "vulninfo/summaries",
                    &SummariesRequest {
                        ids: chunk.to_vec(),
                    },
                )
                .await?;
            out.summaries.extend(r.summaries);
            out.missing.extend(r.missing);
        }
        Ok(out)
    }

    async fn detail(&self, id: &str, raw: bool) -> StepResult<Value> {
        let mut query = vec![q("id", id)];
        if raw {
            query.push(q("raw", "1"));
        }
        self.get("vulninfo/detail", &query).await
    }

    async fn search(&self, params: Value) -> StepResult<Value> {
        let Value::Object(obj) = params else {
            return Err(WireError::invalid_params(
                "search: the parameters are a JSON object",
            ));
        };
        let mut query = Vec::new();
        for (k, v) in &obj {
            let scalar = |v: &Value| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                Value::Bool(b) => Some(b.to_string()),
                _ => None,
            };
            match v {
                Value::Null => {}
                Value::Array(items) => {
                    for i in items {
                        let s = scalar(i).ok_or_else(|| {
                            WireError::invalid_params(format!("search: {k}: expected scalars"))
                        })?;
                        query.push(q(k, s));
                    }
                }
                other => {
                    let s = scalar(other).ok_or_else(|| {
                        WireError::invalid_params(format!("search: {k}: expected a scalar"))
                    })?;
                    query.push(q(k, s));
                }
            }
        }
        self.get("vulninfo/search", &query).await
    }
}

#[async_trait]
impl Feed for RemoteNode {
    async fn status(&self) -> StepResult<FeedStatus> {
        self.get("feed/status", &[]).await
    }

    async fn since(&self, req: FeedSinceRequest) -> StepResult<FeedPage> {
        let mut query = vec![q("source", req.source)];
        if let Some(s) = req.since {
            query.push(q("since", s));
        }
        if let Some(p) = req.page {
            query.push(q("page", p));
        }
        if let Some(l) = req.limit {
            query.push(q("limit", l.to_string()));
        }
        self.get("feed/since", &query).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(url: &str) -> RemoteConfig {
        RemoteConfig {
            base_url: url.into(),
            api_key: "smk_00000000_x".into(),
            ca_cert: None,
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn urls_are_checked() {
        assert!(RemoteNode::new(cfg("https://mirror.example:8765")).is_ok());
        assert!(RemoteNode::new(cfg("http://127.0.0.1:8765")).is_ok());
        assert!(RemoteNode::new(cfg("http://localhost:8765")).is_ok());
        assert!(RemoteNode::new(cfg("http://[::1]:8765")).is_ok());
        for bad in [
            "http://mirror.example",
            "ftp://mirror.example",
            "https://user:pw@mirror.example",
            "mirror.example",
            "",
        ] {
            assert!(RemoteNode::new(cfg(bad)).is_err(), "{bad}");
        }
        let mut c = cfg("https://m.example");
        c.api_key = " ".into();
        assert!(RemoteNode::new(c).is_err());
        let mut c = cfg("https://m.example");
        c.ca_cert = Some("/nonexistent/ca.pem".into());
        assert!(RemoteNode::new(c).is_err());
    }

    #[test]
    fn debug_never_shows_the_key() {
        let c = cfg("https://m.example");
        assert!(!format!("{c:?}").contains("smk_"));
        let n = RemoteNode::new(c).unwrap();
        assert!(!format!("{n:?}").contains("smk_"));
    }
}
