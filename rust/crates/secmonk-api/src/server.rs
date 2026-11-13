//! The server layer in front of the [`Router`]: authentication (API key to JWT exchange, Bearer / ApiKey
//! requests, scopes, rate limit, failed-authentication throttle, audit) and mount points for extra APIs (the node
//! API under `/node/v1/`).
//!
//! Order of checks for a request: method, `Host` (the router's rules), `/auth/*`, then paths that need a caller
//! (`/api/*` and the mounts) authenticate when auth is on; everything else (the UI files) is public and goes to the
//! router as it is. With auth off (loopback) `/api/*` is served as before, and **mounts answer 403**: a mount is
//! never reachable without a principal.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use async_trait::async_trait;
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use secmonk_auth::{AuthError, Authenticator, HeaderLookup, Principal, RequestContext, Scope};
use serde_json::{Value, json};

use crate::error::ApiError;
use crate::proxies::TrustedProxies;
use crate::router::{MAX_BODY, Router, error_response, json_response};

/// Largest body of a mounted API request (`/node/v1/match/components` carries up to 1 000 components).
pub const MAX_MOUNT_BODY: usize = 4 * 1024 * 1024;
/// Largest body of `POST /auth/token`.
pub const MAX_TOKEN_BODY: usize = 4 * 1024;
/// `Retry-After` (seconds) of a 429 (rate limit or throttle).
pub const RETRY_AFTER_S: &str = "60";
/// The 403 body of a mount route when authentication is off.
pub const MOUNT_NEEDS_AUTH: &str = "the node API needs authentication: enable [server] auth";

/// What a mount route requires of the caller, checked by the [`Server`] before the mount is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredScope {
    /// The principal must hold this scope (403 otherwise).
    Scope(Scope),
    /// Any authenticated principal.
    Authenticated,
}

/// An API served under a path prefix, behind the server's authentication.
///
/// The server authenticates the request first, applies the per-key rate limit and the scope that
/// [`Mount::required_scope`] names (401 / 403 / 429 before the mount is called), and caps the body at
/// [`MAX_MOUNT_BODY`]. A mount is **never** reached without a principal: with auth off its routes answer 403
/// ([`MOUNT_NEEDS_AUTH`]), so `handle` always gets `Some(principal)` (the `Option` stays for compatibility).
/// Requests need no `X-SecMonk-Request` header: mounts are not browser routes. Build answers with
/// [`json_response`] and [`error_response`].
#[async_trait]
pub trait Mount: Send + Sync {
    /// The path prefix, with both slashes (`"/node/v1/"`).
    fn prefix(&self) -> &'static str;

    /// The scope a request needs. `None` (a path that is not a route of the mount, a wrong method) and
    /// [`RequiredScope::Authenticated`] both mean "any principal": the mount then answers (404, 405, ...). The
    /// default asks only for authentication.
    fn required_scope(&self, method: &Method, path: &str) -> Option<RequiredScope> {
        let _ = (method, path);
        Some(RequiredScope::Authenticated)
    }

    /// Answer one authenticated request (`principal` is always `Some`).
    async fn handle(
        &self,
        req: Request<Vec<u8>>,
        principal: Option<Principal>,
    ) -> Response<Vec<u8>>;
}

/// [`HeaderLookup`] over an `http` header map (first value, valid text only).
struct Headers<'a>(&'a HeaderMap);

impl HeaderLookup for Headers<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.0.get(name).and_then(|v| v.to_str().ok())
    }
}

/// Router + authentication + mounts. Build it once, share it in an `Arc`, serve it with [`crate::serve`].
pub struct Server {
    router: Arc<Router>,
    auth: Option<Arc<Authenticator>>,
    mounts: Vec<Arc<dyn Mount>>,
    proxies: TrustedProxies,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("auth", &self.auth.is_some())
            .field(
                "mounts",
                &self.mounts.iter().map(|m| m.prefix()).collect::<Vec<_>>(),
            )
            .field("trusted_proxies", &self.proxies)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// A server with authentication off and no mounts (what the loopback bindings use).
    pub fn new(router: Arc<Router>) -> Self {
        Self {
            router,
            auth: None,
            mounts: Vec::new(),
            proxies: TrustedProxies::default(),
        }
    }

    /// Require an API key or token on `/api/*` and on the mounts.
    #[must_use]
    pub fn with_auth(mut self, auth: Arc<Authenticator>) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Mount an API under its prefix.
    #[must_use]
    pub fn with_mount(mut self, mount: Arc<dyn Mount>) -> Self {
        self.mounts.push(mount);
        self
    }

    /// Trust `X-Forwarded-For` from these peers (`[server] trusted_proxies`, parsed with
    /// [`TrustedProxies::parse`]): the client address of throttles and audit is then the right-most untrusted
    /// entry. Trusted proxies are also exempt from the per-address connection cap.
    #[must_use]
    pub fn with_trusted_proxies(mut self, proxies: TrustedProxies) -> Self {
        self.proxies = proxies;
        self
    }

    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    pub fn auth_enabled(&self) -> bool {
        self.auth.is_some()
    }

    /// The trusted proxies.
    pub fn trusted_proxies(&self) -> &TrustedProxies {
        &self.proxies
    }

    /// The largest body the HTTP reader accepts for a request to `path` (checked before the body is read; pass
    /// the path of the parsed request URI, the one the router sees).
    pub fn body_limit(&self, path: &str) -> usize {
        if path == "/auth/token" {
            MAX_TOKEN_BODY
        } else if self.mount_for(path).is_some() {
            MAX_MOUNT_BODY
        } else {
            MAX_BODY
        }
    }

    fn mount_for(&self, path: &str) -> Option<&Arc<dyn Mount>> {
        self.mounts.iter().find(|m| path.starts_with(m.prefix()))
    }

    /// The client address of a request from `peer`: the peer, or the forwarded client behind a trusted proxy.
    pub fn client_ip(&self, peer: Option<SocketAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        peer.map(|p| self.proxies.client_ip(p.ip(), headers))
    }

    /// Answer one request. `client` is the TCP peer address (throttles, audit; resolved through the trusted
    /// proxies). Never panics on input.
    pub async fn handle(
        &self,
        req: Request<Vec<u8>>,
        client: Option<SocketAddr>,
    ) -> Response<Vec<u8>> {
        let method = req.method().clone();
        if method != Method::GET && method != Method::POST {
            return self.router.handle(req).await; // 405, as before any other check
        }
        if let Err(e) = self.router.check_host(&req) {
            return error_response(&e);
        }
        let path = req.uri().path().to_owned();
        let ip = self
            .client_ip(client, req.headers())
            .map_or_else(|| "unknown".to_owned(), |a| a.to_string());
        if let Some(rest) = path.strip_prefix("/auth/") {
            return match rest {
                "info" => self.auth_info(&method),
                "token" => self.auth_token(&req, &method, &ip),
                _ => error_response(&ApiError::not_found("not found")),
            };
        }
        let mount = self.mount_for(&path).cloned();
        let is_api = path.starts_with("/api/");
        if mount.is_none() && !is_api {
            return self.router.handle(req).await; // the UI files: public
        }
        let principal = match &self.auth {
            None if mount.is_some() => {
                return error_response(&ApiError::new(StatusCode::FORBIDDEN, MOUNT_NEEDS_AUTH));
            }
            None => None,
            Some(auth) => match authenticate(auth, &req, &method, &path, &ip) {
                Ok(p) => Some(p),
                Err(e) => return auth_failure(&e),
            },
        };
        let response = self
            .dispatch(req, &method, &path, mount, principal.clone())
            .await;
        if let Some(p) = &principal {
            tracing::info!(
                target: "audit",
                key = ?p.subject,
                provider = ?p.provider,
                client = ?ip,
                method = %method,
                path = ?path,
                status = response.status().as_u16(),
                "request"
            );
        }
        response
    }

    async fn dispatch(
        &self,
        req: Request<Vec<u8>>,
        method: &Method,
        path: &str,
        mount: Option<Arc<dyn Mount>>,
        principal: Option<Principal>,
    ) -> Response<Vec<u8>> {
        if let Some(mount) = mount {
            let Some(p) = &principal else {
                // unreachable by construction (handle refuses mounts without auth); fail closed anyway
                return error_response(&ApiError::new(StatusCode::FORBIDDEN, MOUNT_NEEDS_AUTH));
            };
            if let Some(RequiredScope::Scope(need)) = mount.required_scope(method, path)
                && !p.scopes.contains(need)
            {
                return forbidden(need, method, path);
            }
            if body_too_large(&req, MAX_MOUNT_BODY) {
                return error_response(&too_large(MAX_MOUNT_BODY));
            }
            return mount.handle(req, principal).await;
        }
        if let Some(p) = &principal {
            let need = if method == Method::GET {
                Scope::UiRead
            } else {
                Scope::UiActions
            };
            if !p.scopes.contains(need) {
                return forbidden(need, method, path);
            }
        }
        self.router.handle(req).await
    }

    fn auth_info(&self, method: &Method) -> Response<Vec<u8>> {
        if method != Method::GET {
            return method_not_allowed();
        }
        let body = match &self.auth {
            None => json!({ "auth": false }),
            Some(a) => json!({
                "auth": true,
                "providers": a.provider_names(),
                "login_methods": a.login_methods(),
            }),
        };
        json_response(StatusCode::OK, &body)
    }

    fn auth_token(&self, req: &Request<Vec<u8>>, method: &Method, who: &str) -> Response<Vec<u8>> {
        if method != Method::POST {
            return method_not_allowed();
        }
        let Some(auth) = &self.auth else {
            return error_response(&ApiError::not_found("authentication is not enabled"));
        };
        if body_too_large(req, MAX_TOKEN_BODY) {
            return error_response(&too_large(MAX_TOKEN_BODY));
        }
        let (method_name, params) = match login_params(req) {
            Ok(k) => k,
            Err(e) => return error_response(&e),
        };
        // failures are audit-logged by the authenticator (client, provider, reason class)
        match auth.login_from(
            who,
            &method_name,
            &params,
            SystemTime::now(),
            Instant::now(),
        ) {
            Ok(t) => {
                tracing::info!(target: "audit", client = ?who, method = ?method_name, "token issued");
                json_response(
                    StatusCode::OK,
                    &json!({
                        "token": t.token,
                        "token_type": "Bearer",
                        "expires_at": t.expires_at,
                        "scopes": t.scopes.iter().map(|s| Value::from(s.as_str())).collect::<Vec<_>>(),
                    }),
                )
            }
            Err(e) => auth_failure(&e),
        }
    }
}

/// The caller of a protected request (throttled, audit-logged on failure, rate limited), or the error.
fn authenticate(
    auth: &Authenticator,
    req: &Request<Vec<u8>>,
    method: &Method,
    path: &str,
    client: &str,
) -> Result<Principal, AuthError> {
    let header = match req.headers().get(header::AUTHORIZATION) {
        None => None,
        Some(v) => match v.to_str() {
            Ok(v) => Some(v),
            Err(_) => return Err(AuthError::Malformed("bad Authorization header".into())),
        },
    };
    let headers = Headers(req.headers());
    let ctx = RequestContext::new(header, Some(client))
        .with_request(method.as_str(), path)
        .with_headers(&headers);
    let principal = auth.authenticate_from(&ctx, SystemTime::now(), Instant::now())?;
    auth.check_rate(&principal, Instant::now())?;
    Ok(principal)
}

fn forbidden(need: Scope, method: &Method, path: &str) -> Response<Vec<u8>> {
    error_response(
        &ApiError::new(StatusCode::FORBIDDEN, "forbidden").with_hint(format!(
            "the API key lacks the scope {need} (needed for {method} {path})"
        )),
    )
}

/// The login of `POST /auth/token`: `(method, params)` from a JSON body `{"method": "...", ...}` (`method`
/// defaults to `api_key`) or from `Authorization: ApiKey <key>`.
fn login_params(req: &Request<Vec<u8>>) -> Result<(String, Value), ApiError> {
    if let Some(h) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        && let Some((scheme, cred)) = h.trim().split_once(' ')
        && scheme.eq_ignore_ascii_case("apikey")
    {
        return Ok(("api_key".to_owned(), json!({ "api_key": cred.trim() })));
    }
    let bad = || {
        ApiError::bad_request(
            "expected a JSON object {\"method\": \"...\", ...} (or {\"api_key\": \"...\"}) or an Authorization: ApiKey header",
        )
    };
    let value: Value = serde_json::from_slice(req.body()).map_err(|_| bad())?;
    let Value::Object(obj) = &value else {
        return Err(bad());
    };
    let method = match obj.get("method") {
        None => "api_key".to_owned(),
        Some(Value::String(m)) => m.clone(),
        Some(_) => return Err(bad()),
    };
    Ok((method, value))
}

/// The answer to an authentication failure, by [`AuthError::http_status`]: 401 (the same body whatever the
/// reason, with the `Bearer` challenge), 403, 429 (with `Retry-After`), 503, 500.
fn auth_failure(e: &AuthError) -> Response<Vec<u8>> {
    let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut r = error_response(&ApiError::new(status, e.public_message()));
    match status {
        StatusCode::UNAUTHORIZED => {
            r.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer"),
            );
        }
        StatusCode::TOO_MANY_REQUESTS => {
            r.headers_mut().insert(
                header::RETRY_AFTER,
                header::HeaderValue::from_static(RETRY_AFTER_S),
            );
        }
        _ => {}
    }
    r
}

fn method_not_allowed() -> Response<Vec<u8>> {
    error_response(&ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed",
    ))
}

fn too_large(limit: usize) -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        format!("request body over {limit} bytes"),
    )
}

fn body_too_large(req: &Request<Vec<u8>>, limit: usize) -> bool {
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<usize>().ok());
    declared.is_some_and(|d| d > limit) || req.body().len() > limit
}
