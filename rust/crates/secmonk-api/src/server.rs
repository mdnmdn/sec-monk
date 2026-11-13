//! The server layer in front of the [`Router`]: authentication (API key to JWT exchange, Bearer / ApiKey
//! requests, scopes, rate limit, audit) and mount points for extra APIs (the node API under `/node/v1/`).
//!
//! Order of checks for a request: method, `Host` (the router's rules), `/auth/*`, then paths that need a caller
//! (`/api/*` and the mounts) authenticate when auth is on; everything else (the UI files) is public and goes to the
//! router as it is. With auth off (loopback) every request is served as before and mounts get `None` as principal.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use async_trait::async_trait;
use http::{Method, Request, Response, StatusCode, header};
use secmonk_auth::{AuthError, Authenticator, Principal, RequestContext, Scope};
use serde_json::{Value, json};

use crate::error::ApiError;
use crate::router::{MAX_BODY, Router, error_response, json_response};

/// Largest body of a mounted API request (`/node/v1/match/components` carries up to 1 000 components).
pub const MAX_MOUNT_BODY: usize = 4 * 1024 * 1024;
/// Largest body of `POST /auth/token`.
pub const MAX_TOKEN_BODY: usize = 4 * 1024;

/// An API served under a path prefix, behind the server's authentication.
///
/// The server authenticates the request first (a mount never sees an unauthenticated one when auth is on) and
/// applies the per-key rate limit; the mount does its own scope checks with the `principal` (`None` only when
/// auth is off). Requests need no `X-SecMonk-Request` header: mounts are not browser routes. The body is capped
/// at [`MAX_MOUNT_BODY`] before the mount is called. Build answers with [`json_response`] and [`error_response`].
#[async_trait]
pub trait Mount: Send + Sync {
    /// The path prefix, with both slashes (`"/node/v1/"`).
    fn prefix(&self) -> &'static str;

    /// Answer one authenticated request.
    async fn handle(
        &self,
        req: Request<Vec<u8>>,
        principal: Option<Principal>,
    ) -> Response<Vec<u8>>;
}

/// Router + authentication + mounts. Build it once, share it in an `Arc`, serve it with [`crate::serve`].
pub struct Server {
    router: Arc<Router>,
    auth: Option<Arc<Authenticator>>,
    mounts: Vec<Arc<dyn Mount>>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("auth", &self.auth.is_some())
            .field(
                "mounts",
                &self.mounts.iter().map(|m| m.prefix()).collect::<Vec<_>>(),
            )
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

    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    pub fn auth_enabled(&self) -> bool {
        self.auth.is_some()
    }

    /// The largest body the HTTP reader accepts for a request to `path` (checked before the body is read).
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

    /// Answer one request. `client` is the peer address (for the login throttle). Never panics on input.
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
        if let Some(rest) = path.strip_prefix("/auth/") {
            return match rest {
                "info" => self.auth_info(&method),
                "token" => self.auth_token(&req, &method, client),
                _ => error_response(&ApiError::not_found("not found")),
            };
        }
        let mount = self.mount_for(&path).cloned();
        let is_api = path.starts_with("/api/");
        if mount.is_none() && !is_api {
            return self.router.handle(req).await; // the UI files: public
        }
        let principal = match &self.auth {
            None => None,
            Some(auth) => match self.authenticate(auth, &req, client) {
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
                key = %p.key_id,
                provider = %p.provider,
                method = %method,
                path = %path,
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
                return error_response(
                    &ApiError::new(StatusCode::FORBIDDEN, "forbidden").with_hint(format!(
                        "the API key lacks the scope {need} (needed for {method} {path})"
                    )),
                );
            }
        }
        self.router.handle(req).await
    }

    /// The caller of a protected request, or the 401 / 429 answer.
    fn authenticate(
        &self,
        auth: &Authenticator,
        req: &Request<Vec<u8>>,
        client: Option<SocketAddr>,
    ) -> Result<Principal, AuthError> {
        let header = match req.headers().get(header::AUTHORIZATION) {
            None => None,
            Some(v) => match v.to_str() {
                Ok(v) => Some(v),
                Err(_) => return Err(AuthError::Malformed("bad Authorization header".into())),
            },
        };
        let ip = client.map(|a| a.ip().to_string());
        let ctx = RequestContext::new(header, ip.as_deref());
        let principal = auth.authenticate_request(&ctx, SystemTime::now())?;
        auth.check_rate(&principal, Instant::now())?;
        Ok(principal)
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

    fn auth_token(
        &self,
        req: &Request<Vec<u8>>,
        method: &Method,
        client: Option<SocketAddr>,
    ) -> Response<Vec<u8>> {
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
        let who = client.map_or_else(|| "unknown".to_owned(), |a| a.ip().to_string());
        match auth.login_from(
            &who,
            &method_name,
            &params,
            SystemTime::now(),
            Instant::now(),
        ) {
            Ok(t) => {
                tracing::info!(target: "audit", client = %who, method = %method_name, "token issued");
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
            Err(e) => {
                tracing::warn!(target: "audit", client = %who, method = %method_name, "token exchange refused");
                auth_failure(&e)
            }
        }
    }
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

/// 401 for every credential failure (the same body whatever the reason), 429 when throttled, 500 otherwise.
fn auth_failure(e: &AuthError) -> Response<Vec<u8>> {
    let mut r = match e {
        AuthError::RateLimited => {
            let mut r = error_response(&ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limited",
            ));
            r.headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("60"));
            return r;
        }
        e if e.is_credential_failure() || matches!(e, AuthError::Missing) => {
            let msg = if matches!(e, AuthError::Missing) {
                e.public_message()
            } else {
                "invalid credentials"
            };
            error_response(&ApiError::new(StatusCode::UNAUTHORIZED, msg))
        }
        AuthError::Forbidden(_) => {
            error_response(&ApiError::new(StatusCode::FORBIDDEN, "forbidden"))
        }
        _ => error_response(&ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error",
        )),
    };
    if r.status() == StatusCode::UNAUTHORIZED {
        r.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer"),
        );
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
