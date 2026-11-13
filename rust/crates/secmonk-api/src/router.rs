//! The router: one async function from an HTTP request to an HTTP response, shared by the Tauri scheme handler
//! and the dev HTTP binding. Order of checks as `web/server.py`: method, Host, `/api` header, route, params.

use std::sync::Arc;

use http::{Method, Request, Response, StatusCode, header};
use secmonk_engine::{
    DiscoverQuery, DockerListQuery, EngineService, FindingsQuery, JobKind, JobsQuery, JsonObject,
    VulnSearchQuery,
};
use serde_json::Value;

use crate::error::{ApiError, discover_error, docker_error, kubeconfigs_error};
use crate::host::HostPolicy;
use crate::overlay;
use crate::policy;
use crate::query::Query;
use crate::routes::{Capture, RouteId, lookup};
use crate::static_files::{Refused, StaticDir};

/// `web/server.py` `CSP`, byte for byte.
pub const CSP: &str = "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self'; img-src 'self' data:; \
connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'";
pub const CSRF_HEADER: &str = "x-secmonk-request";
/// Largest POST body (`MAX_BODY`).
pub const MAX_BODY: usize = 64 * 1024;
/// Largest `limit` of the jobs list (`LIST_MAX`).
const JOBS_LIST_MAX: u32 = 200;
/// `ui_limit` bounds of `web/data.py`.
const MAX_LIMIT: u32 = 5000;
const PRIORITIES: [&str; 4] = ["P1", "P2", "P3", "P4"];

#[derive(Debug, Clone)]
pub struct RouterOptions {
    pub static_dir: StaticDir,
    pub host_policy: HostPolicy,
    /// Scans, syncs, discovery and docker listings (always on in the desktop window).
    pub actions: bool,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("opts", &self.opts)
            .finish_non_exhaustive()
    }
}

pub struct Router {
    engine: Arc<dyn EngineService>,
    opts: RouterOptions,
}

type ApiResult<T> = Result<T, ApiError>;

impl Router {
    pub fn new(engine: Arc<dyn EngineService>, opts: RouterOptions) -> Self {
        Self { engine, opts }
    }

    pub fn options(&self) -> &RouterOptions {
        &self.opts
    }

    /// Answer one request. Never panics on input; every response carries the security headers.
    pub async fn handle(&self, req: Request<Vec<u8>>) -> Response<Vec<u8>> {
        match self.dispatch(&req).await {
            Ok(r) => r,
            Err(e) => error_response(&e),
        }
    }

    async fn dispatch(&self, req: &Request<Vec<u8>>) -> ApiResult<Response<Vec<u8>>> {
        let method = req.method();
        if method != Method::GET && method != Method::POST {
            // `do_PUT` / `do_DELETE` / `do_PATCH`: before any other check.
            return Err(ApiError::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }
        self.check_host(req)?;
        let path = req.uri().path();
        let is_api = path.starts_with("/api/");
        if *method == Method::POST && !is_api {
            return Err(ApiError::not_found("not found"));
        }
        if is_api && header_str(req, CSRF_HEADER) != Some("1") {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "missing X-SecMonk-Request header",
            ));
        }
        if !is_api {
            return self.static_response(path);
        }
        let query = Query::parse(req.uri().query());
        let Some((route, capture)) = lookup(method, path) else {
            return Err(ApiError::not_found(format!("no such endpoint {path}")));
        };
        if route.id == RouteId::JobStart {
            // Body checks come first (`self._body()` is evaluated before `jobs.start`).
            let body = json_body(req)?;
            self.require_actions()?;
            policy::check_scan_body(&body)?;
            let v = self.engine.job_start(body).await?;
            return Ok(json_response(StatusCode::ACCEPTED, &v));
        }
        if route.actions {
            self.require_actions()?;
        }
        self.call(route.id, capture, &query).await
    }

    /// The authority must name this server (`_host_ok`). Both the URI authority and a `Host` header are checked
    /// when present; one of them must exist.
    pub fn check_host(&self, req: &Request<Vec<u8>>) -> ApiResult<()> {
        let from_uri = req.uri().authority().map(|a| a.as_str());
        let from_header = header_str(req, "host");
        let ok = (from_uri.is_some() || from_header.is_some())
            && from_uri.is_none_or(|a| self.opts.host_policy.allows(a))
            && from_header.is_none_or(|h| self.opts.host_policy.allows(h));
        if ok {
            return Ok(());
        }
        Err(ApiError::new(StatusCode::MISDIRECTED_REQUEST, "unexpected Host header").with_hint(
            "the UI only answers on the address it listens on (add names with `secmonk ui --allow-host`)",
        ))
    }

    fn require_actions(&self) -> ApiResult<()> {
        if self.opts.actions {
            return Ok(());
        }
        Err(ApiError::new(StatusCode::FORBIDDEN, "actions are disabled on this server").with_hint(
            "The UI listens on a non-loopback address: start it with --allow-actions to run scans, syncs and \
             docker queries from the browser.",
        ))
    }

    fn static_response(&self, path: &str) -> ApiResult<Response<Vec<u8>>> {
        // the overlay page replaces static_dir/index.html (same scripts plus the transport)
        let overlay_index = || {
            Ok(response(
                StatusCode::OK,
                "text/html; charset=utf-8",
                overlay::INDEX_HTML.as_bytes().to_vec(),
                true,
                &[],
            ))
        };
        let rel = if path == "/" || path == "/index.html" {
            return overlay_index();
        } else if let Some(rest) = path.strip_prefix("/static/") {
            rest
        } else if let Some(name) = path.strip_prefix("/rust-ui/") {
            return match overlay::file(name) {
                Some((ct, body)) => Ok(response(
                    StatusCode::OK,
                    ct,
                    body.as_bytes().to_vec(),
                    true,
                    &[],
                )),
                None => Err(ApiError::not_found("not found")),
            };
        } else if looks_like_page(path) {
            // History-mode deep link (the UI uses hash routing, the fallback is harmless).
            return overlay_index();
        } else {
            return Err(ApiError::not_found("not found"));
        };
        match self.opts.static_dir.read(rel) {
            Ok(f) => Ok(response(StatusCode::OK, f.content_type, f.body, true, &[])),
            Err(Refused::Unreadable) => Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "cannot read file",
            )),
            Err(_) => Err(ApiError::not_found("not found")),
        }
    }

    async fn call(&self, id: RouteId, capture: Capture, q: &Query) -> ApiResult<Response<Vec<u8>>> {
        let e = &self.engine;
        let ok = |v: Value| Ok(json_response(StatusCode::OK, &v));
        match id {
            RouteId::Meta => {
                let mut v = e.meta().await?;
                if let Some(o) = v.as_object_mut() {
                    // transport facts belong to the router
                    o.insert(
                        "bind".into(),
                        Value::String(self.opts.host_policy.bind_label()),
                    );
                    o.insert("actions".into(), Value::Bool(self.opts.actions));
                }
                ok(v)
            }
            RouteId::Processes => ok(e.processes(q.all("refresh") == ["1"]).await?),
            RouteId::ProcessesWatch => ok(e.processes_watch().await?),
            RouteId::ProcessesSave => ok(e.processes_save().await?),
            RouteId::Overview => ok(e.overview().await?),
            RouteId::Assets => ok(e.assets().await?),
            RouteId::AssetDetail => {
                let aid = required(q, "id")?;
                ok(
                    e.asset_detail(&aid, q.int("limit", MAX_LIMIT, 1, MAX_LIMIT)?)
                        .await?,
                )
            }
            RouteId::Sbom => {
                let Capture::Asset(aid) = capture else {
                    unreachable!("sbom captures an asset id")
                };
                if aid.is_empty() {
                    return Err(ApiError::not_found("no such endpoint /api/assets//sbom"));
                }
                let doc = e.sbom(&aid, q.flag("vulns")).await?;
                let name = sbom_filename(&aid);
                let body = serde_json::to_vec(&doc).unwrap_or_default();
                Ok(response(
                    StatusCode::OK,
                    "application/vnd.cyclonedx+json; charset=utf-8",
                    body,
                    false,
                    &[(
                        "Content-Disposition",
                        format!("attachment; filename=\"{name}.cdx.json\""),
                    )],
                ))
            }
            RouteId::MatchAsset => ok(e.match_asset(&required(q, "id")?).await?),
            RouteId::Unmatched => ok(e.unmatched().await?),
            RouteId::Findings => ok(e.findings(&findings_query(q)?).await?),
            RouteId::VulnShow => ok(e.vuln_show(&required(q, "id")?, q.flag("raw")).await?),
            RouteId::VulnSearch => ok(e.vuln_search(&vuln_search_query(q)?).await?),
            RouteId::Sources => ok(e.sources().await?),
            RouteId::Collectors => ok(e.collectors().await?),
            RouteId::JobsList => ok(e.jobs_list(&jobs_query(q)?).await?),
            RouteId::JobGet => {
                let Capture::Job(digits) = capture else {
                    unreachable!("jobs/<id> captures digits")
                };
                match digits.parse::<u64>() {
                    Ok(n) => ok(e.job_get(n).await?),
                    Err(_) => Err(ApiError::not_found(format!(
                        "no job {}",
                        digits.trim_start_matches('0')
                    ))),
                }
            }
            RouteId::Discover => {
                let query = DiscoverQuery {
                    target: q.one("target"),
                    options: q.options("opt"),
                };
                policy::check_discover_opts(&query.options)?;
                match e.discover(&query).await {
                    Ok(v) => ok(v),
                    Err(err) => Err(discover_error(err, query.target.as_deref())),
                }
            }
            RouteId::K8sKubeconfigs => match e.k8s_kubeconfigs().await {
                Ok(v) => ok(v),
                Err(err) => Err(kubeconfigs_error(err)),
            },
            RouteId::DockerContexts => match e.docker_contexts().await {
                Ok(v) => ok(v),
                Err(err) => Err(docker_error(err)),
            },
            RouteId::DockerContainers => {
                let query = DockerListQuery {
                    host: q.one("host"),
                    context: q.one("context"),
                    all: q.flag("all"),
                    selector: q.one("match"),
                    options: q.options("opt"),
                };
                policy::check_docker_opts(&query.options)?;
                match e.docker_containers(&query).await {
                    Ok(v) => ok(v),
                    Err(err) => Err(docker_error(err)),
                }
            }
            RouteId::JobStart => unreachable!("handled before the call table"),
        }
    }
}

fn required(q: &Query, name: &str) -> ApiResult<String> {
    q.one(name)
        .ok_or_else(|| ApiError::bad_request(format!("{name}: required")))
}

fn findings_query(q: &Query) -> ApiResult<FindingsQuery> {
    let limit = q.int("limit", 200, 1, MAX_LIMIT)?;
    let priority = match q.one("priority") {
        None => None,
        Some(p) if PRIORITIES.contains(&p.to_uppercase().as_str()) => Some(p.to_uppercase()),
        Some(_) => {
            return Err(ApiError::bad_request(format!(
                "priority: expected one of {}",
                PRIORITIES.join(", ")
            )));
        }
    };
    Ok(FindingsQuery {
        priority,
        asset: q.one("asset"),
        include_closed: q.flag("all"),
        fixable: q.flag("fixable"),
        hide_minor: q.flag("hide_minor"),
        hide_deferred: q.flag("hide_deferred"),
        limit,
    })
}

fn vuln_search_query(q: &Query) -> ApiResult<VulnSearchQuery> {
    Ok(VulnSearchQuery {
        limit: q.int("limit", 50, 1, 1000)?,
        package: q.one("package"),
        ecosystem: q.one("ecosystem"),
        product: q.one("product"),
        version: q.one("version"),
    })
}

fn jobs_query(q: &Query) -> ApiResult<JobsQuery> {
    let limit = q.int("limit", 50, 1, JOBS_LIST_MAX)?;
    let kind = match q.one("kind").as_deref() {
        None => None,
        Some("scan") => Some(JobKind::Scan),
        Some("sync") => Some(JobKind::Sync),
        Some(_) => return Err(ApiError::bad_request("kind: expected 'scan' or 'sync'")),
    };
    Ok(JobsQuery { kind, limit })
}

/// `GET`s that are not files: no extension in the last segment.
fn looks_like_page(path: &str) -> bool {
    !path.rsplit('/').next().unwrap_or("").contains('.')
}

/// `re.sub(r"[^A-Za-z0-9._-]+", "_", id).strip("_")[:80] or "asset"`.
fn sbom_filename(id: &str) -> String {
    let mut out = String::new();
    let mut in_run = false;
    for c in id.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    let trimmed: String = out.trim_matches('_').chars().take(80).collect();
    if trimmed.is_empty() {
        "asset".into()
    } else {
        trimmed
    }
}

/// `POST /api/jobs` body: `application/json`, at most `MAX_BODY` bytes, a JSON object.
fn json_body(req: &Request<Vec<u8>>) -> ApiResult<JsonObject> {
    let ctype = header_str(req, "content-type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if ctype != "application/json" {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected Content-Type: application/json",
        ));
    }
    let declared = match header_str(req, "content-length") {
        None => req.body().len(),
        Some(v) => v
            .trim()
            .parse::<usize>()
            .map_err(|_| ApiError::bad_request("bad Content-Length"))?,
    };
    if declared > MAX_BODY || req.body().len() > MAX_BODY {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body over {MAX_BODY} bytes"),
        ));
    }
    let bytes = &req.body()[..declared.min(req.body().len())];
    let value: Value = if bytes.is_empty() {
        Value::Object(JsonObject::new())
    } else {
        serde_json::from_slice(bytes)
            .map_err(|_| ApiError::bad_request("request body is not valid JSON"))?
    };
    match value {
        Value::Object(o) => Ok(o),
        _ => Err(ApiError::bad_request("request body must be a JSON object")),
    }
}

fn header_str<'a>(req: &'a Request<Vec<u8>>, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

/// Build a response with the security headers on every answer (`Handler._headers`).
pub fn response(
    status: StatusCode,
    content_type: &str,
    body: Vec<u8>,
    cache: bool,
    extra: &[(&str, String)],
) -> Response<Vec<u8>> {
    let mut b = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, body.len())
        .header(header::CONTENT_SECURITY_POLICY, CSP)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header("Cross-Origin-Opener-Policy", "same-origin")
        .header(
            header::CACHE_CONTROL,
            if cache { "no-cache" } else { "no-store" },
        );
    for (k, v) in extra {
        b = b.header(*k, v.as_str());
    }
    b.body(body)
        .expect("static header names and values are valid")
}

/// A JSON response with the security headers (`Cache-Control: no-store`).
pub fn json_response(status: StatusCode, v: &Value) -> Response<Vec<u8>> {
    response(
        status,
        "application/json; charset=utf-8",
        serde_json::to_vec(v).unwrap_or_default(),
        false,
        &[],
    )
}

pub fn error_response(e: &ApiError) -> Response<Vec<u8>> {
    response(
        e.status,
        "application/json; charset=utf-8",
        e.body(),
        false,
        &[],
    )
}
