//! The `/node/v1` binding: [`NodeApi`] is a [`secmonk_api::Mount`] over the three node services.
//!
//! Order of checks: route (404), method (405 + `Allow`), scope (403), service enabled (404 `service not enabled`),
//! body / query validation and caps (400 / 413), the call. The server layer in front has authenticated the
//! request, enforced the route's scope ([`Mount::required_scope`]) and capped its body
//! ([`secmonk_api::MAX_MOUNT_BODY`]); with auth off the server refuses the node API (403), so over HTTP a
//! principal is always present (`handle` keeps its own scope check as defense in depth). Request bodies are parsed, used and dropped: never stored, never logged (proposal §5).

use std::sync::Arc;

use async_trait::async_trait;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use secmonk_api::{ApiError, Mount, RequiredScope, error_response, json_response};
use secmonk_auth::{Principal, Scope};
use secmonk_model::node::{
    ChangesRequest, FeedSinceRequest, MAX_COMPONENTS, MAX_IDS, MatchComponentsRequest, NodeInfo,
    SummariesRequest,
};
use secmonk_traits::StepResult;
use secmonk_traits::node::{Feed, MatchService, VulnInfo};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::wire::{api_error_of_wire, parse_query};

/// The mount prefix.
pub const PREFIX: &str = "/node/v1/";

/// Most sources a `match/changes` request may name.
pub const MAX_CHANGE_SOURCES: usize = 256;
/// Longest id, source name or similar identifier accepted.
pub const MAX_NAME_LEN: usize = 256;
/// Most query parameters of `vulninfo/search`, and the longest value.
pub const MAX_SEARCH_PARAMS: usize = 32;
/// Longest value of a `vulninfo/search` parameter.
pub const MAX_SEARCH_VALUE: usize = 1024;

/// Where `GET info` takes its answer from.
#[async_trait]
pub trait NodeInfoProvider: Send + Sync {
    /// What this node is and offers.
    async fn info(&self) -> StepResult<NodeInfo>;
}

/// A fixed [`NodeInfo`] (tests, nodes without a mirror).
#[derive(Debug, Clone)]
pub struct StaticInfo(pub NodeInfo);

#[async_trait]
impl NodeInfoProvider for StaticInfo {
    async fn info(&self) -> StepResult<NodeInfo> {
        Ok(self.0.clone())
    }
}

/// [`NodeInfo`] derived from the enabled services: the roles are the enabled ones, the versions come from
/// `Feed::status` (else `MatchService::versions`).
pub struct DerivedInfo {
    node_id: String,
    mirror: bool,
    matcher: Option<Arc<dyn MatchService>>,
    vulninfo: bool,
    feed: Option<Arc<dyn Feed>>,
}

impl std::fmt::Debug for DerivedInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedInfo")
            .field("node_id", &self.node_id)
            .field("mirror", &self.mirror)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl NodeInfoProvider for DerivedInfo {
    async fn info(&self) -> StepResult<NodeInfo> {
        let mut roles = Vec::new();
        if self.feed.is_some() {
            roles.push("feed".to_owned());
        }
        if self.matcher.is_some() {
            roles.push("match".to_owned());
        }
        if self.vulninfo {
            roles.push("vulninfo".to_owned());
        }
        let (matcher, sources) = if let Some(f) = &self.feed {
            let s = f.status().await?;
            (s.matcher, s.sources)
        } else if let Some(m) = &self.matcher {
            let v = m.versions().await?;
            (v.matcher, v.sources.into_values().collect())
        } else {
            // neither a feed nor a match service: no matcher is served
            ("none".to_owned(), Vec::new())
        };
        Ok(NodeInfo {
            node_id: self.node_id.clone(),
            roles,
            matcher,
            mirror: self.mirror,
            sources: if self.mirror { sources } else { Vec::new() },
        })
    }
}

/// The node API. Build it with the services listed in `[node] serve` (the others `None`) and mount it with
/// `Server::with_mount`.
pub struct NodeApi {
    matcher: Option<Arc<dyn MatchService>>,
    vulninfo: Option<Arc<dyn VulnInfo>>,
    feed: Option<Arc<dyn Feed>>,
    info: Arc<dyn NodeInfoProvider>,
}

impl std::fmt::Debug for NodeApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeApi")
            .field("match", &self.matcher.is_some())
            .field("vulninfo", &self.vulninfo.is_some())
            .field("feed", &self.feed.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Info,
    MatchComponents,
    MatchChanges,
    VulninfoSummaries,
    VulninfoDetail,
    VulninfoSearch,
    FeedStatus,
    FeedSince,
}

impl Route {
    fn parse(rest: &str) -> Option<Route> {
        Some(match rest {
            "info" => Route::Info,
            "match/components" => Route::MatchComponents,
            "match/changes" => Route::MatchChanges,
            "vulninfo/summaries" => Route::VulninfoSummaries,
            "vulninfo/detail" => Route::VulninfoDetail,
            "vulninfo/search" => Route::VulninfoSearch,
            "feed/status" => Route::FeedStatus,
            "feed/since" => Route::FeedSince,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Route::Info => "info",
            Route::MatchComponents => "match/components",
            Route::MatchChanges => "match/changes",
            Route::VulninfoSummaries => "vulninfo/summaries",
            Route::VulninfoDetail => "vulninfo/detail",
            Route::VulninfoSearch => "vulninfo/search",
            Route::FeedStatus => "feed/status",
            Route::FeedSince => "feed/since",
        }
    }

    fn method(self) -> Method {
        match self {
            Route::MatchComponents | Route::MatchChanges | Route::VulninfoSummaries => Method::POST,
            _ => Method::GET,
        }
    }

    /// `None`: any authenticated principal.
    fn scope(self) -> Option<Scope> {
        match self {
            Route::Info => None,
            Route::MatchComponents | Route::MatchChanges => Some(Scope::Match),
            Route::VulninfoSummaries | Route::VulninfoDetail | Route::VulninfoSearch => {
                Some(Scope::VulninfoRead)
            }
            Route::FeedStatus | Route::FeedSince => Some(Scope::FeedRead),
        }
    }
}

/// A successful answer and the count the audit line records.
type Reply = (Value, usize);

impl NodeApi {
    /// The node API over the enabled services, `GET info` answered by `info`.
    pub fn new(
        matcher: Option<Arc<dyn MatchService>>,
        vulninfo: Option<Arc<dyn VulnInfo>>,
        feed: Option<Arc<dyn Feed>>,
        info: Arc<dyn NodeInfoProvider>,
    ) -> NodeApi {
        NodeApi {
            matcher,
            vulninfo,
            feed,
            info,
        }
    }

    /// [`NodeApi::new`] with the info derived from the services ([`DerivedInfo`]).
    pub fn derived(
        matcher: Option<Arc<dyn MatchService>>,
        vulninfo: Option<Arc<dyn VulnInfo>>,
        feed: Option<Arc<dyn Feed>>,
        node_id: impl Into<String>,
        mirror: bool,
    ) -> NodeApi {
        let info = DerivedInfo {
            node_id: node_id.into(),
            mirror,
            matcher: matcher.clone(),
            vulninfo: vulninfo.is_some(),
            feed: feed.clone(),
        };
        NodeApi::new(matcher, vulninfo, feed, Arc::new(info))
    }

    async fn dispatch(&self, route: Route, req: &Request<Vec<u8>>) -> Result<Reply, ApiError> {
        match route {
            Route::Info => reply(self.info.info().await, 1),
            Route::MatchComponents => {
                let svc = enabled(&self.matcher)?;
                let body: MatchComponentsRequest = parse_body(req)?;
                if body.components.len() > MAX_COMPONENTS {
                    return Err(too_many(
                        "components",
                        body.components.len(),
                        MAX_COMPONENTS,
                    ));
                }
                if let Some(c) = body.min_confidence
                    && !(0.0..=1.0).contains(&c)
                {
                    return Err(ApiError::bad_request("min_confidence: expected 0..1"));
                }
                let n = body.components.len();
                reply(svc.match_components(body).await, n)
            }
            Route::MatchChanges => {
                let svc = enabled(&self.matcher)?;
                let body: ChangesRequest = parse_body(req)?;
                if body.since.len() > MAX_CHANGE_SOURCES {
                    return Err(too_many("sources", body.since.len(), MAX_CHANGE_SOURCES));
                }
                if body
                    .since
                    .iter()
                    .any(|(k, v)| k.len() > MAX_NAME_LEN || v.len() > MAX_NAME_LEN)
                {
                    return Err(ApiError::bad_request(format!(
                        "since: names and versions are at most {MAX_NAME_LEN} bytes"
                    )));
                }
                let n = body.since.len();
                reply(svc.changes(body).await, n)
            }
            Route::VulninfoSummaries => {
                let svc = enabled(&self.vulninfo)?;
                let body: SummariesRequest = parse_body(req)?;
                if body.ids.len() > MAX_IDS {
                    return Err(too_many("ids", body.ids.len(), MAX_IDS));
                }
                if body.ids.iter().any(|i| i.len() > MAX_NAME_LEN) {
                    return Err(ApiError::bad_request(format!(
                        "ids: at most {MAX_NAME_LEN} bytes each"
                    )));
                }
                let n = body.ids.len();
                reply(svc.summaries(&body.ids).await, n)
            }
            Route::VulninfoDetail => {
                let svc = enabled(&self.vulninfo)?;
                let q = parse_query(req.uri().query());
                let id = param(&q, "id").ok_or_else(|| ApiError::bad_request("id is required"))?;
                if id.len() > MAX_NAME_LEN {
                    return Err(ApiError::bad_request(format!(
                        "id: at most {MAX_NAME_LEN} bytes"
                    )));
                }
                let raw = matches!(param(&q, "raw"), Some("1" | "true" | "yes"));
                match svc.detail(id, raw).await {
                    Ok(v) => Ok((v, 1)),
                    Err(e) => Err(api_error_of_wire(&e)),
                }
            }
            Route::VulninfoSearch => {
                let svc = enabled(&self.vulninfo)?;
                let q = parse_query(req.uri().query());
                if q.len() > MAX_SEARCH_PARAMS {
                    return Err(too_many("query parameters", q.len(), MAX_SEARCH_PARAMS));
                }
                if q.iter().any(|(_, v)| v.len() > MAX_SEARCH_VALUE) {
                    return Err(ApiError::bad_request(format!(
                        "query values are at most {MAX_SEARCH_VALUE} bytes"
                    )));
                }
                let mut obj = Map::new();
                for (k, v) in q {
                    match obj.get_mut(&k) {
                        None => {
                            obj.insert(k, Value::String(v));
                        }
                        Some(Value::Array(a)) => a.push(Value::String(v)),
                        Some(first) => {
                            let first = first.take();
                            obj.insert(k, Value::Array(vec![first, Value::String(v)]));
                        }
                    }
                }
                match svc.search(Value::Object(obj)).await {
                    Ok(v) => Ok((v, 1)),
                    Err(e) => Err(api_error_of_wire(&e)),
                }
            }
            Route::FeedStatus => {
                let svc = enabled(&self.feed)?;
                let s = svc.status().await;
                let n = s.as_ref().map_or(0, |s| s.sources.len());
                reply(s, n)
            }
            Route::FeedSince => {
                let svc = enabled(&self.feed)?;
                let q = parse_query(req.uri().query());
                let source = param(&q, "source")
                    .ok_or_else(|| ApiError::bad_request("source is required"))?
                    .to_owned();
                let since = param(&q, "since").map(str::to_owned);
                let page = param(&q, "page").map(str::to_owned);
                for (name, v) in [
                    ("source", Some(&source)),
                    ("since", since.as_ref()),
                    ("page", page.as_ref()),
                ] {
                    if v.is_some_and(|v| v.len() > MAX_NAME_LEN * 4) {
                        return Err(ApiError::bad_request(format!("{name}: too long")));
                    }
                }
                let limit = match param(&q, "limit") {
                    None => None,
                    Some(l) => Some(l.parse::<u32>().map_err(|_| {
                        ApiError::bad_request("limit: expected a positive integer")
                    })?),
                };
                let page = svc
                    .since(FeedSinceRequest {
                        source,
                        since,
                        page,
                        limit,
                    })
                    .await;
                let n = page.as_ref().map_or(0, |p| p.batches.len());
                reply(page, n)
            }
        }
    }
}

#[async_trait]
impl Mount for NodeApi {
    fn prefix(&self) -> &'static str {
        PREFIX
    }

    /// The server enforces the route's scope before [`Mount::handle`] (403); an unknown route or a wrong method
    /// only needs a principal, so `handle` answers 404 / 405.
    fn required_scope(&self, method: &Method, path: &str) -> Option<RequiredScope> {
        let route = Route::parse(path.strip_prefix(PREFIX)?)?;
        if *method != route.method() {
            return Some(RequiredScope::Authenticated);
        }
        Some(
            route
                .scope()
                .map_or(RequiredScope::Authenticated, RequiredScope::Scope),
        )
    }

    async fn handle(
        &self,
        req: Request<Vec<u8>>,
        principal: Option<Principal>,
    ) -> Response<Vec<u8>> {
        let rest = req.uri().path().strip_prefix(PREFIX).unwrap_or("");
        let Some(route) = Route::parse(rest) else {
            return error_response(&ApiError::not_found("not found"));
        };
        if req.method() != route.method() {
            let mut r = error_response(&ApiError::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
            if let Ok(v) = HeaderValue::from_str(route.method().as_str()) {
                r.headers_mut().insert(header::ALLOW, v);
            }
            return r;
        }
        // defense in depth: the server already enforced `required_scope` and never calls a mount without a
        // principal (`None` only reaches here from in-process callers, e.g. host tests)
        if let (Some(p), Some(need)) = (&principal, route.scope())
            && !p.scopes.contains(need)
        {
            return error_response(
                &ApiError::new(StatusCode::FORBIDDEN, "forbidden").with_hint(format!(
                    "the API key lacks the scope {need} (needed for {} {})",
                    route.method(),
                    route.name()
                )),
            );
        }
        let (response, count) = match self.dispatch(route, &req).await {
            Ok((v, n)) => (json_response(StatusCode::OK, &v), n),
            Err(e) => (error_response(&e), 0),
        };
        // the audit line: who, which call, how many; never a body, a query or an id
        tracing::info!(
            target: "audit",
            key = ?principal.as_ref().map_or("-", |p| p.subject.as_str()),
            route = route.name(),
            status = response.status().as_u16(),
            count,
            "node call"
        );
        response
    }
}

fn enabled<T: ?Sized>(svc: &Option<Arc<T>>) -> Result<&Arc<T>, ApiError> {
    svc.as_ref()
        .ok_or_else(|| ApiError::not_found("service not enabled"))
}

fn too_many(what: &str, n: usize, max: usize) -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        format!("too many {what}: {n} (at most {max} per request)"),
    )
    .with_hint(format!("split the request into calls of at most {max}"))
}

fn reply<T: Serialize>(r: StepResult<T>, count: usize) -> Result<Reply, ApiError> {
    match r {
        Ok(v) => serde_json::to_value(v)
            .map(|v| (v, count))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
        Err(e) => Err(api_error_of_wire(&e)),
    }
}

fn parse_body<T: DeserializeOwned>(req: &Request<Vec<u8>>) -> Result<T, ApiError> {
    serde_json::from_slice(req.body())
        .map_err(|e| ApiError::bad_request(format!("invalid request body: {e}")))
}

fn param<'a>(q: &'a [(String, String)], name: &str) -> Option<&'a str> {
    q.iter()
        .rev()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.trim().is_empty())
}
