//! `NodeApi` behind `secmonk_api::Server` (auth on, real sockets) and `RemoteNode` against it, plain and TLS.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use http::{Request, Response};
use secmonk_api::{
    HostPolicy, Mount, Router, RouterOptions, Server, StaticDir, TlsFiles, accept_loop,
    tls_acceptor,
};
use secmonk_auth::{Authenticator, JwtSigner, KeyStore, Principal, Scopes};
use secmonk_engine::{EngineInfo, SkeletonEngine};
use secmonk_model::Category;
use secmonk_model::node::{
    ChangesRequest, ChangesResponse, ComponentIdentity, ComponentResult, Coverage, FeedMode,
    FeedPage, FeedSinceRequest, FeedStatus, MATCHER_VERSION, MAX_COMPONENTS, MAX_IDS,
    MatchComponentsRequest, MatchComponentsResponse, SourceChanges, SourceVersion,
    SummariesResponse, VersionKind, Versions, VulnSummary,
};
use secmonk_node::{NodeApi, RemoteConfig, RemoteNode};
use secmonk_traits::node::{Feed, MatchService, VulnInfo};
use secmonk_traits::{ErrorCode, StepResult, WireError};
use serde_json::{Value, json};
use tokio::net::TcpListener;

// ------------------------------------------------------------------------------------------------------------
// fakes

fn version(source: &str) -> SourceVersion {
    SourceVersion {
        source: source.into(),
        version: Some("2026-11-01T00:00:00Z".into()),
        importer: "rust/1".into(),
        kind: VersionKind::Record,
        records: 7,
        last_sync: None,
        status: Some("ok".into()),
    }
}

fn versions() -> Versions {
    Versions::new(MATCHER_VERSION, [version("nvd"), version("kev")])
}

#[derive(Default)]
struct FakeMatch {
    calls: AtomicUsize,
    sizes: std::sync::Mutex<Vec<usize>>,
}

#[async_trait]
impl MatchService for FakeMatch {
    async fn match_components(
        &self,
        req: MatchComponentsRequest,
    ) -> StepResult<MatchComponentsResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.sizes.lock().unwrap().push(req.components.len());
        Ok(MatchComponentsResponse {
            results: req
                .components
                .iter()
                .map(|c| ComponentResult {
                    key: c.key(),
                    matches: vec![],
                    lookup_keys: vec![format!("prod:{}", c.name.to_lowercase())],
                })
                .collect(),
            as_of: versions(),
            coverage: Coverage {
                sources: vec!["nvd".into()],
                ecosystems: vec!["PyPI".into()],
            },
        })
    }

    async fn changes(&self, req: ChangesRequest) -> StepResult<ChangesResponse> {
        Ok(ChangesResponse {
            sources: req
                .since
                .keys()
                .map(|k| (k.clone(), SourceChanges::Unchanged))
                .collect(),
            as_of: versions(),
        })
    }

    async fn versions(&self) -> StepResult<Versions> {
        Ok(versions())
    }
}

#[derive(Default)]
struct FakeVuln;

fn summary(id: &str) -> VulnSummary {
    VulnSummary {
        id: id.into(),
        aliases: vec![],
        summary: Some("s".into()),
        severity: Some("HIGH".into()),
        cvss_score: Some(7.5),
        cvss_vector: None,
        published: None,
        modified: None,
        withdrawn: None,
        kev: false,
        kev_date_added: None,
        epss: None,
        epss_percentile: None,
        sources: vec!["nvd".into()],
    }
}

#[async_trait]
impl VulnInfo for FakeVuln {
    async fn summaries(&self, ids: &[String]) -> StepResult<SummariesResponse> {
        let (known, missing): (Vec<_>, Vec<_>) =
            ids.iter().cloned().partition(|i| i.starts_with("CVE-"));
        Ok(SummariesResponse {
            summaries: known.iter().map(|i| summary(i)).collect(),
            missing,
        })
    }

    async fn detail(&self, id: &str, raw: bool) -> StepResult<Value> {
        if id == "CVE-0000-0000" {
            return Err(WireError::new(
                ErrorCode::UnknownVuln,
                "no such vulnerability",
            ));
        }
        if id == "boom" {
            return Err(WireError::internal("Secret", "/var/lib/db leaked"));
        }
        Ok(json!({"id": id, "raw": raw}))
    }

    async fn search(&self, params: Value) -> StepResult<Value> {
        Ok(json!({"params": params}))
    }
}

struct FakeFeed;

#[async_trait]
impl Feed for FakeFeed {
    async fn status(&self) -> StepResult<FeedStatus> {
        Ok(FeedStatus {
            node_id: Some("node:test".into()),
            matcher: MATCHER_VERSION.into(),
            sources: vec![version("kev"), version("nvd")],
        })
    }

    async fn since(&self, req: FeedSinceRequest) -> StepResult<FeedPage> {
        Ok(FeedPage {
            version: version(&req.source),
            source: req.source,
            mode: FeedMode::Delta,
            batches: vec![],
            next_page: req.page.map(|p| format!("{p}+")),
        })
    }
}

/// Fails the first request to a route with a 401 (a token the node no longer accepts), then delegates.
struct FlakyAuth {
    inner: Arc<NodeApi>,
    left: AtomicUsize,
}

#[async_trait]
impl Mount for FlakyAuth {
    fn prefix(&self) -> &'static str {
        "/node/v1/"
    }
    async fn handle(
        &self,
        req: Request<Vec<u8>>,
        principal: Option<Principal>,
    ) -> Response<Vec<u8>> {
        if req.uri().path().ends_with("/info")
            && self
                .left
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        {
            return Response::builder()
                .status(401)
                .body(b"{\"error\":\"invalid credentials\"}".to_vec())
                .unwrap();
        }
        self.inner.handle(req, principal).await
    }
}

// ------------------------------------------------------------------------------------------------------------
// fixture

struct Keys {
    all: String,
    matcher: String,
    feed: String,
    vuln: String,
    ui: String,
}

struct Fixture {
    addr: SocketAddr,
    keys: Keys,
    matcher: Arc<FakeMatch>,
    tls: bool,
}

#[derive(Clone, Copy)]
struct Opts {
    tls: bool,
    jwt_ttl: u64,
    enable_feed: bool,
    flaky_info: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            tls: false,
            jwt_ttl: 3600,
            enable_feed: true,
            flaky_info: 0,
        }
    }
}

fn tls_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../secmonk-api/tests/fixtures/tls")
}

async fn start(o: Opts) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let engine = Arc::new(SkeletonEngine::new(EngineInfo::new(
        "0.1.0",
        "/x/state.sqlite3",
    )));
    let router = Arc::new(Router::new(
        engine,
        RouterOptions {
            static_dir: StaticDir::new(std::env::temp_dir().join("secmonk-node-none")),
            host_policy: HostPolicy::http_server("127.0.0.1", addr.port(), &[]),
            actions: true,
        },
    ));
    let mut store = KeyStore::in_memory();
    let mut mk = |name: &str, scopes: &[&str]| {
        store
            .create(name, Scopes::parse(scopes.iter().copied()).unwrap(), None)
            .unwrap()
    };
    let keys = Keys {
        all: mk("all", &["match", "vulninfo:read", "feed:read"]),
        matcher: mk("matcher", &["match"]),
        feed: mk("feeder", &["feed:read"]),
        vuln: mk("vuln", &["vulninfo:read"]),
        ui: mk("ui", &["ui"]),
    };
    let matcher = Arc::new(FakeMatch::default());
    let m: Arc<dyn MatchService> = matcher.clone();
    let v: Arc<dyn VulnInfo> = Arc::new(FakeVuln);
    let f: Option<Arc<dyn Feed>> = o.enable_feed.then(|| Arc::new(FakeFeed) as Arc<dyn Feed>);
    let api = Arc::new(NodeApi::derived(Some(m), Some(v), f, "node:test", true));
    let mount: Arc<dyn Mount> = if o.flaky_info > 0 {
        Arc::new(FlakyAuth {
            inner: api,
            left: AtomicUsize::new(o.flaky_info),
        })
    } else {
        api
    };
    let signer = JwtSigner::new(vec![7; 32], o.jwt_ttl);
    let server = Server::new(router)
        .with_auth(Arc::new(Authenticator::new(store, signer, 10_000)))
        .with_mount(mount);
    let acceptor = o.tls.then(|| {
        tls_acceptor(&TlsFiles {
            cert: tls_dir().join("cert.pem"),
            key: tls_dir().join("key.pem"),
        })
        .unwrap()
    });
    tokio::spawn(accept_loop(
        Arc::new(server),
        listener,
        acceptor,
        Duration::from_secs(5),
        16,
    ));
    Fixture {
        addr,
        keys,
        matcher,
        tls: o.tls,
    }
}

impl Fixture {
    fn base(&self) -> String {
        format!(
            "{}://127.0.0.1:{}",
            if self.tls { "https" } else { "http" },
            self.addr.port()
        )
    }

    fn remote(&self, key: &str) -> RemoteNode {
        RemoteNode::new(RemoteConfig {
            base_url: self.base(),
            api_key: key.into(),
            ca_cert: self.tls.then(|| tls_dir().join("cert.pem")),
            timeout: Duration::from_secs(10),
        })
        .unwrap()
    }

    /// A raw call with `Authorization: ApiKey`.
    async fn raw(
        &self,
        key: Option<&str>,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value, reqwest::header::HeaderMap) {
        let c = reqwest::Client::new();
        let mut r = c.request(
            method.parse().unwrap(),
            format!("http://127.0.0.1:{}{path}", self.addr.port()),
        );
        if let Some(k) = key {
            r = r.header("Authorization", format!("ApiKey {k}"));
        }
        if let Some(b) = body {
            r = r
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(&b).unwrap());
        }
        let resp = r.send().await.unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let text = resp.text().await.unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
            headers,
        )
    }
}

fn component(n: usize) -> ComponentIdentity {
    ComponentIdentity {
        name: format!("pkg{n}"),
        version: Some("1.0".into()),
        category: Category::Library,
        purl: None,
        cpe: None,
        vendor: None,
        ecosystem: None,
        meta: Default::default(),
    }
}

// ------------------------------------------------------------------------------------------------------------
// the server binding

#[tokio::test]
async fn every_route_answers_with_its_scope() {
    let fx = start(Opts::default()).await;
    let k = &fx.keys;
    let comps = json!({"components": [component(1)]});

    let (s, v, h) = fx.raw(Some(&k.all), "GET", "/node/v1/info", None).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["node_id"], "node:test");
    assert_eq!(v["roles"], json!(["feed", "match", "vulninfo"]));
    assert_eq!(h.get("cache-control").unwrap(), "no-store");
    // info is for any authenticated principal, even one with a UI scope only
    assert_eq!(
        fx.raw(Some(&k.ui), "GET", "/node/v1/info", None).await.0,
        200
    );

    let (s, v, _) = fx
        .raw(
            Some(&k.matcher),
            "POST",
            "/node/v1/match/components",
            Some(comps),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["results"][0]["key"], "name:library//pkg1@1.0");
    let (s, v, _) = fx
        .raw(
            Some(&k.matcher),
            "POST",
            "/node/v1/match/changes",
            Some(json!({"since": {"nvd": "rust/1@x"}})),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["sources"]["nvd"], json!({"unchanged": true}));

    let (s, v, _) = fx
        .raw(
            Some(&k.vuln),
            "POST",
            "/node/v1/vulninfo/summaries",
            Some(json!({"ids": ["CVE-1", "GHSA-x"]})),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["summaries"][0]["id"], "CVE-1");
    assert_eq!(v["missing"], json!(["GHSA-x"]));
    let (s, v, _) = fx
        .raw(
            Some(&k.vuln),
            "GET",
            "/node/v1/vulninfo/detail?id=CVE-9&raw=1",
            None,
        )
        .await;
    assert_eq!(
        (s, &v["id"], &v["raw"]),
        (200, &json!("CVE-9"), &json!(true))
    );
    let (s, v, _) = fx
        .raw(
            Some(&k.vuln),
            "GET",
            "/node/v1/vulninfo/search?q=openssl&severity=HIGH&severity=LOW&limit=5",
            None,
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        v["params"],
        json!({"q": "openssl", "severity": ["HIGH", "LOW"], "limit": "5"})
    );

    let (s, v, _) = fx
        .raw(Some(&k.feed), "GET", "/node/v1/feed/status", None)
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["sources"][0]["source"], "kev");
    let (s, v, _) = fx
        .raw(
            Some(&k.feed),
            "GET",
            "/node/v1/feed/since?source=nvd&since=2026-01-01&page=p1&limit=10",
            None,
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        (&v["source"], &v["mode"], &v["next_page"]),
        (&json!("nvd"), &json!("delta"), &json!("p1+"))
    );
}

#[tokio::test]
async fn scopes_are_enforced_per_route() {
    let fx = start(Opts::default()).await;
    let k = &fx.keys;
    // the match key cannot read the feed or vulninfo; the feed key cannot match
    let (s, v, _) = fx
        .raw(Some(&k.matcher), "GET", "/node/v1/feed/status", None)
        .await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(v["error"], "forbidden");
    assert!(v["hint"].as_str().unwrap().contains("feed:read"));
    assert_eq!(
        fx.raw(
            Some(&k.matcher),
            "GET",
            "/node/v1/feed/since?source=nvd",
            None
        )
        .await
        .0,
        403
    );
    assert_eq!(
        fx.raw(
            Some(&k.matcher),
            "GET",
            "/node/v1/vulninfo/detail?id=CVE-1",
            None
        )
        .await
        .0,
        403
    );
    assert_eq!(
        fx.raw(
            Some(&k.feed),
            "POST",
            "/node/v1/match/components",
            Some(json!({"components": []}))
        )
        .await
        .0,
        403
    );
    assert_eq!(
        fx.raw(
            Some(&k.vuln),
            "POST",
            "/node/v1/match/changes",
            Some(json!({"since": {}}))
        )
        .await
        .0,
        403
    );
    assert_eq!(
        fx.raw(
            Some(&k.ui),
            "POST",
            "/node/v1/vulninfo/summaries",
            Some(json!({"ids": []}))
        )
        .await
        .0,
        403
    );
    // no credential at all: the server layer answers 401 before the mount
    assert_eq!(fx.raw(None, "GET", "/node/v1/info", None).await.0, 401);
}

#[tokio::test]
async fn caps_methods_unknown_routes_and_bad_bodies() {
    let fx = start(Opts::default()).await;
    let k = &fx.keys;
    let many: Vec<_> = (0..=MAX_COMPONENTS).map(component).collect();
    let (s, v, _) = fx
        .raw(
            Some(&k.matcher),
            "POST",
            "/node/v1/match/components",
            Some(json!({"components": many})),
        )
        .await;
    assert_eq!(s, 413, "{v}");
    assert!(v["error"].as_str().unwrap().contains("1001"));
    assert_eq!(
        fx.matcher.calls.load(Ordering::SeqCst),
        0,
        "the service never saw the oversized request"
    );
    let ids: Vec<String> = (0..=MAX_IDS).map(|i| format!("CVE-{i}")).collect();
    let (s, _, _) = fx
        .raw(
            Some(&k.vuln),
            "POST",
            "/node/v1/vulninfo/summaries",
            Some(json!({"ids": ids})),
        )
        .await;
    assert_eq!(s, 413);
    // exactly at the cap is fine
    let ok: Vec<_> = (0..MAX_COMPONENTS).map(component).collect();
    assert_eq!(
        fx.raw(
            Some(&k.matcher),
            "POST",
            "/node/v1/match/components",
            Some(json!({"components": ok}))
        )
        .await
        .0,
        200
    );
    // unknown fields, bad JSON, bad parameters
    let (s, v, _) = fx
        .raw(
            Some(&k.matcher),
            "POST",
            "/node/v1/match/components",
            Some(json!({"components": [], "asset_id": "x"})),
        )
        .await;
    assert_eq!(s, 400, "{v}");
    assert!(v["error"].as_str().unwrap().contains("asset_id"));
    let (s, _, _) = fx
        .raw(
            Some(&k.matcher),
            "POST",
            "/node/v1/match/changes",
            Some(json!([1])),
        )
        .await;
    assert_eq!(s, 400);
    assert_eq!(
        fx.raw(Some(&k.vuln), "GET", "/node/v1/vulninfo/detail", None)
            .await
            .0,
        400
    );
    assert_eq!(
        fx.raw(Some(&k.feed), "GET", "/node/v1/feed/since", None)
            .await
            .0,
        400
    );
    assert_eq!(
        fx.raw(
            Some(&k.feed),
            "GET",
            "/node/v1/feed/since?source=nvd&limit=x",
            None
        )
        .await
        .0,
        400
    );
    // method mismatch and unknown route
    let (s, _, h) = fx
        .raw(Some(&k.matcher), "GET", "/node/v1/match/components", None)
        .await;
    assert_eq!(s, 405);
    assert_eq!(h.get("allow").unwrap(), "POST");
    assert_eq!(
        fx.raw(
            Some(&k.feed),
            "POST",
            "/node/v1/feed/status",
            Some(json!({}))
        )
        .await
        .0,
        405
    );
    assert_eq!(
        fx.raw(Some(&k.all), "GET", "/node/v1/nothing", None)
            .await
            .0,
        404
    );
    assert_eq!(fx.raw(Some(&k.all), "GET", "/node/v1/", None).await.0, 404);
}

#[tokio::test]
async fn wire_errors_map_to_statuses_and_internals_stay_inside() {
    let fx = start(Opts::default()).await;
    let k = &fx.keys;
    let (s, v, _) = fx
        .raw(
            Some(&k.vuln),
            "GET",
            "/node/v1/vulninfo/detail?id=CVE-0000-0000",
            None,
        )
        .await;
    assert_eq!((s, v["code"].as_str()), (404, Some("unknown-vuln")));
    let (s, v, _) = fx
        .raw(
            Some(&k.vuln),
            "GET",
            "/node/v1/vulninfo/detail?id=boom",
            None,
        )
        .await;
    assert_eq!(s, 500);
    assert_eq!(v["error"], "internal error");
    assert!(!v.to_string().contains("leaked"));
}

#[tokio::test]
async fn a_disabled_service_answers_404() {
    let fx = start(Opts {
        enable_feed: false,
        ..Opts::default()
    })
    .await;
    let (s, v, _) = fx
        .raw(Some(&fx.keys.feed), "GET", "/node/v1/feed/status", None)
        .await;
    assert_eq!((s, v), (404, json!({"error": "service not enabled"})));
    assert_eq!(
        fx.raw(
            Some(&fx.keys.feed),
            "GET",
            "/node/v1/feed/since?source=nvd",
            None
        )
        .await
        .0,
        404
    );
    // the others work, and info lists only the enabled roles
    let (s, v, _) = fx
        .raw(Some(&fx.keys.all), "GET", "/node/v1/info", None)
        .await;
    assert_eq!((s, &v["roles"]), (200, &json!(["match", "vulninfo"])));
}

// ------------------------------------------------------------------------------------------------------------
// the client

#[tokio::test]
async fn remote_node_calls_every_service() {
    let fx = start(Opts::default()).await;
    let n = fx.remote(&fx.keys.all);

    let info = n.info().await.unwrap();
    assert_eq!(info.node_id, "node:test");
    assert_eq!(n.versions().await.unwrap().sources.len(), 2);
    let r = n
        .match_components(MatchComponentsRequest {
            components: vec![component(1), component(2)],
            min_confidence: Some(0.5),
        })
        .await
        .unwrap();
    assert_eq!(r.results.len(), 2);
    assert_eq!(r.as_of.matcher, MATCHER_VERSION);
    let c = n
        .changes(ChangesRequest {
            since: [("nvd".to_owned(), "rust/1@x".to_owned())].into(),
            matcher: None,
        })
        .await
        .unwrap();
    assert_eq!(c.sources["nvd"], SourceChanges::Unchanged);
    let s = n.summaries(&["CVE-1".into(), "x".into()]).await.unwrap();
    assert_eq!((s.summaries.len(), s.missing), (1, vec!["x".to_owned()]));
    assert_eq!(
        n.detail("CVE-2", true).await.unwrap(),
        json!({"id": "CVE-2", "raw": true})
    );
    assert_eq!(
        n.search(json!({"q": "a b&c", "tag": ["x", "y"], "limit": 3, "skip": null}))
            .await
            .unwrap(),
        json!({"params": {"q": "a b&c", "tag": ["x", "y"], "limit": "3"}})
    );
    assert_eq!(n.status().await.unwrap().sources.len(), 2);
    let p = n
        .since(FeedSinceRequest {
            source: "kev".into(),
            since: Some("v 1".into()),
            page: Some("p".into()),
            limit: Some(5),
        })
        .await
        .unwrap();
    assert_eq!(
        (p.source.as_str(), p.next_page.as_deref()),
        ("kev", Some("p+"))
    );
    assert_eq!(n.token_exchanges(), 1, "one token served every call");

    // errors come back as wire codes
    assert_eq!(
        n.detail("CVE-0000-0000", false).await.unwrap_err().code,
        ErrorCode::UnknownVuln
    );
    let e = n.detail("boom", false).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Internal);
    assert!(!e.error.contains("leaked"));
    assert_eq!(
        n.search(json!("x")).await.unwrap_err().code,
        ErrorCode::InvalidParams
    );
}

#[tokio::test]
async fn remote_node_splits_large_calls_and_merges() {
    let fx = start(Opts::default()).await;
    let n = fx.remote(&fx.keys.all);
    let comps: Vec<_> = (0..2 * MAX_COMPONENTS + 5).map(component).collect();
    let r = n
        .match_components(MatchComponentsRequest {
            components: comps.clone(),
            min_confidence: None,
        })
        .await
        .unwrap();
    assert_eq!(
        fx.matcher.sizes.lock().unwrap().clone(),
        vec![1000, 1000, 5]
    );
    assert_eq!(r.results.len(), comps.len());
    assert_eq!(r.results[1005].key, comps[1005].key(), "request order");
    assert_eq!(r.coverage.sources, vec!["nvd".to_owned()]);
    let ids: Vec<String> = (0..MAX_IDS + 1)
        .map(|i| {
            if i % 2 == 0 {
                format!("CVE-{i}")
            } else {
                format!("X-{i}")
            }
        })
        .collect();
    let s = n.summaries(&ids).await.unwrap();
    assert_eq!(s.summaries.len() + s.missing.len(), ids.len());
    // an empty request is one call
    let before = fx.matcher.calls.load(Ordering::SeqCst);
    let r = n
        .match_components(MatchComponentsRequest {
            components: vec![],
            min_confidence: None,
        })
        .await
        .unwrap();
    assert!(r.results.is_empty());
    assert_eq!(fx.matcher.calls.load(Ordering::SeqCst), before + 1);
}

#[tokio::test]
async fn remote_node_scopes_and_bad_keys() {
    let fx = start(Opts::default()).await;
    let n = fx.remote(&fx.keys.matcher);
    n.match_components(MatchComponentsRequest {
        components: vec![],
        min_confidence: None,
    })
    .await
    .unwrap();
    let e = n.status().await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Other("forbidden".into()));
    assert!(e.hint.unwrap_or_default().contains("feed:read"));
    let bad = fx.remote("smk_deadbeef_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let e = bad.info().await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Other("unauthorized".into()));
    assert!(!e.error.contains("smk_"));
    // nothing listens: a network error, not a panic
    let dead = RemoteNode::new(RemoteConfig {
        base_url: "http://127.0.0.1:1".into(),
        api_key: "smk_00000000_x".into(),
        ca_cert: None,
        timeout: Duration::from_secs(2),
    })
    .unwrap();
    assert_eq!(
        dead.info().await.unwrap_err().code,
        ErrorCode::HostUnreachable
    );
}

#[tokio::test]
async fn the_token_is_renewed_before_it_expires() {
    let fx = start(Opts {
        jwt_ttl: 2,
        ..Opts::default()
    })
    .await;
    // default margin (60 s) is over a 2 s token's life: every call exchanges again, and every call works
    let n = fx.remote(&fx.keys.all);
    n.info().await.unwrap();
    n.info().await.unwrap();
    assert_eq!(n.token_exchanges(), 2);
    // a margin of zero keeps the token until it expires, then renews
    let n = fx.remote(&fx.keys.all).with_refresh_margin(Duration::ZERO);
    n.info().await.unwrap();
    n.info().await.unwrap();
    assert_eq!(n.token_exchanges(), 1);
    tokio::time::sleep(Duration::from_millis(3200)).await;
    n.info().await.unwrap();
    assert_eq!(n.token_exchanges(), 2, "renewed after the expiry");
}

#[tokio::test]
async fn a_401_renews_the_token_and_retries_once() {
    let fx = start(Opts {
        flaky_info: 1,
        ..Opts::default()
    })
    .await;
    let n = fx.remote(&fx.keys.all);
    n.info().await.unwrap();
    assert_eq!(n.token_exchanges(), 2, "the refused token was replaced");
    // a node that keeps answering 401 is not retried forever
    let fx = start(Opts {
        flaky_info: 5,
        ..Opts::default()
    })
    .await;
    let n = fx.remote(&fx.keys.all);
    let e = n.info().await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Other("unauthorized".into()));
    assert_eq!(n.token_exchanges(), 2);
}

// ------------------------------------------------------------------------------------------------------------
// TLS

#[tokio::test]
async fn remote_node_over_tls_with_an_extra_ca() {
    let fx = start(Opts {
        tls: true,
        ..Opts::default()
    })
    .await;
    let n = fx.remote(&fx.keys.all);
    assert_eq!(n.info().await.unwrap().node_id, "node:test");
    assert_eq!(n.status().await.unwrap().sources.len(), 2);
    // without the CA the self-signed certificate is refused
    let n = RemoteNode::new(RemoteConfig {
        base_url: fx.base(),
        api_key: fx.keys.all.clone(),
        ca_cert: None,
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    let e = n.info().await.unwrap_err();
    assert_eq!(e.code, ErrorCode::HostUnreachable, "{e}");
    assert!(!e.error.contains("smk_"));
}
