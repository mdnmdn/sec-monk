//! Router tests: the whole request path (method, Host, header gate, route table, validation, error bodies,
//! security headers, static files) against the skeleton engine and an echo engine.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use http::{Method, Request, Response, StatusCode};
use secmonk_api::{CSP, HostPolicy, ROUTES, Router, RouterOptions, StaticDir};
use secmonk_engine::{
    DiscoverQuery, DockerListQuery, EngineInfo, EngineResult, EngineService, FindingsQuery,
    JobsQuery, JsonObject, SkeletonEngine, VulnSearchQuery,
};
use serde_json::{Value, json};

const CATALOG: &str = include_str!("../../../contracts/catalog/api-routes.json");
const ERROR_NO_DB: &str = include_str!("../../../contracts/examples/api/error-no-db.json");
const STATE_PATH: &str = "/data/sec-monk/db/state.sqlite3";

fn static_tree(tag: &str) -> PathBuf {
    let base =
        std::env::temp_dir().join(format!("secmonk-api-router-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("static/js")).unwrap();
    std::fs::write(base.join("static/index.html"), "<div id=\"app\"></div>").unwrap();
    std::fs::write(base.join("static/js/boot.js"), "// boot").unwrap();
    std::fs::write(base.join("secret.txt"), "secret").unwrap();
    base
}

fn router_with(
    engine: Arc<dyn EngineService>,
    tag: &str,
    host: HostPolicy,
    actions: bool,
) -> Router {
    let base = static_tree(tag);
    Router::new(
        engine,
        RouterOptions {
            static_dir: StaticDir::new(base.join("static")),
            host_policy: host,
            actions,
        },
    )
}

fn skeleton(tag: &str) -> Router {
    let e = Arc::new(SkeletonEngine::new(EngineInfo::new("0.1.0", STATE_PATH)));
    router_with(e, tag, HostPolicy::scheme("secmonk"), true)
}

fn req(
    method: &str,
    uri: &str,
    header: Option<&str>,
    body: &[u8],
    ctype: Option<&str>,
) -> Request<Vec<u8>> {
    let mut b = Request::builder()
        .method(method)
        .uri(format!("secmonk://localhost{uri}"));
    if let Some(h) = header {
        b = b.header("X-SecMonk-Request", h);
    }
    if let Some(c) = ctype {
        b = b.header("Content-Type", c);
    }
    b.body(body.to_vec()).unwrap()
}

fn get(r: &Router, uri: &str) -> Response<Vec<u8>> {
    block(r.handle(req("GET", uri, Some("1"), b"", None)))
}

fn block<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn json_of(r: &Response<Vec<u8>>) -> Value {
    serde_json::from_slice(r.body())
        .unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", String::from_utf8_lossy(r.body())))
}

fn assert_security_headers(r: &Response<Vec<u8>>, what: &str) {
    let h = r.headers();
    assert_eq!(h["content-security-policy"], CSP, "{what}: CSP");
    assert_eq!(h["x-content-type-options"], "nosniff", "{what}");
    assert_eq!(h["referrer-policy"], "no-referrer", "{what}");
    assert_eq!(h["cross-origin-opener-policy"], "same-origin", "{what}");
    assert!(h.contains_key("cache-control"), "{what}");
    assert!(h.contains_key("content-type"), "{what}");
}

/// The Python `CSP` constant, spelled out once more so a typo in either place fails.
#[test]
fn csp_is_the_exact_string_of_server_py() {
    assert_eq!(
        CSP,
        "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self'; img-src 'self' data:; \
         connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; \
         object-src 'none'"
    );
    let py = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/secmonk/web/server.py"
    ));
    if let Ok(py) = py {
        // the Python source splits the string over lines: compare the directives
        for directive in CSP.split("; ") {
            assert!(
                py.contains(directive.trim_end_matches(';')),
                "server.py lacks {directive}"
            );
        }
    }
}

#[test]
fn every_catalog_route_answers_with_its_method_and_security_headers() {
    let r = skeleton("routes");
    let cat: Value = serde_json::from_str(CATALOG).unwrap();
    for c in cat["routes"].as_array().unwrap() {
        let (method, path) = (c["method"].as_str().unwrap(), c["path"].as_str().unwrap());
        let url = path.replace(
            "{id}",
            if path.starts_with("/api/jobs") {
                "42"
            } else {
                "A1"
            },
        ) + "?id=A1";
        let body: &[u8] = if path == "/api/jobs" && method == "POST" {
            br#"{"kind":"sync"}"#
        } else {
            b""
        };
        let resp = block(r.handle(req(method, &url, Some("1"), body, Some("application/json"))));
        let what = format!("{method} {path}");
        assert_security_headers(&resp, &what);
        let j = json_of_or_none(&resp);
        let msg = j.as_ref().and_then(|j| j["error"].as_str()).unwrap_or("");
        assert!(
            !msg.starts_with("no such endpoint"),
            "{what} is not registered: {msg}"
        );
        assert_ne!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "{what}");
        assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{what}");
        // the wrong method on a path that has only one answers 404 no such endpoint
        let other = if method == "GET" { "POST" } else { "GET" };
        if !cat["routes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["path"] == path && o["method"] == other)
        {
            let wrong =
                block(r.handle(req(other, &url, Some("1"), b"{}", Some("application/json"))));
            assert_eq!(wrong.status(), StatusCode::NOT_FOUND, "{other} {path}");
            assert_security_headers(&wrong, &format!("{other} {path}"));
        }
    }
    assert_eq!(cat["routes"].as_array().unwrap().len(), ROUTES.len());
}

fn json_of_or_none(r: &Response<Vec<u8>>) -> Option<Value> {
    serde_json::from_slice(r.body()).ok()
}

#[test]
fn api_without_the_header_is_403_on_every_route_and_verb() {
    let r = skeleton("csrf");
    let cat: Value = serde_json::from_str(CATALOG).unwrap();
    for c in cat["routes"].as_array().unwrap() {
        let (method, path) = (c["method"].as_str().unwrap(), c["path"].as_str().unwrap());
        let url = path.replace("{id}", "1");
        for header in [None, Some("0"), Some("")] {
            let resp = block(r.handle(req(method, &url, header, b"{}", Some("application/json"))));
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{method} {path} header {header:?}"
            );
            assert_eq!(
                json_of(&resp),
                json!({"error": "missing X-SecMonk-Request header"})
            );
            assert_security_headers(&resp, "403");
        }
    }
    // unknown /api paths are gated first, like Python
    let resp = block(r.handle(req("GET", "/api/nope", None, b"", None)));
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // static files need no header
    assert_eq!(
        block(r.handle(req("GET", "/", None, b"", None))).status(),
        StatusCode::OK
    );
}

#[test]
fn no_db_error_equals_the_python_example() {
    let r = skeleton("nodb");
    let expected: Value = serde_json::from_str(ERROR_NO_DB).unwrap();
    for path in [
        "/api/overview",
        "/api/assets",
        "/api/unmatched",
        "/api/findings",
        "/api/assets/detail?id=x",
        "/api/vulns/show?id=CVE-1",
        "/api/vulns/search?package=x",
        "/api/assets/x/sbom",
    ] {
        let resp = get(&r, path);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(json_of(&resp), expected, "{path}");
        assert_security_headers(&resp, path);
    }
    let post = block(r.handle(req("POST", "/api/assets/match?id=x", Some("1"), b"", None)));
    assert_eq!(json_of(&post), expected);
}

#[test]
fn error_shape_has_error_hint_code_only() {
    let r = skeleton("shape");
    let missing = get(&r, "/api/assets/detail");
    assert_eq!(
        (missing.status().as_u16(), json_of(&missing)),
        (400, json!({"error": "id: required"}))
    );
    let ni = get(&r, "/api/sources");
    let j = json_of(&ni);
    assert_eq!(ni.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(j["code"], "not-implemented");
    let keys: Vec<_> = j.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["error", "hint", "code"]);
    let unk = get(&r, "/api/nope");
    assert_eq!(
        (unk.status().as_u16(), json_of(&unk)),
        (404, json!({"error": "no such endpoint /api/nope"}))
    );
    let job = get(&r, "/api/jobs/7");
    assert_eq!(
        (job.status().as_u16(), json_of(&job)),
        (404, json!({"error": "no job 7"}))
    );
    let notnum = get(&r, "/api/jobs/x");
    assert_eq!(
        json_of(&notnum),
        json!({"error": "no such endpoint /api/jobs/x"})
    );
}

#[test]
fn validation_messages_are_pythons() {
    let r = skeleton("validation");
    let cases = [
        ("/api/findings?limit=0", "limit: expected 1..5000, got 0"),
        (
            "/api/findings?limit=abc",
            "limit: expected an integer, got 'abc'",
        ),
        (
            "/api/findings?priority=P9",
            "priority: expected one of P1, P2, P3, P4",
        ),
        (
            "/api/vulns/search?limit=1001",
            "limit: expected 1..1000, got 1001",
        ),
        ("/api/vulns/show", "id: required"),
        (
            "/api/assets/detail?id=a&limit=5001",
            "limit: expected 1..5000, got 5001",
        ),
        ("/api/jobs?kind=other", "kind: expected 'scan' or 'sync'"),
        ("/api/jobs?limit=201", "limit: expected 1..200, got 201"),
        ("/api/assets//sbom", "no such endpoint /api/assets//sbom"),
    ];
    for (uri, msg) in cases {
        let resp = get(&r, uri);
        assert_eq!(json_of(&resp)["error"], msg, "{uri}");
        assert!(matches!(resp.status().as_u16(), 400 | 404), "{uri}");
    }
    let m = block(r.handle(req("POST", "/api/assets/match", Some("1"), b"", None)));
    assert_eq!(json_of(&m)["error"], "id: required");
}

#[test]
fn statics_and_traversal() {
    let r = skeleton("static");
    let index = block(r.handle(req("GET", "/", None, b"", None)));
    assert_eq!(index.status(), StatusCode::OK);
    assert_eq!(index.headers()["content-type"], "text/html; charset=utf-8");
    assert_eq!(index.headers()["cache-control"], "no-cache");
    assert_security_headers(&index, "index");
    // the overlay page, not static_dir/index.html
    let html = String::from_utf8(index.body().clone()).unwrap();
    assert!(html.contains("/rust-ui/transport.js") && html.contains("/static/js/secmonk-views.js"));
    let js = get(&r, "/static/js/boot.js");
    assert_eq!(
        js.headers()["content-type"],
        "text/javascript; charset=utf-8"
    );
    for bad in [
        "/static/../secret.txt",
        "/static/%2e%2e/secret.txt",
        "/static/js/../../secret.txt",
        "/static/%2e%2e%2fsecret.txt",
        "/static//etc/passwd",
        "/static/js%5c..%5c..%5csecret.txt",
        "/static/nope.js",
        "/static/js",
        "/static/",
    ] {
        let resp = block(r.handle(req("GET", bad, None, b"", None)));
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{bad}");
        assert_eq!(json_of(&resp), json!({"error": "not found"}), "{bad}");
        assert_security_headers(&resp, bad);
    }
    // deep link falls back to the app; a missing file with an extension does not
    assert_eq!(
        block(r.handle(req("GET", "/assets/42", None, b"", None))).body(),
        index.body()
    );
    assert_eq!(
        block(r.handle(req("GET", "/favicon.ico", None, b"", None))).status(),
        StatusCode::NOT_FOUND
    );
}

#[test]
fn methods_and_host() {
    let r = skeleton("methods");
    for m in ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
        let resp = block(r.handle(req(m, "/api/meta", Some("1"), b"", None)));
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "{m}");
        assert_eq!(json_of(&resp), json!({"error": "method not allowed"}));
        assert_security_headers(&resp, m);
    }
    let post_static = block(r.handle(req("POST", "/", Some("1"), b"", None)));
    assert_eq!(json_of(&post_static), json!({"error": "not found"}));
    // Host / authority
    for uri in [
        "secmonk://evil.example/api/meta",
        "http://localhost:8765/api/meta",
        "secmonk://localhost.evil.example/",
    ] {
        let q = Request::builder()
            .method("GET")
            .uri(uri)
            .header("X-SecMonk-Request", "1")
            .body(vec![])
            .unwrap();
        let resp = block(r.handle(q));
        assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST, "{uri}");
        assert_eq!(json_of(&resp)["error"], "unexpected Host header");
        assert_security_headers(&resp, uri);
    }
    let win = Request::builder()
        .uri("http://secmonk.localhost/api/meta")
        .header("X-SecMonk-Request", "1")
        .body(vec![])
        .unwrap();
    assert_eq!(block(r.handle(win)).status(), StatusCode::OK);
    let relative = Request::builder()
        .uri("/api/meta")
        .header("X-SecMonk-Request", "1")
        .body(vec![])
        .unwrap();
    assert_eq!(
        block(r.handle(relative)).status(),
        StatusCode::MISDIRECTED_REQUEST,
        "no authority at all"
    );
    let spoof = Request::builder()
        .uri("secmonk://localhost/api/meta")
        .header("Host", "evil.example")
        .header("X-SecMonk-Request", "1")
        .body(vec![])
        .unwrap();
    assert_eq!(
        block(r.handle(spoof)).status(),
        StatusCode::MISDIRECTED_REQUEST,
        "a conflicting Host header"
    );
}

#[test]
fn http_binding_applies_the_python_host_rules() {
    let e = Arc::new(SkeletonEngine::new(EngineInfo::new("0.1.0", STATE_PATH)));
    let r = router_with(e, "http", HostPolicy::http("127.0.0.1", 8765, &[]), true);
    let ok = Request::builder()
        .uri("http://127.0.0.1:8765/api/meta")
        .header("X-SecMonk-Request", "1")
        .body(vec![])
        .unwrap();
    let resp = block(r.handle(ok));
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_of(&resp)["bind"], "http://127.0.0.1:8765");
    for host in [
        "evil.example:8765",
        "127.0.0.1",
        "127.0.0.1:9999",
        "10.1.1.1:8765",
    ] {
        let q = Request::builder()
            .uri(format!("http://{host}/api/meta"))
            .header("X-SecMonk-Request", "1")
            .body(vec![])
            .unwrap();
        assert_eq!(
            block(r.handle(q)).status(),
            StatusCode::MISDIRECTED_REQUEST,
            "{host}"
        );
    }
}

#[test]
fn meta_adds_transport_facts() {
    let r = skeleton("meta");
    let m = json_of(&get(&r, "/api/meta"));
    assert_eq!(m["bind"], "secmonk://localhost");
    assert_eq!(m["actions"], true);
    assert_eq!(m["db"], json!({"path": STATE_PATH, "exists": false}));
    for k in [
        "version", "mode", "platform", "db", "bind", "features", "actions",
    ] {
        assert!(m.get(k).is_some(), "{k}");
    }
}

#[test]
fn actions_gate_and_job_body_checks() {
    let e = Arc::new(SkeletonEngine::new(EngineInfo::new("0.1.0", STATE_PATH)));
    let off = router_with(e, "actions", HostPolicy::scheme("secmonk"), false);
    for path in [
        "/api/discover",
        "/api/k8s/kubeconfigs",
        "/api/docker/contexts",
        "/api/docker/containers",
    ] {
        let resp = get(&off, path);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(
            json_of(&resp)["error"],
            "actions are disabled on this server"
        );
    }
    let job = |body: &[u8], ctype: Option<&str>| {
        json_of_status(block(off.handle(req(
            "POST",
            "/api/jobs",
            Some("1"),
            body,
            ctype,
        ))))
    };
    assert_eq!(job(b"{}", Some("application/json")).0, 403);
    // body checks come before the gate, as in Python
    assert_eq!(job(b"{}", Some("text/plain")).0, 415);
    assert_eq!(job(b"{}", None).0, 415);
    assert_eq!(
        job(b"[]", Some("application/json")),
        (400, json!({"error": "request body must be a JSON object"}))
    );
    assert_eq!(
        job(b"{nope", Some("application/json")),
        (400, json!({"error": "request body is not valid JSON"}))
    );
    let big = vec![b' '; 64 * 1024 + 1];
    assert_eq!(
        job(&big, Some("application/json")),
        (413, json!({"error": "request body over 65536 bytes"}))
    );
    assert_eq!(
        job(b"{}", Some("Application/JSON; charset=utf-8")).0,
        403,
        "content type is case-insensitive, params ignored"
    );
    // reads that do not contact anything stay available
    assert_eq!(get(&off, "/api/meta").status(), StatusCode::OK);
    assert_eq!(json_of(&get(&off, "/api/meta"))["actions"], false);
}

fn json_of_status(r: Response<Vec<u8>>) -> (u16, Value) {
    (r.status().as_u16(), json_of(&r))
}

/// An engine that echoes what it received, to check the parameter plumbing.
struct Echo;

macro_rules! echo_engine {
    ($ty:ty, meta($self_m:ident) $meta:block, sbom($self_s:ident, $sid:ident, $sv:ident) $sbom:block) => {
        #[async_trait]
        impl EngineService for $ty {
            async fn meta(&$self_m) -> EngineResult<Value> $meta
            async fn sbom(&$self_s, $sid: &str, $sv: bool) -> EngineResult<Value> $sbom
            async fn processes(&self, refresh: bool) -> EngineResult<Value> { echo_val("processes", format!("{:?}", (refresh,))) }
            async fn processes_watch(&self) -> EngineResult<Value> { echo_val("processes_watch", String::new()) }
            async fn processes_save(&self) -> EngineResult<Value> { echo_val("processes_save", String::new()) }
            async fn overview(&self) -> EngineResult<Value> { echo_val("overview", String::new()) }
            async fn assets(&self) -> EngineResult<Value> { echo_val("assets", String::new()) }
            async fn asset_detail(&self, id: &str, limit: u32) -> EngineResult<Value> { echo_val("asset_detail", format!("{:?}", (id, limit))) }
            async fn match_asset(&self, id: &str) -> EngineResult<Value> { echo_val("match_asset", format!("{:?}", (id,))) }
            async fn unmatched(&self) -> EngineResult<Value> { echo_val("unmatched", String::new()) }
            async fn findings(&self, q: &FindingsQuery) -> EngineResult<Value> { echo_val("findings", format!("{q:?}")) }
            async fn vuln_show(&self, id: &str, raw: bool) -> EngineResult<Value> { echo_val("vuln_show", format!("{:?}", (id, raw))) }
            async fn vuln_search(&self, q: &VulnSearchQuery) -> EngineResult<Value> { echo_val("vuln_search", format!("{q:?}")) }
            async fn sources(&self) -> EngineResult<Value> { echo_val("sources", String::new()) }
            async fn collectors(&self) -> EngineResult<Value> { echo_val("collectors", String::new()) }
            async fn jobs_list(&self, q: &JobsQuery) -> EngineResult<Value> { echo_val("jobs_list", format!("{q:?}")) }
            async fn job_get(&self, id: u64) -> EngineResult<Value> { echo_val("job_get", format!("{:?}", (id,))) }
            async fn job_start(&self, body: JsonObject) -> EngineResult<Value> { echo_val("job_start", format!("{body:?}")) }
            async fn discover(&self, q: &DiscoverQuery) -> EngineResult<Value> { echo_val("discover", format!("{q:?}")) }
            async fn k8s_kubeconfigs(&self) -> EngineResult<Value> { echo_val("k8s_kubeconfigs", String::new()) }
            async fn docker_contexts(&self) -> EngineResult<Value> { echo_val("docker_contexts", String::new()) }
            async fn docker_containers(&self, q: &DockerListQuery) -> EngineResult<Value> { echo_val("docker_containers", format!("{q:?}")) }
        }
    };
}

fn echo_val(method: &str, args: String) -> EngineResult<Value> {
    Ok(json!({"method": method, "args": args}))
}

echo_engine!(Echo,
    meta(self) { Ok(json!({"version": "t", "mode": "live", "platform": "darwin", "db": {"path": "p", "exists": true}, "features": []})) },
    sbom(self, id, with_vulns) { Ok(json!({"bomFormat": "CycloneDX", "id": id, "vulns": with_vulns})) }
);

fn echo(tag: &str) -> Router {
    router_with(Arc::new(Echo), tag, HostPolicy::scheme("secmonk"), true)
}

fn args(r: &Router, uri: &str) -> String {
    json_of(&get(r, uri))["args"].as_str().unwrap().to_owned()
}

#[test]
fn parameters_reach_the_engine_validated() {
    let r = echo("plumb");
    assert_eq!(args(&r, "/api/processes?refresh=1"), "(true,)");
    assert_eq!(args(&r, "/api/processes?refresh=1&refresh=1"), "(false,)");
    assert_eq!(
        args(&r, "/api/assets/detail?id=%20a%20&limit=7"),
        "(\"a\", 7)"
    );
    assert_eq!(args(&r, "/api/assets/detail?id=a"), "(\"a\", 5000)");
    assert!(args(&r, "/api/findings?priority=p2&asset=x&all=yes&limit=9").contains(
        "FindingsQuery { priority: Some(\"P2\"), asset: Some(\"x\"), include_closed: true, fixable: false, \
         hide_minor: false, hide_deferred: false, limit: 9 }"
    ));
    assert!(args(&r, "/api/findings").contains("limit: 200"));
    assert!(args(&r, "/api/vulns/search?package=lodash&ecosystem=npm&version=4.17.0").contains(
        "VulnSearchQuery { package: Some(\"lodash\"), ecosystem: Some(\"npm\"), product: None, version: Some(\"4.17.0\"), limit: 50 }"
    ));
    assert!(
        args(&r, "/api/jobs?kind=sync&limit=3")
            .contains("JobsQuery { kind: Some(Sync), limit: 3 }")
    );
    assert_eq!(args(&r, "/api/jobs/12"), "(12,)");
    assert!(
        args(
            &r,
            "/api/discover?target=ssh://u@h&opt=connect_timeout%3D5&opt=%20"
        )
        .contains(
            "DiscoverQuery { target: Some(\"ssh://u@h\"), options: [\"connect_timeout=5\"] }"
        )
    );
    assert!(args(&r, "/api/docker/containers?host=tcp://h:2376&all=1&match=web&opt=tls_verify%3D1").contains(
        "DockerListQuery { host: Some(\"tcp://h:2376\"), context: None, all: true, selector: Some(\"web\"), \
         options: [\"tls_verify=1\"] }"
    ));
    let post = block(r.handle(req(
        "POST",
        "/api/jobs",
        Some("1"),
        br#"{"kind":"scan","target":"x"}"#,
        Some("application/json"),
    )));
    assert_eq!(post.status(), StatusCode::ACCEPTED);
    assert!(
        json_of(&post)["args"]
            .as_str()
            .unwrap()
            .contains("\"kind\": String(\"scan\")")
    );
}

#[test]
fn browser_option_policy_is_enforced_before_the_engine() {
    let r = echo("policy");
    let post = |body: &str| {
        let resp = block(r.handle(req(
            "POST",
            "/api/jobs",
            Some("1"),
            body.as_bytes(),
            Some("application/json"),
        )));
        (resp.status().as_u16(), json_of(&resp))
    };
    let (st, v) = post(
        r#"{"kind":"scan","collector":"ssh","target":"u@h","options":["ssh_bin=/tmp/x","depth=1"]}"#,
    );
    assert_eq!(st, 400);
    assert_eq!(
        v["error"],
        "options: option not accepted from the browser: ssh_bin"
    );
    assert!(v["hint"].as_str().unwrap().contains("secmonk CLI"));
    let (st, v) = post(
        r#"{"kind":"scan","items":[{"collector":"fs"},{"collector":"k8s","options":"kubectl=/x\nssh_config=/y"}]}"#,
    );
    assert_eq!(st, 400);
    assert_eq!(
        v["error"],
        "items[2]: option not accepted from the browser: kubectl, ssh_config"
    );
    let (st, _) = post(r#"{"kind":"scan","collector":"fs","options":["depth=2"]}"#);
    assert_eq!(st, 202);

    for (uri, msg) in [
        (
            "/api/discover?opt=ssh_option%3DProxyCommand%3Dx",
            "opt: not accepted here: ssh_option",
        ),
        (
            "/api/discover?opt=transport%3Dx&opt=ssh_bin%3Dy",
            "opt: not accepted here: ssh_bin, transport",
        ),
        (
            "/api/docker/containers?opt=socket%3D/var/run/docker.sock",
            "opt: not accepted here: socket",
        ),
        (
            "/api/docker/containers?opt=ssh_bin%3Dx",
            "opt: not accepted here: ssh_bin",
        ),
        (
            "/api/discover?opt=bare",
            "opt: expected key=value, got 'bare'",
        ),
    ] {
        let resp = get(&r, uri);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(json_of(&resp)["error"], msg, "{uri}");
    }
    assert_eq!(
        get(&r, "/api/discover?opt=identity%3D/k&opt=sudo%3Dtrue").status(),
        StatusCode::OK
    );
    assert_eq!(
        get(&r, "/api/docker/containers?opt=tls_verify%3D1").status(),
        StatusCode::OK
    );
}

#[test]
fn probe_failures_map_to_python_statuses() {
    use secmonk_engine::{EngineError, ErrorKind};
    struct Failing(EngineError);
    #[async_trait]
    impl EngineService for Failing {
        async fn meta(&self) -> EngineResult<Value> {
            Ok(json!({}))
        }
        async fn processes(&self, _: bool) -> EngineResult<Value> {
            unreachable!()
        }
        async fn processes_watch(&self) -> EngineResult<Value> {
            unreachable!()
        }
        async fn processes_save(&self) -> EngineResult<Value> {
            unreachable!()
        }
        async fn overview(&self) -> EngineResult<Value> {
            unreachable!()
        }
        async fn assets(&self) -> EngineResult<Value> {
            unreachable!()
        }
        async fn asset_detail(&self, _: &str, _: u32) -> EngineResult<Value> {
            unreachable!()
        }
        async fn sbom(&self, _: &str, _: bool) -> EngineResult<Value> {
            unreachable!()
        }
        async fn match_asset(&self, _: &str) -> EngineResult<Value> {
            unreachable!()
        }
        async fn unmatched(&self) -> EngineResult<Value> {
            unreachable!()
        }
        async fn findings(&self, _: &FindingsQuery) -> EngineResult<Value> {
            unreachable!()
        }
        async fn vuln_show(&self, _: &str, _: bool) -> EngineResult<Value> {
            unreachable!()
        }
        async fn vuln_search(&self, _: &VulnSearchQuery) -> EngineResult<Value> {
            unreachable!()
        }
        async fn sources(&self) -> EngineResult<Value> {
            unreachable!()
        }
        async fn collectors(&self) -> EngineResult<Value> {
            unreachable!()
        }
        async fn jobs_list(&self, _: &JobsQuery) -> EngineResult<Value> {
            unreachable!()
        }
        async fn job_get(&self, _: u64) -> EngineResult<Value> {
            unreachable!()
        }
        async fn job_start(&self, _: JsonObject) -> EngineResult<Value> {
            unreachable!()
        }
        async fn discover(&self, _: &DiscoverQuery) -> EngineResult<Value> {
            Err(self.0.clone())
        }
        async fn k8s_kubeconfigs(&self) -> EngineResult<Value> {
            Err(self.0.clone())
        }
        async fn docker_contexts(&self) -> EngineResult<Value> {
            Err(self.0.clone())
        }
        async fn docker_containers(&self, _: &DockerListQuery) -> EngineResult<Value> {
            Err(self.0.clone())
        }
    }
    let run = |e: EngineError, uri: &str| {
        let r = router_with(
            Arc::new(Failing(e)),
            "probe-fail",
            HostPolicy::scheme("secmonk"),
            true,
        );
        let resp = get(&r, uri);
        (resp.status().as_u16(), json_of(&resp))
    };
    let k8s = |reason: &str| {
        let mut e = EngineError::new(ErrorKind::HostUnreachable, "KubectlError: x");
        e.reason = Some(reason.to_owned());
        e
    };
    let (st, v) = run(
        {
            let mut e =
                EngineError::new(ErrorKind::CollectError, "KubectlError: kubectl not found");
            e.reason = Some("kubectl-missing".into());
            e
        },
        "/api/discover?target=k8s://prod",
    );
    assert_eq!((st, v["code"].as_str()), (424, Some("kubectl-missing")));
    let (st, v) = run(k8s("k8s-denied"), "/api/discover?target=k8s://prod");
    assert_eq!((st, v["code"].as_str()), (502, Some("k8s-denied")));
    let (st, v) = run(k8s("k8s-unreachable"), "/api/discover?target=k8s://prod");
    assert_eq!((st, v["code"].as_str()), (502, Some("k8s-unreachable")));
    let (st, v) = run(
        EngineError::new(ErrorKind::HostUnreachable, "SSHError: nope"),
        "/api/discover?target=u@h",
    );
    assert_eq!(
        (st, v["error"].as_str()),
        (502, Some("cannot explore the host (SSHError)"))
    );
    let (st, v) = run(
        EngineError::new(ErrorKind::EngineUnreachable, "RuntimeError: refused"),
        "/api/docker/contexts",
    );
    assert_eq!(
        (st, v["error"].as_str()),
        (502, Some("cannot reach the Docker engine (RuntimeError)"))
    );
    let (st, _) = run(
        EngineError::new(ErrorKind::InvalidParams, "ValueError: bad"),
        "/api/docker/containers?host=x",
    );
    assert_eq!(st, 400);
    let (st, v) = run(
        EngineError::new(ErrorKind::Internal, "OSError: no"),
        "/api/k8s/kubeconfigs",
    );
    assert_eq!(
        (st, v["error"].as_str()),
        (500, Some("cannot list kubeconfigs (OSError)"))
    );
    let (st, _) = run(
        EngineError::new(ErrorKind::ModuleUnavailable, "py-probe failed"),
        "/api/discover",
    );
    assert_eq!(st, 503);
}

#[test]
fn sbom_is_a_download() {
    let r = echo("sbom");
    let resp = get(&r, "/api/assets/host%3A1%2Fweb%20app%2F/sbom?vulns=1");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()["content-type"],
        "application/vnd.cyclonedx+json; charset=utf-8"
    );
    assert_eq!(
        resp.headers()["content-disposition"],
        "attachment; filename=\"host_1_web_app.cdx.json\""
    );
    assert_eq!(resp.headers()["cache-control"], "no-store");
    assert_security_headers(&resp, "sbom");
    let j = json_of(&resp);
    assert_eq!(
        (j["id"].as_str().unwrap(), j["vulns"].as_bool().unwrap()),
        ("host:1/web app/", true)
    );
    let weird = get(&r, "/api/assets/%2F%2F/sbom");
    assert_eq!(
        weird.headers()["content-disposition"],
        "attachment; filename=\"asset.cdx.json\""
    );
}

#[test]
fn engine_errors_become_api_errors() {
    use secmonk_engine::{EngineError, ErrorKind};
    struct Failing(ErrorKind);
    echo_engine!(Failing,
        meta(self) { Err(EngineError::new(self.0, "boom").with_hint("see logs")) },
        sbom(self, _id, _v) { Ok(json!({})) }
    );
    for (kind, status, code) in [
        (ErrorKind::InvalidParams, 400, None),
        (ErrorKind::UnknownAsset, 404, Some("unknown-asset")),
        (ErrorKind::UnknownVuln, 404, Some("unknown-vuln")),
        (ErrorKind::Busy, 409, None),
        (ErrorKind::UnsupportedPlatform, 503, None),
        (ErrorKind::CollectError, 503, None),
        (ErrorKind::EngineUnreachable, 502, None),
        (ErrorKind::HostUnreachable, 502, None),
        (ErrorKind::ModuleUnavailable, 503, None),
        (ErrorKind::ModuleCrashed, 503, None),
        (ErrorKind::Timeout, 503, None),
        (ErrorKind::Internal, 500, None),
    ] {
        let r = router_with(
            Arc::new(Failing(kind)),
            "errs",
            HostPolicy::scheme("secmonk"),
            true,
        );
        let resp = get(&r, "/api/meta");
        let j = json_of(&resp);
        assert_eq!(resp.status().as_u16(), status, "{kind:?}");
        assert_eq!(j["code"].as_str(), code, "{kind:?}");
        assert_eq!(
            (j["error"].as_str(), j["hint"].as_str()),
            (Some("boom"), Some("see logs"))
        );
    }
}

#[allow(dead_code)]
fn _method_is_used(_: Method) {}
