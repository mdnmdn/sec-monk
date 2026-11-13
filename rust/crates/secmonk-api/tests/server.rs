//! The server layer over real sockets: overlay serving, `/auth/*`, scopes, rate limit, mounts, body limits,
//! TLS and the exposure rules.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use http::{Request, Response, StatusCode};
use secmonk_api::{
    CSP, HostPolicy, Mount, Router, RouterOptions, Server, StaticDir, TlsFiles, accept_loop,
    check_exposure, error_response, json_response, tls_acceptor,
};
use secmonk_auth::{Authenticator, JwtSigner, KeyStore, Principal, Scope, Scopes};
use secmonk_engine::{EngineInfo, SkeletonEngine};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

struct Echo;

#[async_trait]
impl Mount for Echo {
    fn prefix(&self) -> &'static str {
        "/node/v1/"
    }
    async fn handle(
        &self,
        req: Request<Vec<u8>>,
        principal: Option<Principal>,
    ) -> Response<Vec<u8>> {
        if req.uri().path().ends_with("/needs-match")
            && !principal
                .as_ref()
                .is_some_and(|p| p.scopes.contains(Scope::Match))
        {
            return error_response(&secmonk_api::ApiError::new(
                StatusCode::FORBIDDEN,
                "forbidden",
            ));
        }
        json_response(
            StatusCode::OK,
            &json!({"key": principal.map(|p| p.key_id), "len": req.body().len()}),
        )
    }
}

struct Keys {
    ui: String,
    ro: String,
    node: String,
}

struct Fixture {
    addr: SocketAddr,
    keys: Keys,
    tls: bool,
}

fn tls_files() -> TlsFiles {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    TlsFiles {
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
    }
}

async fn start(auth: bool, tls: bool, rate: u32) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let engine = Arc::new(SkeletonEngine::new(EngineInfo::new(
        "0.1.0",
        "/x/state.sqlite3",
    )));
    let router = Arc::new(Router::new(
        engine,
        RouterOptions {
            static_dir: StaticDir::new(std::env::temp_dir().join("secmonk-server-none")),
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
        ui: mk("ui", &["ui"]),
        ro: mk("ro", &["ui:read"]),
        node: mk("node", &["match"]),
    };
    let mut server = Server::new(router).with_mount(Arc::new(Echo));
    if auth {
        let signer = JwtSigner::new(vec![7; 32], 3600);
        server = server.with_auth(Arc::new(Authenticator::new(store, signer, rate)));
    }
    let acceptor = tls.then(|| tls_acceptor(&tls_files()).unwrap());
    tokio::spawn(accept_loop(
        Arc::new(server),
        listener,
        acceptor,
        std::time::Duration::from_secs(5),
        16,
    ));
    Fixture { addr, keys, tls }
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("not JSON: {:?}", self.text()))
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn client_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let pem = std::fs::read(tls_files().cert).unwrap();
    for c in rustls_pemfile_certs(&pem) {
        roots.add(c).unwrap();
    }
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// The certificates of a PEM file (a minimal parser: the fixture is one `CERTIFICATE` block).
fn rustls_pemfile_certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    use rustls_pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem)
        .map(|c| c.unwrap())
        .collect()
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, raw: Vec<u8>) -> Resp {
    s.write_all(&raw).await.unwrap();
    let mut buf = Vec::new();
    // a TLS peer may close without close_notify after the body: keep what arrived
    let _ = s.read_to_end(&mut buf).await;
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no response head in {:?}", String::from_utf8_lossy(&buf)));
    let head = String::from_utf8_lossy(&buf[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Resp {
        status,
        headers,
        body: buf[split + 4..].to_vec(),
    }
}

impl Fixture {
    async fn call(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Resp {
        let mut raw = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n",
            self.addr.port(),
            body.len()
        );
        for (k, v) in headers {
            raw.push_str(&format!("{k}: {v}\r\n"));
        }
        raw.push_str("\r\n");
        let mut bytes = raw.into_bytes();
        bytes.extend_from_slice(body);
        let tcp = TcpStream::connect(self.addr).await.unwrap();
        if self.tls {
            let name = ServerName::try_from("localhost").unwrap();
            let s = TlsConnector::from(client_config())
                .connect(name, tcp)
                .await
                .unwrap();
            exchange(s, bytes).await
        } else {
            exchange(tcp, bytes).await
        }
    }

    async fn get(&self, path: &str, headers: &[(&str, &str)]) -> Resp {
        self.call("GET", path, headers, b"").await
    }

    async fn token(&self, key: &str) -> String {
        let body = json!({"api_key": key}).to_string();
        let r = self
            .call(
                "POST",
                "/auth/token",
                &[("Content-Type", "application/json")],
                body.as_bytes(),
            )
            .await;
        assert_eq!(r.status, 200, "{}", r.text());
        r.json()["token"].as_str().unwrap().to_owned()
    }
}

const CSRF: (&str, &str) = ("X-SecMonk-Request", "1");

#[tokio::test]
async fn overlay_is_served_with_the_csp() {
    let f = start(false, false, 600).await;
    for path in ["/", "/index.html"] {
        let r = f.get(path, &[]).await;
        assert_eq!(r.status, 200, "{path}");
        assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
        assert_eq!(r.header("content-security-policy"), Some(CSP));
        assert!(r.text().contains("/rust-ui/transport.js"));
    }
    let js = f.get("/rust-ui/transport.js", &[]).await;
    assert_eq!(js.status, 200);
    assert_eq!(
        js.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );
    assert_eq!(js.header("content-security-policy"), Some(CSP));
    assert!(js.text().contains("SecMonkTransport"));
    let css = f.get("/rust-ui/rust-ui.css", &[]).await;
    assert_eq!(css.header("content-type"), Some("text/css; charset=utf-8"));
    for name in ["login.js", "boot.js"] {
        assert_eq!(f.get(&format!("/rust-ui/{name}"), &[]).await.status, 200);
    }
    assert_eq!(f.get("/rust-ui/nope.js", &[]).await.status, 404);
    assert_eq!(f.get("/rust-ui/../secret", &[]).await.status, 404);
}

#[tokio::test]
async fn auth_info_in_both_modes() {
    let off = start(false, false, 600).await;
    assert_eq!(
        off.get("/auth/info", &[]).await.json(),
        json!({"auth": false})
    );
    let on = start(true, false, 600).await;
    let r = on.get("/auth/info", &[]).await;
    assert_eq!(r.json()["auth"], json!(true));
    assert_eq!(r.json()["providers"], json!(["api_key"]));
    assert_eq!(r.json()["login_methods"], json!(["api_key"]));
    assert_eq!(r.header("content-security-policy"), Some(CSP));
    assert_eq!(on.call("POST", "/auth/info", &[], b"").await.status, 405);
    assert_eq!(on.get("/auth/other", &[]).await.status, 404);
    // the UI files stay public with auth on
    assert_eq!(on.get("/", &[]).await.status, 200);
    // auth off: no exchange, /api open
    assert_eq!(
        off.call("POST", "/auth/token", &[], b"{}").await.status,
        404
    );
    assert_eq!(off.get("/api/meta", &[CSRF]).await.status, 200);
}

#[tokio::test]
async fn token_exchange_and_bearer_requests() {
    let f = start(true, false, 600).await;
    let body = json!({"api_key": f.keys.ui}).to_string();
    let r = f.call("POST", "/auth/token", &[], body.as_bytes()).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("cache-control"), Some("no-store"));
    let j = r.json();
    assert_eq!(j["token_type"], "Bearer");
    assert!(j["expires_at"].as_u64().unwrap() > 1_700_000_000);
    assert_eq!(j["scopes"], json!(["ui:read", "ui:actions"]));
    let token = j["token"].as_str().unwrap().to_owned();

    // no token, bad token: 401 with the challenge, the same body for every reason
    let none = f.get("/api/meta", &[CSRF]).await;
    assert_eq!(none.status, 401);
    assert_eq!(none.header("www-authenticate"), Some("Bearer"));
    assert_eq!(none.json(), json!({"error": "authentication required"}));
    let bad = f
        .get(
            "/api/meta",
            &[CSRF, ("Authorization", "Bearer abc.def.ghi")],
        )
        .await;
    assert_eq!(bad.status, 401);
    assert_eq!(bad.json(), json!({"error": "invalid credentials"}));

    let ok = f
        .get(
            "/api/meta",
            &[CSRF, ("Authorization", &format!("Bearer {token}"))],
        )
        .await;
    assert_eq!(ok.status, 200, "{}", ok.text());
    assert!(ok.json().get("version").is_some() || ok.json().is_object());
    // the CSRF header is still the router's rule behind the login
    let nocsrf = f
        .get(
            "/api/meta",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
    assert_eq!(nocsrf.status, 403);
    // machine clients: the key itself
    let k = f
        .get(
            "/api/meta",
            &[CSRF, ("Authorization", &format!("ApiKey {}", f.keys.ui))],
        )
        .await;
    assert_eq!(k.status, 200);
    // the exchange also takes the header
    let via_header = f
        .call(
            "POST",
            "/auth/token",
            &[("Authorization", &format!("ApiKey {}", f.keys.ui))],
            b"",
        )
        .await;
    assert_eq!(via_header.status, 200);
}

#[tokio::test]
async fn token_exchange_failures_and_throttle() {
    let f = start(true, false, 600).await;
    let wrong = "smk_00000000_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for key in [wrong, "garbage", ""] {
        let r = f
            .call(
                "POST",
                "/auth/token",
                &[],
                json!({"api_key": key}).to_string().as_bytes(),
            )
            .await;
        assert_eq!(r.status, 401, "{key}");
        assert_eq!(r.json(), json!({"error": "invalid credentials"}));
        assert_eq!(r.header("www-authenticate"), Some("Bearer"));
        assert_eq!(r.header("cache-control"), Some("no-store"));
    }
    assert_eq!(
        f.call("POST", "/auth/token", &[], b"not json").await.status,
        400
    );
    assert_eq!(f.get("/auth/token", &[]).await.status, 405);
    let big = vec![b' '; 5000];
    assert_eq!(f.call("POST", "/auth/token", &[], &big).await.status, 413);
    // ten failures block the address, even for the right key
    for _ in 0..8 {
        f.call(
            "POST",
            "/auth/token",
            &[],
            json!({"api_key": wrong}).to_string().as_bytes(),
        )
        .await;
    }
    let blocked = f
        .call(
            "POST",
            "/auth/token",
            &[],
            json!({"api_key": f.keys.ui}).to_string().as_bytes(),
        )
        .await;
    assert_eq!(blocked.status, 429, "{}", blocked.text());
    assert_eq!(blocked.header("retry-after"), Some("60"));
}

#[tokio::test]
async fn scopes_guard_the_api() {
    let f = start(true, false, 600).await;
    let ro = f.token(&f.keys.ro).await;
    let node = f.token(&f.keys.node).await;
    let bearer = |t: &str| format!("Bearer {t}");
    assert_eq!(
        f.get("/api/meta", &[CSRF, ("Authorization", &bearer(&ro))])
            .await
            .status,
        200
    );
    let lacks_read = f
        .get("/api/meta", &[CSRF, ("Authorization", &bearer(&node))])
        .await;
    assert_eq!(lacks_read.status, 403);
    let j = lacks_read.json();
    assert_eq!(j["error"], "forbidden");
    assert!(j["hint"].as_str().unwrap().contains("ui:read"));
    // POST needs ui:actions
    let post = f
        .call(
            "POST",
            "/api/jobs",
            &[
                CSRF,
                ("Authorization", &bearer(&ro)),
                ("Content-Type", "application/json"),
            ],
            b"{}",
        )
        .await;
    assert_eq!(post.status, 403);
    assert!(post.json()["hint"].as_str().unwrap().contains("ui:actions"));
    let ui = f.token(&f.keys.ui).await;
    let allowed = f
        .call(
            "POST",
            "/api/jobs",
            &[
                CSRF,
                ("Authorization", &bearer(&ui)),
                ("Content-Type", "application/json"),
            ],
            b"{}",
        )
        .await;
    assert_ne!(allowed.status, 403, "{}", allowed.text());
    assert_ne!(allowed.status, 401);
}

#[tokio::test]
async fn rate_limit_per_principal() {
    let f = start(true, false, 3).await;
    let h = format!("ApiKey {}", f.keys.ui);
    let mut statuses = Vec::new();
    for _ in 0..6 {
        statuses.push(f.get("/api/meta", &[CSRF, ("Authorization", &h)]).await);
    }
    assert!(statuses[..3].iter().all(|r| r.status == 200));
    let limited = statuses.iter().find(|r| r.status == 429).expect("a 429");
    assert_eq!(limited.header("retry-after"), Some("60"));
    assert_eq!(limited.json(), json!({"error": "rate limited"}));
    // another principal has its own bucket
    let other = f
        .get(
            "/api/meta",
            &[CSRF, ("Authorization", &format!("ApiKey {}", f.keys.ro))],
        )
        .await;
    assert_eq!(other.status, 200);
}

#[tokio::test]
async fn mounts_get_the_principal_and_bigger_bodies() {
    let f = start(true, false, 600).await;
    let key = &f.keys.node;
    let auth = format!("ApiKey {key}");
    // authenticated, no CSRF header needed
    let r = f
        .call("POST", "/node/v1/echo", &[("Authorization", &auth)], b"{}")
        .await;
    assert_eq!(r.status, 200);
    let who = r.json()["key"].as_str().unwrap().to_owned();
    assert!(key.starts_with(&format!("smk_{who}_")));
    // anonymous: refused before the mount
    assert_eq!(
        f.call("POST", "/node/v1/echo", &[], b"{}").await.status,
        401
    );
    // 1 MiB, far over the /api limit
    let big = vec![b'x'; 1 << 20];
    let r = f
        .call("POST", "/node/v1/echo", &[("Authorization", &auth)], &big)
        .await;
    assert_eq!((r.status, r.json()["len"].as_u64()), (200, Some(1 << 20)));
    // over 4 MiB: 413 without reading it all
    let r = f
        .call(
            "POST",
            "/node/v1/echo",
            &[("Authorization", &auth)],
            &vec![b'x'; (4 << 20) + 10],
        )
        .await;
    assert_eq!(r.status, 413);
    // the mount's own scope check
    assert_eq!(
        f.get("/node/v1/needs-match", &[("Authorization", &auth)])
            .await
            .status,
        200
    );
    let ui = format!("ApiKey {}", f.keys.ui);
    assert_eq!(
        f.get("/node/v1/needs-match", &[("Authorization", &ui)])
            .await
            .status,
        403
    );
    // /api keeps its 64 KiB
    let r = f
        .call(
            "POST",
            "/api/jobs",
            &[
                CSRF,
                ("Authorization", &ui),
                ("Content-Type", "application/json"),
            ],
            &vec![b' '; 70_000],
        )
        .await;
    assert_eq!(r.status, 413);
    // auth off: mount gets no principal
    let off = start(false, false, 600).await;
    let r = off.get("/node/v1/echo", &[]).await;
    assert_eq!(r.json(), json!({"key": null, "len": 0}));
}

#[tokio::test]
async fn host_is_still_checked() {
    let f = start(true, false, 600).await;
    let r = f
        .call("GET", "/auth/info", &[("Host", "evil.example")], b"")
        .await;
    // a second Host header is a different value; the raw request carries both, and the first one wins in
    // the head parser: send a request with only the wrong one instead
    let _ = r;
    let mut s = TcpStream::connect(f.addr).await.unwrap();
    s.write_all(b"GET /auth/info HTTP/1.1\r\nHost: evil.example\r\n\r\n")
        .await
        .unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).await.unwrap();
    assert!(buf.starts_with("HTTP/1.1 421"), "{buf}");
}

#[tokio::test]
async fn tls_end_to_end() {
    let f = start(true, true, 600).await;
    assert_eq!(f.get("/auth/info", &[]).await.json()["auth"], json!(true));
    let token = f.token(&f.keys.ui).await;
    let r = f
        .get(
            "/api/meta",
            &[CSRF, ("Authorization", &format!("Bearer {token}"))],
        )
        .await;
    assert_eq!(r.status, 200);
    // a plain-text client on the TLS port is dropped, and the server keeps serving
    let mut raw = TcpStream::connect(f.addr).await.unwrap();
    raw.write_all(b"GET /auth/info HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = raw.read_to_end(&mut buf).await;
    assert!(!String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200"));
    assert_eq!(f.get("/auth/info", &[]).await.status, 200);
}

#[test]
fn tls_files_are_validated() {
    let missing = TlsFiles {
        cert: "/nonexistent/c.pem".into(),
        key: "/nonexistent/k.pem".into(),
    };
    assert!(tls_acceptor(&missing).is_err());
    let swapped = TlsFiles {
        cert: tls_files().key,
        key: tls_files().cert,
    };
    assert!(tls_acceptor(&swapped).is_err());
}

#[test]
fn exposure_matrix() {
    let lo: SocketAddr = "127.0.0.1:8765".parse().unwrap();
    let lo6: SocketAddr = "[::1]:8765".parse().unwrap();
    let any: SocketAddr = "0.0.0.0:8765".parse().unwrap();
    let any6: SocketAddr = "[::]:8765".parse().unwrap();
    let lan: SocketAddr = "192.168.1.5:8765".parse().unwrap();
    for l in [lo, lo6] {
        for tls in [false, true] {
            for auth in [false, true] {
                for insecure in [false, true] {
                    assert!(check_exposure(&l, tls, auth, insecure).is_ok());
                }
            }
        }
    }
    for l in [any, any6, lan] {
        assert!(check_exposure(&l, true, true, false).is_ok());
        assert!(check_exposure(&l, false, true, true).is_ok());
        assert!(check_exposure(&l, true, true, true).is_ok());
        let no_auth = check_exposure(&l, true, false, false).unwrap_err();
        assert!(no_auth.contains("authentication"), "{no_auth}");
        assert!(check_exposure(&l, true, false, true).is_err());
        let no_tls = check_exposure(&l, false, true, false).unwrap_err();
        assert!(
            no_tls.contains("--tls-cert")
                && no_tls.contains("--tls-key")
                && no_tls.contains("insecure_http"),
            "{no_tls}"
        );
    }
}
