//! The server mode: the API and the UI over HTTP(S), with API-key authentication when the address is not loopback
//! (or `[server] auth = "required"`). [`build_server`] turns a configuration and an engine into the
//! `secmonk_api::Server` (router, authentication, mounts) and is testable with a stub engine; [`serve`] adds the
//! host (uv, Python, stores), the listener and the shutdown on Ctrl-C / SIGTERM.

use std::net::SocketAddr;
use std::sync::Arc;

use secmonk_api::{
    HostPolicy, Mount, Router, RouterOptions, Server, ServerOptions, StaticDir, TlsFiles,
    check_exposure,
};
use secmonk_auth::{
    Authenticator, JwtSigner, KeyStore, load_or_create_secret, secret_from_env_value,
};
use secmonk_config::{AuthMode, Config, is_loopback_listen};
use secmonk_engine::EngineService;

use crate::Service;

/// Listen address when neither `[server] listen` nor `[ui] http_listen` is set.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8765";

/// The environment variable that carries the JWT signing secret (hex or base64, at least 32 bytes); it wins over
/// `[auth] jwt_secret_file`.
pub const JWT_SECRET_ENV: &str = "SECMONK_JWT_SECRET";

/// Builds the extra API mounts (the node API) once the [`Service`] exists.
pub type MountFactory = Box<dyn Fn(&Service) -> Vec<Arc<dyn Mount>> + Send + Sync>;

/// What the caller adds to the server mode.
#[derive(Default)]
pub struct ServeOptions {
    /// The JWT secret from the environment ([`JWT_SECRET_ENV`]); `None`: the secret file.
    pub jwt_secret_env: Option<String>,
    /// Extra mounts behind the server's authentication.
    pub mount_factory: Option<MountFactory>,
}

impl std::fmt::Debug for ServeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeOptions")
            .field(
                "jwt_secret_env",
                &self.jwt_secret_env.as_ref().map(|_| "<set>"),
            )
            .field("mount_factory", &self.mount_factory.is_some())
            .finish()
    }
}

impl ServeOptions {
    /// Read the process environment ([`JWT_SECRET_ENV`]); the one place it is read.
    pub fn from_env() -> Self {
        Self {
            jwt_secret_env: std::env::var(JWT_SECRET_ENV)
                .ok()
                .filter(|v| !v.trim().is_empty()),
            mount_factory: None,
        }
    }
}

/// Why the server cannot start: a usage error (exit 2) or a runtime error (exit 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeError {
    Usage(String),
    Runtime(String),
}

impl ServeError {
    /// The exit code.
    pub fn code(&self) -> i32 {
        match self {
            ServeError::Usage(_) => 2,
            ServeError::Runtime(_) => 1,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            ServeError::Usage(m) | ServeError::Runtime(m) => m,
        }
    }
}

/// The server, ready to listen.
#[derive(Debug)]
pub struct Prepared {
    pub server: Arc<Server>,
    pub listen: SocketAddr,
    pub tls: Option<TlsFiles>,
    pub auth_on: bool,
    /// Keys that can be used now (not revoked); 0 with auth on means nobody can log in yet.
    pub active_keys: usize,
}

/// `[server] listen`, else `[ui] http_listen`, else [`DEFAULT_LISTEN`].
pub fn configured_listen(config: &Config) -> String {
    config
        .server_listen
        .clone()
        .or_else(|| config.ui_http_listen.clone())
        .unwrap_or_else(|| DEFAULT_LISTEN.to_owned())
}

/// Any address, loopback or not: `HOST:PORT` with a non-zero port (`localhost` is 127.0.0.1).
pub fn parse_listen(value: &str) -> Result<SocketAddr, String> {
    let bad = |why: String| {
        format!("listen address {value:?}: {why} (expected HOST:PORT, e.g. {DEFAULT_LISTEN})")
    };
    let addr: SocketAddr = match value.parse() {
        Ok(a) => a,
        Err(e) => {
            let (host, port) = value
                .rsplit_once(':')
                .filter(|(h, _)| h.eq_ignore_ascii_case("localhost"))
                .ok_or_else(|| bad(e.to_string()))?;
            let port: u16 = port.parse().map_err(|_| bad("bad port".into()))?;
            let _ = host;
            SocketAddr::from(([127, 0, 0, 1], port))
        }
    };
    if addr.port() == 0 {
        return Err(bad("the port must not be 0".into()));
    }
    Ok(addr)
}

/// Whether authentication is on: `required`, or `auto` on a non-loopback address. (`off` on a non-loopback address
/// is refused when the configuration loads.)
pub fn auth_required(config: &Config, listen: &SocketAddr) -> bool {
    match config.server_auth {
        AuthMode::Required => true,
        AuthMode::Auto => !is_loopback_listen(&listen.to_string()),
        AuthMode::Off => false,
    }
}

/// Build the router, the authentication and the mounts for `engine` from the configuration. Checks the exposure
/// rules ([`check_exposure`]) before anything is bound. Creates the auth directory (0700) and the JWT secret file
/// when auth is on.
pub fn build_server(
    config: &Config,
    engine: Arc<dyn EngineService>,
    jwt_secret_env: Option<&str>,
    mounts: Vec<Arc<dyn Mount>>,
) -> Result<Prepared, ServeError> {
    let runtime = |m: String| ServeError::Runtime(m);
    let listen = parse_listen(&configured_listen(config)).map_err(ServeError::Usage)?;
    let auth_on = auth_required(config, &listen);
    let tls = match (&config.server_tls_cert, &config.server_tls_key) {
        (Some(cert), Some(key)) => Some(TlsFiles {
            cert: cert.clone(),
            key: key.clone(),
        }),
        _ => None,
    };
    check_exposure(&listen, tls.is_some(), auth_on, config.server_insecure_http)
        .map_err(ServeError::Usage)?;

    // `serve_ui = false`: the static directory points nowhere, so the UI files answer 404 (the API stays)
    let static_root = if config.server_serve_ui {
        config.ui_static_dir.clone()
    } else {
        config.data_dir.join("no-ui")
    };
    let router = Arc::new(Router::new(
        engine,
        RouterOptions {
            static_dir: StaticDir::new(static_root),
            host_policy: HostPolicy::http_server(
                &listen.ip().to_string(),
                listen.port(),
                &config.server_allow_hosts,
            ),
            actions: config.server_allow_actions,
        },
    ));
    let mut server = Server::new(router);
    let mut active_keys = 0;
    if auth_on {
        crate::apikeys::ensure_auth_dirs(config).map_err(runtime)?;
        let store = KeyStore::load(&config.auth_keys_file).map_err(|e| runtime(e.to_string()))?;
        active_keys = store.list().iter().filter(|k| !k.revoked).count();
        let secret = match jwt_secret_env {
            Some(v) => {
                secret_from_env_value(v).map_err(|e| runtime(format!("{}: {e}", JWT_SECRET_ENV)))
            }
            None => load_or_create_secret(&config.auth_jwt_secret_file)
                .map_err(|e| runtime(e.to_string())),
        }?;
        let signer = JwtSigner::new(secret, config.auth_jwt_ttl_s);
        server = server.with_auth(Arc::new(Authenticator::new(
            store,
            signer,
            config.auth_rate_per_minute,
        )));
    }
    // node mounts: added by the node work package, through `ServeOptions::mount_factory`
    for m in mounts {
        server = server.with_mount(m);
    }
    Ok(Prepared {
        server: Arc::new(server),
        listen,
        tls,
        auth_on,
        active_keys,
    })
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// Run the server until Ctrl-C / SIGTERM. Returns the exit code (0 ok, 1 runtime error, 2 usage error).
pub async fn serve(prog: &str, config: Arc<Config>, opts: ServeOptions) -> i32 {
    let service = Service::with_actions(config.clone(), config.server_allow_actions);
    let mounts = opts
        .mount_factory
        .as_ref()
        .map(|f| f(&service))
        .unwrap_or_default();
    let prepared = match build_server(
        &config,
        service.engine(),
        opts.jwt_secret_env.as_deref(),
        mounts,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{prog}: {}", e.message());
            return e.code();
        }
    };
    if prepared.auth_on && prepared.active_keys == 0 {
        tracing::warn!(
            keys_file = %config.auth_keys_file.display(),
            "authentication is on but there is no API key: nobody can sign in. Create one with \
             `secmonk-server apikey create --name admin --scope admin`"
        );
    }
    let scheme = if prepared.tls.is_some() {
        "https"
    } else {
        "http"
    };
    tracing::info!(
        listen = %prepared.listen,
        scheme,
        auth = prepared.auth_on,
        actions = config.server_allow_actions,
        ui = config.server_serve_ui,
        data_dir = %config.data_dir.display(),
        "starting"
    );
    let starter = tokio::spawn(service.clone().run());
    let listen = prepared.listen;
    let server = secmonk_api::serve(
        prepared.server,
        ServerOptions {
            tls: prepared.tls,
            ..ServerOptions::new(listen)
        },
        |a| eprintln!("listening {scheme}://{a}"),
    );
    let code = tokio::select! {
        r = server => match r {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("{prog}: cannot serve on {listen}: {e}");
                1
            }
        },
        () = shutdown_signal() => {
            tracing::info!("signal received: stopping");
            0
        }
    };
    service.shutdown().await;
    let _ = starter.await;
    code
}

/// [`serve`] on a fresh runtime, with logging to stderr and the log file. For the command line.
pub fn serve_blocking(prog: &str, config: Arc<Config>, opts: ServeOptions) -> i32 {
    crate::logging::init(&config, true);
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{prog}: cannot start the async runtime: {e}");
            return 1;
        }
    };
    rt.block_on(serve(prog, config, opts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_config;
    use secmonk_engine::{EngineInfo, SkeletonEngine};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn stub() -> Arc<dyn EngineService> {
        Arc::new(SkeletonEngine::new(EngineInfo::new(
            "0.0.0-test",
            "/nonexistent/state.sqlite3",
        )))
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// One HTTP exchange on a fresh connection: (status, body).
    async fn http(port: u16, req: &str) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text.split(' ').nth(1).unwrap().parse().unwrap();
        let body = text.split_once("\r\n\r\n").map_or("", |x| x.1).to_owned();
        (status, body)
    }

    fn get(port: u16, path: &str, auth: Option<&str>) -> String {
        let a = auth
            .map(|a| format!("Authorization: {a}\r\n"))
            .unwrap_or_default();
        format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-SecMonk-Request: 1\r\n{a}Connection: close\r\n\r\n"
        )
    }

    #[test]
    fn listen_rules() {
        assert_eq!(parse_listen("0.0.0.0:8765").unwrap().port(), 8765);
        assert!(parse_listen("[::]:443").is_ok());
        assert_eq!(
            parse_listen("localhost:9000").unwrap().to_string(),
            "127.0.0.1:9000"
        );
        assert!(parse_listen("127.0.0.1:0").is_err());
        assert!(parse_listen("nonsense").is_err());
    }

    #[test]
    fn listen_precedence_and_auth_decision() {
        let d = tempfile::tempdir().unwrap();
        let c = temp_config(d.path(), &[]);
        assert_eq!(configured_listen(&c), DEFAULT_LISTEN);
        let a = parse_listen(DEFAULT_LISTEN).unwrap();
        assert!(!auth_required(&c, &a));
        let c = temp_config(
            d.path(),
            &[
                "ui.http_listen=\"127.0.0.1:9\"",
                "server.listen=\"0.0.0.0:9000\"",
            ],
        );
        assert_eq!(configured_listen(&c), "0.0.0.0:9000");
        assert!(auth_required(&c, &parse_listen("0.0.0.0:9000").unwrap()));
        let c = temp_config(d.path(), &["ui.http_listen=\"127.0.0.1:9\""]);
        assert_eq!(configured_listen(&c), "127.0.0.1:9");
        let c = temp_config(d.path(), &["server.auth=\"required\""]);
        assert!(auth_required(&c, &a));
    }

    #[test]
    fn exposure_is_refused_with_a_usage_error() {
        let d = tempfile::tempdir().unwrap();
        // non-loopback, auth auto -> on, but no TLS and no insecure_http
        let c = temp_config(d.path(), &["server.listen=\"0.0.0.0:8765\""]);
        let e = build_server(&c, stub(), None, vec![]).unwrap_err();
        assert_eq!(e.code(), 2);
        assert!(e.message().contains("TLS"), "{}", e.message());
        // behind a proxy: allowed
        let c = temp_config(
            d.path(),
            &[
                "server.listen=\"0.0.0.0:8765\"",
                "server.insecure_http=true",
            ],
        );
        let p = build_server(&c, stub(), Some(&"ab".repeat(32)), vec![]).unwrap();
        assert!(p.auth_on && p.server.auth_enabled());
    }

    #[tokio::test]
    async fn auth_flow_with_a_key_made_by_the_apikey_code_path() {
        let d = tempfile::tempdir().unwrap();
        let port = free_port();
        let listen = format!("server.listen=\"127.0.0.1:{port}\"");
        let c = temp_config(d.path(), &[&listen, "server.auth=\"required\""]);
        let key = crate::apikeys::create(&c, "admin", &["admin".into()], None).unwrap();
        let reader = crate::apikeys::create(&c, "ro", &["feed:read".into()], None).unwrap();

        let p = build_server(&c, stub(), None, vec![]).unwrap();
        assert!(p.auth_on && p.active_keys == 2 && p.tls.is_none());
        assert!(
            c.auth_jwt_secret_file.exists(),
            "the secret is created on first start"
        );
        let opts = ServerOptions::new(p.listen);
        let server = p.server.clone();
        let task = tokio::spawn(async move { secmonk_api::serve(server, opts, |_| {}).await });
        // wait for the listener
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let (s, body) = http(port, &get(port, "/auth/info", None)).await;
        assert_eq!(s, 200);
        assert!(body.contains("\"auth\":true"), "{body}");

        let (s, _) = http(port, &get(port, "/api/meta", None)).await;
        assert_eq!(s, 401);

        let login = format!("{{\"api_key\":\"{key}\"}}");
        let req = format!(
            "POST /auth/token HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{login}",
            login.len()
        );
        let (s, body) = http(port, &req).await;
        assert_eq!(s, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let token = v["token"].as_str().unwrap().to_owned();
        assert_eq!(v["token_type"], "Bearer");

        let (s, _) = http(
            port,
            &get(port, "/api/meta", Some(&format!("Bearer {token}"))),
        )
        .await;
        assert_eq!(s, 200);
        let (s, _) = http(
            port,
            &get(port, "/api/meta", Some(&format!("ApiKey {key}"))),
        )
        .await;
        assert_eq!(s, 200);
        // a key without ui:read is authenticated but forbidden
        let (s, _) = http(
            port,
            &get(port, "/api/meta", Some(&format!("ApiKey {reader}"))),
        )
        .await;
        assert_eq!(s, 403);
        // a key revoked while the server runs stops working
        crate::apikeys::revoke(&c, "ro").unwrap();
        let (s, _) = http(
            port,
            &get(port, "/api/meta", Some(&format!("ApiKey {reader}"))),
        )
        .await;
        assert_eq!(s, 401);
        let (s, _) = http(port, &get(port, "/api/meta", Some("Bearer not.a.jwt"))).await;
        assert_eq!(s, 401);
        task.abort();
    }

    #[test]
    fn no_auth_on_loopback_by_default() {
        let d = tempfile::tempdir().unwrap();
        let c = temp_config(d.path(), &[]);
        let p = build_server(&c, stub(), None, vec![]).unwrap();
        assert!(!p.auth_on && !p.server.auth_enabled());
        assert!(!c.auth_jwt_secret_file.exists(), "no secret without auth");
    }

    #[test]
    fn a_bad_jwt_secret_in_the_environment_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let c = temp_config(d.path(), &["server.auth=\"required\""]);
        let e = build_server(&c, stub(), Some("short"), vec![]).unwrap_err();
        assert_eq!(e.code(), 1);
        assert!(e.message().contains(JWT_SECRET_ENV));
    }
}
