//! The headless server: the API and the UI over loopback HTTP, with the Host check of `secmonk ui`. This is the
//! Linux "engine + probe" build (no Tauri, no webview) and the dev server for the Node UI harness.
//!
//! ```text
//! secmonk-headless [--config FILE] [--listen 127.0.0.1:8765]
//! ```
//!
//! It loads the configuration like the desktop app (`--config`, `SECMONK_CONFIG`, `./sec-monk.toml`, the per-user
//! file, defaults), serves `ui.static_dir` in place and answers 503 "preparing" while uv and Python install on
//! the first run. Only loopback addresses are accepted. Ctrl-C and SIGTERM stop the modules and exit.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use secmonk_api::{HostPolicy, Router, RouterOptions, StaticDir, serve_http};
use secmonk_config::{LoadOptions, load};

use crate::Service;

/// Whether this binding runs actions (scans, syncs): loopback only, so always. Router and engine get the same value.
const ACTIONS: bool = true;

/// Default listen address when neither `--listen` nor `[ui] http_listen` is set.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8765";

/// Command line of the headless server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// `--config FILE`.
    pub config: Option<PathBuf>,
    /// `--listen HOST:PORT`.
    pub listen: Option<String>,
}

/// Parse the arguments (without the program name).
pub fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut o = Options::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_owned())),
            _ => (a.as_str(), None),
        };
        let mut value = |name: &str| {
            inline
                .clone()
                .or_else(|| it.next().cloned())
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match flag {
            "--config" => o.config = Some(PathBuf::from(value("--config")?)),
            "--listen" => o.listen = Some(value("--listen")?),
            "-h" | "--help" => {
                return Err(
                    "usage: secmonk-headless [--config FILE] [--listen 127.0.0.1:8765]".into(),
                );
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(o)
}

/// The listen address: loopback only, non-zero port.
pub fn listen_addr(value: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = value.parse().map_err(|e| {
        format!("listen address {value:?}: {e} (expected HOST:PORT, e.g. {DEFAULT_LISTEN})")
    })?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "listen address {value:?}: only loopback addresses are accepted (the headless server has no login)"
        ));
    }
    if addr.port() == 0 {
        return Err(format!("listen address {value:?}: the port must not be 0"));
    }
    Ok(addr)
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

/// Run the server until a signal. Returns the process exit code (0 ok, 1 runtime error, 2 usage).
pub fn run(args: &[String]) -> i32 {
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(m) => {
            eprintln!("secmonk-headless: {m}");
            return 2;
        }
    };
    let config = match load(&LoadOptions::from_env(opts.config.clone())) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("secmonk-headless: {e}");
            return 1;
        }
    };
    let listen = opts
        .listen
        .clone()
        .or_else(|| config.ui_http_listen.clone())
        .unwrap_or_else(|| DEFAULT_LISTEN.to_owned());
    let addr = match listen_addr(&listen) {
        Ok(a) => a,
        Err(m) => {
            eprintln!("secmonk-headless: {m}");
            return 2;
        }
    };
    crate::logging::init(&config, true);
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("secmonk-headless: cannot start the async runtime: {e}");
            return 1;
        }
    };
    rt.block_on(async move {
        let service = Service::with_actions(config.clone(), ACTIONS);
        let router = Arc::new(Router::new(
            service.engine(),
            RouterOptions {
                static_dir: StaticDir::new(config.ui_static_dir.clone()),
                host_policy: HostPolicy::http(&addr.ip().to_string(), addr.port(), &[]),
                actions: ACTIONS,
            },
        ));
        tracing::info!(data_dir = %config.data_dir.display(), static_dir = %config.ui_static_dir.display(), "starting");
        let starter = tokio::spawn(service.clone().run());
        let server = serve_http(router, addr, |a| eprintln!("listening http://{a}"));
        let code = tokio::select! {
            r = server => match r {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("secmonk-headless: cannot serve on {addr}: {e}");
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
    })
}
