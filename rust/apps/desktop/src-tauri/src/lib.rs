//! sec-monk desktop app: the shell over the composed host.
//!
//! With the `ui` feature (default on macOS and Windows) it builds the Tauri window: it loads the config, starts the
//! host in the background ([`secmonk_host::Service`]), builds the API router on the host's gate, registers the
//! `secmonk` custom scheme (the router answers every request of the webview, `/api` included, in-process) and
//! opens the window on the scheme origin. While uv and Python install on the first run the scheme answers a
//! 503 "preparing" state that the UI shows with its normal error panel. The window gets no Tauri IPC (ADR-0007):
//! the scheme is its only way to Rust, plus one IPC command, `secmonk_api`, that answers `/api/` requests in
//! process (the capability `main` grants it to the `main` window only).
//!
//! The command line is `secmonk_host::cli`, shared with `secmonk-server`: `secmonk-desktop serve` (or `--serve`),
//! `apikey ...`, `config show`, `version` run without a window and without initialising Tauri; plain
//! `secmonk-desktop [--config FILE] [--set key=value] [--data-dir DIR]` opens the window.
//!
//! Without `ui` (Linux headless: `--no-default-features --features engine,probe`) the same binary behaves like
//! `secmonk-server` for every subcommand (serving when none is given); Tauri is not in the dependency graph.

#[cfg(feature = "ui")]
pub mod bundle;
#[cfg(feature = "ui")]
mod static_dir;
#[cfg(feature = "ui")]
mod window;

#[cfg(feature = "ui")]
pub use static_dir::resolve as resolve_static_dir;
#[cfg(feature = "ui")]
pub use window::{origin_url, tauri_scheme_authority};

#[cfg(feature = "ui")]
mod ui {
    use std::borrow::Cow;
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    use secmonk_api::{
        BridgeRequest, BridgeResponse, HostPolicy, Router, RouterOptions, StaticDir,
    };
    use secmonk_config::Config;
    use secmonk_host::Service;
    use tauri::{Manager, RunEvent};

    use crate::{resolve_static_dir, window};

    /// The router for a service's engine and a resolved static directory (the Tauri scheme and the dev HTTP
    /// binding build it the same way). The window is local and has no listener: actions are always allowed.
    fn build_router(service: &Service, static_dir: PathBuf, host_policy: HostPolicy) -> Router {
        Router::new(
            service.engine(),
            RouterOptions {
                static_dir: StaticDir::new(static_dir),
                host_policy,
                actions: true,
            },
        )
    }

    fn starting_response() -> tauri::http::Response<Vec<u8>> {
        secmonk_api::router::error_response(&secmonk_api::ApiError::new(
            tauri::http::StatusCode::SERVICE_UNAVAILABLE,
            "starting",
        ))
    }

    /// The IPC command `secmonk_api`: the page's `fetch` of `/api/...` (rust/ui/transport.js) answered in process.
    /// No network and no authentication: the window is local. Only `/api/` paths are served (`handle_bridge`).
    #[tauri::command]
    async fn secmonk_api(
        router: tauri::State<'_, Arc<OnceLock<Arc<Router>>>>,
        request: BridgeRequest,
    ) -> Result<BridgeResponse, String> {
        let ready = router.get().cloned();
        Ok(match ready {
            Some(r) => secmonk_api::handle_bridge(&r, request).await,
            None => starting_bridge_response(),
        })
    }

    /// 503 "starting": the router is built in `setup`, a moment after the window exists.
    fn starting_bridge_response() -> BridgeResponse {
        let r = starting_response();
        BridgeResponse {
            status: r.status().as_u16(),
            headers: r
                .headers()
                .iter()
                .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
                .collect(),
            body: Some(String::from_utf8_lossy(r.body()).into_owned()),
            body_base64: None,
        }
    }

    /// Optional dev binding (`[ui] http_listen`): the same router on a loopback port with the full Host rules.
    fn start_http_binding(
        service: &Service,
        listen: &str,
        static_dir: PathBuf,
    ) -> Result<(), String> {
        let addr = secmonk_host::headless::listen_addr(listen)
            .map_err(|e| format!("[ui] http_listen: {e}"))?;
        let policy = HostPolicy::http(&addr.ip().to_string(), addr.port(), &[]);
        let router = Arc::new(build_router(service, static_dir, policy));
        tauri::async_runtime::spawn(async move {
            if let Err(e) = secmonk_api::serve_http(router, addr, |a| {
                tracing::info!("dev HTTP binding on http://{a}");
            })
            .await
            {
                tracing::error!("dev HTTP binding stopped: {e}");
            }
        });
        Ok(())
    }

    pub fn run(config: Arc<Config>, context: tauri::Context<tauri::Wry>) -> Result<(), String> {
        let service = Service::new(config.clone());
        let router: Arc<OnceLock<Arc<Router>>> = Arc::new(OnceLock::new());
        let for_scheme = router.clone();
        let for_setup = service.clone();
        let for_exit = service.clone();
        let setup_config = config.clone();

        let for_ipc = router.clone();
        let app = tauri::Builder::default()
            .manage(for_ipc)
            .invoke_handler(tauri::generate_handler![secmonk_api])
            // Asynchronous: a slow engine call never blocks the webview thread.
            .register_asynchronous_uri_scheme_protocol(
                config.ui_scheme.clone(),
                move |_ctx, request, responder| {
                    let router = for_scheme.get().cloned();
                    tauri::async_runtime::spawn(async move {
                        let response = match router {
                            Some(r) => r.handle(request).await,
                            None => starting_response(),
                        };
                        responder.respond(response.map(Cow::Owned));
                    });
                },
            )
            .setup(move |app| {
                let config = setup_config;
                let resource_dir = app.path().resource_dir().ok();
                // `ui.static_dir` already carries the `$SECMONK_STATIC` override (secmonk-config); a release
                // build ignores both and serves the bundled copy only.
                let static_dir = resolve_static_dir(
                    cfg!(debug_assertions),
                    None,
                    Some(config.ui_static_dir.clone()),
                    resource_dir.as_deref(),
                )
                .ok_or(
                    "no static UI directory: set [ui] static_dir or bundle the `static` resource",
                )?;
                let policy = HostPolicy::scheme(config.ui_scheme.clone());
                let r = Arc::new(build_router(&for_setup, static_dir.clone(), policy));
                let _ = router.set(r);
                if let Some(listen) = config.ui_http_listen.clone() {
                    start_http_binding(&for_setup, &listen, static_dir.clone())?;
                }
                // uv, Python and the module venv install in the background; the window opens at once and shows
                // the "preparing" state until the engine is up.
                tauri::async_runtime::spawn(for_setup.clone().run());
                window::open_main(app, &config)?;
                Ok(())
            })
            .build(context)
            .map_err(|e| e.to_string())?;

        app.run(move |_app, event| {
            if let RunEvent::Exit = event {
                // stop the modules (stdin EOF, grace, kill) before the process ends
                tauri::async_runtime::block_on(for_exit.shutdown());
            }
        });
        Ok(())
    }
}

/// No subcommand: open the window.
#[cfg(all(feature = "ui", feature = "engine"))]
fn window(cli: &secmonk_host::cli::Cli, context: tauri::Context<tauri::Wry>) -> i32 {
    let config = match cli.load_config() {
        Ok(c) => std::sync::Arc::new(c),
        Err(e) => {
            eprintln!("secmonk-desktop: {e}");
            return 1;
        }
    };
    secmonk_host::logging::init(&config, cfg!(debug_assertions));
    match ui::run(config, context) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("{e}");
            eprintln!("secmonk-desktop: {e}");
            1
        }
    }
}

/// Without the window toolkit every run is a command (`cli.command` or the server default).
#[cfg(all(not(feature = "ui"), feature = "engine"))]
fn window(cli: &secmonk_host::cli::Cli) -> i32 {
    secmonk_host::cli::run("secmonk-desktop", cli)
}

/// Start the app. Returns the process exit code (0 ok, 1 runtime error, 2 usage).
pub fn run() -> i32 {
    const PROG: &str = "secmonk-desktop";
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(feature = "engine")]
    {
        let cli = match secmonk_host::cli::parse(&args) {
            Ok(c) => c,
            Err(m) => {
                eprintln!("{PROG}: {m}\nTry `{PROG} help`.");
                return 2;
            }
        };
        #[cfg(feature = "ui")]
        let context = tauri::generate_context!();
        #[cfg(feature = "ui")]
        let mut cli = cli;
        // An installed app (release build) finds its Python project and UI in its resource directory (on Windows
        // the install directory); they become defaults below the config file. Debug builds keep the repository's
        // dev configuration. Computed before any subcommand, so `secmonk-desktop serve` of a bundle works too.
        #[cfg(feature = "ui")]
        if !cfg!(debug_assertions)
            && let Ok(res) =
                tauri::utils::platform::resource_dir(context.package_info(), &tauri::Env::default())
        {
            cli.app_defaults = bundle::app_defaults(&res);
        }
        // a subcommand (or --serve) never builds the Tauri app; without a window toolkit the server is the default
        if cli.command.is_some() {
            return secmonk_host::cli::run(PROG, &cli);
        }
        #[cfg(feature = "ui")]
        return window(&cli, context);
        #[cfg(not(feature = "ui"))]
        window(&cli)
    }
    #[cfg(not(feature = "engine"))]
    {
        let _ = args;
        eprintln!(
            "{PROG}: built without the `engine` feature (probe-only): there is nothing to serve yet. \
             Rebuild with `--features engine,probe` (headless) or the default features (window)."
        );
        2
    }
}
