//! sec-monk desktop app: the shell over the composed host.
//!
//! With the `ui` feature (default on macOS and Windows) it builds the Tauri window: it loads the config, starts the
//! host in the background ([`secmonk_host::Service`]), builds the API router on the host's gate, registers the
//! `secmonk` custom scheme (the router answers every request of the webview, `/api` included, in-process) and
//! opens the window on the scheme origin. While uv and Python install on the first run the scheme answers a
//! 503 "preparing" state that the UI shows with its normal error panel. The window gets no Tauri IPC (ADR-0007):
//! the scheme is its only way to Rust.
//!
//! Without `ui` (Linux headless: `--no-default-features --features engine,probe`) the same binary runs the
//! loopback HTTP server of `secmonk_host::headless`; Tauri is not in the dependency graph at all.

pub mod cli;

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

    use secmonk_api::{HostPolicy, Router, RouterOptions, StaticDir};
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

    pub fn run(config: Arc<Config>) -> Result<(), String> {
        let service = Service::new(config.clone());
        let router: Arc<OnceLock<Arc<Router>>> = Arc::new(OnceLock::new());
        let for_scheme = router.clone();
        let for_setup = service.clone();
        let for_exit = service.clone();
        let setup_config = config.clone();

        let app = tauri::Builder::default()
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
            .build(tauri::generate_context!())
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

/// Start the app. Returns the process exit code (0 ok, 1 runtime error, 2 usage).
pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(feature = "ui")]
    {
        let config = match cli::load_config(&args) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("secmonk-desktop: {e}");
                return 1;
            }
        };
        secmonk_host::logging::init(&config, cfg!(debug_assertions));
        match ui::run(config) {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("{e}");
                eprintln!("secmonk-desktop: {e}");
                1
            }
        }
    }
    #[cfg(all(not(feature = "ui"), feature = "engine"))]
    {
        secmonk_host::headless::run(&args)
    }
    #[cfg(not(feature = "engine"))]
    {
        let _ = args;
        eprintln!(
            "secmonk-desktop: built without the `engine` feature (probe-only): there is nothing to serve yet. \
             Rebuild with `--features engine,probe` (headless) or the default features (window)."
        );
        2
    }
}
