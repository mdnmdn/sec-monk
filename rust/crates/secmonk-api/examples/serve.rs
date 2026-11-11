//! Headless server: the API router with the skeleton engine over 127.0.0.1 and the Python server's Host rules.
//! No Tauri: this is the Linux headless build and the harness for apps/desktop/tests/nodeapi.cjs.
//!
//!     cargo run -p secmonk-api --example serve -- --static ../src/secmonk/web/static [--port 18765] [--state-db PATH]
//!
//! Prints `listening http://127.0.0.1:<port>` on stderr once bound.

use std::net::SocketAddr;
use std::sync::Arc;

use secmonk_api::{HostPolicy, Router, RouterOptions, StaticDir, serve_http};
use secmonk_engine::{EngineInfo, SkeletonEngine};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let port: u16 = arg(&args, "--port")
        .map(|p| p.parse())
        .transpose()?
        .unwrap_or(18765);
    let static_dir = arg(&args, "--static")
        .or_else(|| std::env::var("SECMONK_STATIC").ok())
        .ok_or("--static DIR")?;
    let state_db = arg(&args, "--state-db").unwrap_or_else(|| "_data/db/state.sqlite3".into());
    let engine = Arc::new(SkeletonEngine::new(EngineInfo::new(
        env!("CARGO_PKG_VERSION"),
        state_db,
    )));
    let router = Arc::new(Router::new(
        engine,
        RouterOptions {
            static_dir: StaticDir::new(static_dir),
            host_policy: HostPolicy::http("127.0.0.1", port, &[]),
            actions: true,
        },
    ));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve_http(
        router,
        SocketAddr::from(([127, 0, 0, 1], port)),
        |a| eprintln!("listening http://{a}"),
    ))?;
    Ok(())
}
