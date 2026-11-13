//! Engine to UI API of the desktop app: the same 22 routes, errors and security rules as `web/server.py`, answered
//! in-process. [`Router::handle`] maps an `http::Request` to an `http::Response`; the Tauri `secmonk` scheme handler
//! and the dev HTTP binding both call it. See `rust/_docs/tech/api-contract.md`.

#![forbid(unsafe_code)]

pub mod bridge;
pub mod error;
pub mod host;
pub mod http_server;
pub mod overlay;
pub mod policy;
pub mod proxies;
pub mod query;
pub mod router;
pub mod routes;
pub mod server;
pub mod static_files;

pub use bridge::{BridgeRequest, BridgeResponse, handle_bridge};
pub use error::ApiError;
pub use host::HostPolicy;
pub use http_server::{
    HANDSHAKE_TIMEOUT, MAX_CONNECTIONS, MAX_PER_IP, READ_TIMEOUT, SERVER_MODE_MAX_CONNECTIONS,
    SHUTDOWN_GRACE, ServerOptions, TlsFiles, WRITE_TIMEOUT, check_exposure, serve, serve_until,
    tls_acceptor,
};
#[doc(hidden)]
pub use http_server::{accept_loop, serve_http, serve_http_with, serve_listener};
pub use proxies::TrustedProxies;
pub use router::{
    CSP, CSP_WINDOW, CSRF_HEADER, MAX_BODY, Router, RouterOptions, error_response, json_response,
};
pub use routes::{ROUTES, Route, RouteId};
pub use server::{
    MAX_MOUNT_BODY, MAX_TOKEN_BODY, MOUNT_NEEDS_AUTH, Mount, RETRY_AFTER_S, RequiredScope, Server,
};
pub use static_files::StaticDir;
/// The shutdown handle of [`serve_until`] (re-exported so callers need no tokio-util dependency).
pub use tokio_util::sync::CancellationToken;
