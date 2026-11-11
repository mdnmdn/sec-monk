//! Engine to UI API of the desktop app: the same 22 routes, errors and security rules as `web/server.py`, answered
//! in-process. [`Router::handle`] maps an `http::Request` to an `http::Response`; the Tauri `secmonk` scheme handler
//! and the dev HTTP binding both call it. See `rust/_docs/tech/api-contract.md`.

#![forbid(unsafe_code)]

pub mod error;
pub mod host;
pub mod http_server;
pub mod policy;
pub mod query;
pub mod router;
pub mod routes;
pub mod static_files;

pub use error::ApiError;
pub use host::HostPolicy;
pub use http_server::{
    MAX_CONNECTIONS, READ_TIMEOUT, WRITE_TIMEOUT, serve_http, serve_http_with, serve_listener,
};
pub use router::{CSP, CSRF_HEADER, MAX_BODY, Router, RouterOptions};
pub use routes::{ROUTES, Route, RouteId};
pub use static_files::StaticDir;
