//! Module host (`secmonk-modhost`): runs modules and exposes them as `secmonk-traits` objects.
//!
//! - [`registry`]: manifests (`rust/python/modules/*.toml|json`), filtered by the config (`enabled`, platform,
//!   trust pins), with config overrides of limits and lifecycle;
//! - [`session`]: `secmonk-wire/1` over any `AsyncRead + AsyncWrite` (hello, request ids, unary and stream
//!   calls, progress, cancel on drop, deadlines with cancel-then-kill, crash detection);
//! - [`child`]: the child-stdio transport (venv Python from `secmonk-runtime`, stderr forwarded to `tracing`,
//!   kill on drop, own process group / `CREATE_NO_WINDOW`);
//! - [`inproc`]: the in-process serialized transport (`tokio::io::duplex`) serving a Rust [`inproc::RustModule`]
//!   through the same session code (conformance tests, Rust ports);
//! - [`supervisor`]: [`supervisor::ModuleHandle`], lazy start, restart with backoff, `max_restarts` per window;
//! - [`adapters`]: `PyCollector`, `PySource`, `PyEngine` implementing the domain traits over a handle.
//!
//! The plain in-process path for a Rust implementation needs nothing from here: the engine receives the Rust
//! object as `Arc<dyn Collector>` directly.

pub mod adapters;
pub mod child;
pub mod hello;
pub mod inproc;
pub mod registry;
pub mod session;
pub mod supervisor;

pub use secmonk_proto::{ErrorCode, WireError};

/// Error type of the module host: the wire error (`module-unavailable`, `module-crashed`, `timeout`, ...).
pub type ModuleError = WireError;
/// Result type of the module host.
pub type ModuleResult<T> = Result<T, ModuleError>;
