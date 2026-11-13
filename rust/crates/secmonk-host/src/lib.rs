//! Composition (`secmonk-host`): the one place that knows both the module host and the engine.
//!
//! The desktop app and the server (`secmonk-server`, `secmonk-headless`) share it. [`Host::start`] runs the startup sequence:
//!
//! 1. ensure uv, the managed Python and the module venv through `UvRuntime` (first run: download, with progress);
//! 2. open the stores and run the migrations (`engine` feature);
//! 3. build the module registry from the manifests and the hello settings (`module_dir`, `process`,
//!    `min_confidence`, `db_read` grants);
//! 4. build the probe service (collector allowlist) over `PyCollector`;
//! 5. build the sources and the engine steps from the adapters, and the mirror-node roles ([`node`]: serve, follow,
//!    state-only matching) from `[node]`;
//! 6. construct the engine.
//!
//! First start takes a while, so a [`Service`] serves a "preparing" state through the API meanwhile ([`Gate`]):
//! the UI shows its normal error state with a hint instead of a blank window. [`Host::shutdown`] stops the
//! modules (close stdin, grace, kill) and closes the stores.
//!
//! Without the `engine` feature the crate composes only the runtime, the module host and the probe (the probe-only
//! build); with it, the engine, the stores and the API binding ([`headless`]) come along.

#![forbid(unsafe_code)]

pub mod host;
pub mod logging;
pub mod startup;

#[cfg(feature = "engine")]
pub(crate) mod apikeys;
#[cfg(feature = "engine")]
pub mod cli;
#[cfg(feature = "engine")]
pub(crate) mod engine;
#[cfg(feature = "engine")]
pub mod gate;
#[cfg(feature = "engine")]
pub mod headless;
#[cfg(feature = "engine")]
pub mod node;
#[cfg(feature = "engine")]
pub(crate) mod serve;
#[cfg(feature = "engine")]
pub mod service;
#[cfg(all(test, feature = "engine"))]
pub(crate) mod testutil;

pub use host::{Host, HostError};
pub use startup::{Phase, Progress, StartupState};

#[cfg(feature = "engine")]
pub use gate::Gate;
#[cfg(feature = "engine")]
pub use service::Service;
