//! Engine service of the desktop app (`secmonk-engine`).
//!
//! - [`EngineService`]: the facade the API calls, one async method per `/api` route; [`EngineError`] and the
//!   validated parameter types;
//! - [`SecmonkEngine`]: the real engine, built with [`SecmonkEngine::new`] from [`EngineDeps`] (stores, engine
//!   steps, sources, probe: trait objects only, never the module host);
//! - [`SkeletonEngine`]: the wave-2 stand-in (no store, no modules), kept for tests and the API's examples.
//!
//! Construction contract and behaviour: `rust/_docs/tech/architecture.md` "Engine construction (W3.1)" and
//! "Engine service (W3.1)".

#![forbid(unsafe_code)]

pub mod deps;
mod engine;
pub mod error;
mod jobs;
mod opts;
pub mod params;
mod payload;
mod prepare;
mod scan;
pub mod service;
pub mod skeleton;
mod sync;
mod view;

pub use deps::{EngineConfig, EngineDeps, ModuleInfo, ModuleStatus};
pub use engine::SecmonkEngine;
pub use error::{EngineError, EngineResult, ErrorKind};
/// Python's `str.splitlines()` (shared with `secmonk-api`'s option policy).
pub use opts::splitlines;
pub use params::{
    DiscoverQuery, DockerListQuery, FindingsQuery, JobKind, JobsQuery, VulnSearchQuery,
};
pub use service::{EngineService, JsonObject};
pub use skeleton::{EngineInfo, SkeletonEngine};
pub use view::StoreMirrorView;
