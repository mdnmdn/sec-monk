//! Mirror-node services over HTTP (rust ADR-0013, `rust/_docs/tech/node-api.md`).
//!
//! - [`NodeApi`]: the `/node/v1` binding, a `secmonk_api::Mount` over `MatchService`, `VulnInfo` and `Feed`.
//! - [`RemoteNode`]: the same three services as an HTTPS client (API key -> JWT).
//! - [`FeedSource`]: following an upstream's feed as a native `Source`.
//!
//! Depends on the traits and the model, never on the store, the engine implementation or the module host: the
//! host composes them. The server binding is the default feature `server` (it needs `secmonk-api`, whose router
//! links the engine); a client-only build (`default-features = false`: `RemoteNode`, `FeedSource`, `wire`) pulls
//! neither `secmonk-api` nor the engine, the store or sqlx.

#![forbid(unsafe_code)]

pub mod client;
pub mod follow;
#[cfg(feature = "server")]
pub mod server;
pub mod wire;

pub use client::{MAX_RESPONSE_BYTES, REFRESH_MARGIN, RemoteConfig, RemoteNode};
pub use follow::{BatchLocalizer, FeedSource, LocalVersionFn};
#[cfg(feature = "server")]
pub use server::{DerivedInfo, NodeApi, NodeInfoProvider, PREFIX, StaticInfo};
