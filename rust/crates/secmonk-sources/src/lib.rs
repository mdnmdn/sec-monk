//! Native vulnerability sources (`secmonk-sources`, rust ADR-0011).
//!
//! A native source implements [`secmonk_traits::Source`] in-process. It never gets a database handle: it reads the
//! previous state it needs (row counts, keys, the applied seq) through a read-only [`MirrorView`] and returns
//! `secmonk-mirror-rows/1` batches that the engine applies with `MirrorStore::apply_rows`, exactly like the batches of
//! the `py-sources` module. Batches carry [`secmonk_traits::NATIVE_GENERATION`]; there is no change log, so `ack` is a
//! no-op and `export` is refused: a native sync is computed against the current mirror and is its own repair.
//!
//! Sources: [`kev`] (CISA KEV). Selection per source: `[sources.implementation]` in `sec-monk.toml`
//! (`rust/_docs/tech/configuration.md`).

#![forbid(unsafe_code)]

use std::sync::Arc;

use secmonk_traits::{MirrorView, Source};

pub mod batch;
pub mod feed;
pub mod kev;

/// Sources with a native implementation.
pub const NATIVE_SOURCES: &[&str] = &["kev"];

/// The native implementation of `name` over `view`, if there is one.
pub fn native_source(name: &str, view: Arc<dyn MirrorView>) -> Option<Arc<dyn Source>> {
    match name {
        "kev" => Some(Arc::new(kev::KevSource::new(view))),
        _ => None,
    }
}
