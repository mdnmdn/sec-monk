//! Native vulnerability sources (`secmonk-sources`, rust ADR-0011, ADR-0012).
//!
//! A native source implements [`secmonk_traits::Source`] in-process. It never gets a database handle: it reads the
//! previous state it needs (row counts, keys, stored rows, the applied seq) through a read-only [`MirrorView`] and
//! returns `secmonk-mirror-rows/1` batches that the engine applies with `MirrorStore::apply_rows`, exactly like the
//! batches of the `py-sources` module. Batches carry [`secmonk_traits::NATIVE_GENERATION`]; there is no change log,
//! so `ack` is a no-op and `export` is refused: a native sync is computed against the current mirror and is its own
//! repair.
//!
//! Importers: the [`importers!`] list below, one module each ([`IMPORTERS`]). Shared: [`feed`] (downloads, streamed
//! downloads, local files, `--path` walks), [`decode`] (sniffed decompression with a cap, BOM, SHA-256), [`batch`]
//! (cutting operations into batches), [`py`] (Python semantics the reference sources rely on), [`rows`] (the row
//! builders of `sources/base.py`), and the crate-private `native` module (outcome, snapshot guard, internal errors,
//! progress lines, `source_sync` row, lazy stream). Selection per source: `[sources.implementation]` in `sec-monk.toml`
//! (`rust/_docs/tech/configuration.md`); the default is [`Importer::default_rust`].
//!
//! **Adding an importer** (`rust/_docs/tech/component-lifecycle.md` "Porting a source to a native importer"): a new
//! file `src/<module>.rs` with a `pub const IMPORTER: Importer`, and one line `<module>,` in the [`importers!`] list.

#![forbid(unsafe_code)]

use std::sync::Arc;

use secmonk_traits::{MirrorView, Source};

pub mod batch;
pub mod decode;
pub mod feed;
mod native;
pub mod py;
pub mod rows;

/// One native importer: its source name, its default implementation and its constructor.
#[derive(Debug, Clone, Copy)]
pub struct Importer {
    /// The source name (`kev`, `debian-tracker`, ...), as `py-sources` serves it.
    pub name: &'static str,
    /// Whether the source defaults to this implementation (`[sources.implementation]` unset). `true` only once the
    /// source's differential test against `py-sources` is green (rust ADR-0011 §6).
    pub default_rust: bool,
    /// The source over a read-only view of the mirror.
    pub new: fn(Arc<dyn MirrorView>) -> Arc<dyn Source>,
}

/// Declares the importer modules and [`IMPORTERS`], in the order given (alphabetical by module).
macro_rules! importers {
    ($($module:ident,)*) => {
        $(pub mod $module;)*

        /// Every native importer (the host lists the selected ones ahead of `py-sources`, in this order).
        pub const IMPORTERS: &[Importer] = &[$($module::IMPORTER,)*];
    };
}

// One line per importer, alphabetical by module; nothing else to register.
importers! {
    debian_tracker,
    epss,
    euvd,
    kev,
    msrc,
}

/// The importer of source `name`, if there is one.
pub fn importer(name: &str) -> Option<&'static Importer> {
    IMPORTERS.iter().find(|i| i.name == name)
}

/// The names of every native importer, in [`IMPORTERS`] order.
pub fn native_names() -> Vec<&'static str> {
    IMPORTERS.iter().map(|i| i.name).collect()
}

/// The native implementation of `name` over `view`, if there is one.
pub fn native_source(name: &str, view: Arc<dyn MirrorView>) -> Option<Arc<dyn Source>> {
    importer(name).map(|i| (i.new)(view))
}
