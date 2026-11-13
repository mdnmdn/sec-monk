//! The store (`secmonk-store`): domain operations on the state and mirror databases. The only crate that
//! speaks SQL (`deny.toml` bans sqlx / sea-query elsewhere).
//!
//! - [`StateStore`]: inventory saves (port of `engine/inventory.save_inventory`), finding sets, run history;
//! - [`MirrorStore`]: `secmonk-mirror-rows/1` batches, one transaction each;
//! - [`sqlite`]: the SQLite backend on sqlx (WAL, one writer per file, a small read pool) and the embedded
//!   schema v3 migrations (`migrations/{state,mirror}/sqlite/`).
//!
//! Schema and rules: `rust/_docs/tech/data-model.md`, rust ADR-0005.
//!
//! **Extension points for reads.** API read queries (asset lists, job pages, …) are added as methods of the two
//! traits (domain terms, never SQL in callers) and implemented in `sqlite::state` / `sqlite::mirror` on the read
//! pool (`SqliteStore::read_pool`). Postgres/MySQL backends implement the same traits.

use async_trait::async_trait;
use secmonk_model::{
    BasedOn, Finding, Inventory, JobFinish, JobKind, JobRow, MirrorTable, NewJob, RowsBatch,
};
use serde_json::{Map, Value};

pub mod jobs;
mod migrations;
pub mod mirror_schema;
pub mod node;
pub mod sqlite;

pub use node::{MirrorNodeStore, NodeCacheStore};
pub use sqlite::{SqliteStore, StoreOptions};

/// Schema version written to `PRAGMA user_version` and `store_meta.schema` (for humans; sqlx's
/// `_sqlx_migrations` table is the source of truth).
pub const SCHEMA_VERSION: i64 = 3;

/// Most ids per [`MirrorStore::rows_by_id`] call (`secmonk_traits::MAX_VIEW_IDS`).
pub const MAX_ROWS_IDS: usize = 500;

/// Most rows per [`MirrorStore::rows_page`] call (`secmonk_traits::MAX_VIEW_PAGE`).
pub const MAX_ROWS_PAGE: usize = 5_000;

/// Store errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Driver error.
    #[error("database: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// Migration error (includes "database has a migration this app does not know", R7).
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// Input refused (unknown table/column, bad value): `invalid-params` on the wire.
    #[error("invalid input: {0}")]
    Invalid(String),
    /// A finding set computed from an outdated scan: `stale` on the wire.
    #[error("stale: {0}")]
    Stale(String),
    /// Something named does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// A stored value cannot be decoded.
    #[error("corrupt row: {0}")]
    Corrupt(String),
    /// Filesystem error (creating database files).
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Result of store operations.
pub type StoreResult<T> = Result<T, StoreError>;

/// Facts the reuse rule needs about a stored asset (decoded from JSON, not filtered in SQL: R3).
#[derive(Debug, Clone, PartialEq)]
pub struct AssetReuseFacts {
    /// Asset id.
    pub asset_id: String,
    /// `asset.name`.
    pub name: Option<String>,
    /// `asset.platform` (the reuse rule falls back to it when `meta.platform` is unset).
    pub platform: Option<String>,
    /// `asset.meta` as stored.
    pub meta: Map<String, Value>,
    /// `asset.last_seen`.
    pub last_seen: Option<String>,
    /// Latest scan id (any scan).
    pub latest_scan_id: Option<i64>,
    /// Whether the latest scan was partial.
    pub latest_scan_partial: bool,
}

/// A source's sync state (`source_sync` row).
#[derive(Debug, Clone, PartialEq)]
pub struct SyncState {
    /// Source.
    pub source: String,
    /// Last successful sync.
    pub last_sync: Option<String>,
    /// Delta cursor.
    pub cursor: Option<String>,
    /// Records.
    pub records: Option<i64>,
    /// Status.
    pub status: Option<String>,
    /// Message.
    pub message: Option<String>,
}

/// Outcome of one applied batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApplyStats {
    /// Upserts executed.
    pub upserts: u64,
    /// Rows deleted.
    pub deleted: u64,
    /// The batch was applied before (its seq is at or below the source's last applied seq): nothing written.
    pub skipped: bool,
    /// The batch cannot be applied nor skipped safely: its staging generation is not the one of the applied seq
    /// (the module's staging database was recreated), or the module acknowledged more than the mirror applied
    /// (the mirror was reset or restored). Nothing written; the caller repairs the source from `source.export`
    /// ([`MirrorStore::begin_repair`]).
    pub needs_repair: bool,
}

/// What the mirror recorded about the batches of one source (`source_applied`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedState {
    /// Last applied seq.
    pub seq: u64,
    /// Staging generation of that seq (`None`: recorded before generations existed, or by a module without one).
    pub generation: Option<String>,
}

/// Outcome of a committed repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RepairStats {
    /// Rows of the source deleted before the export was applied.
    pub deleted: u64,
    /// Rows written from the export.
    pub upserts: u64,
    /// Export batches applied.
    pub batches: u64,
}

/// One source's mirror rows being replaced by a `source.export` stream, in **one** transaction (opened by
/// [`MirrorStore::begin_repair`], which deleted the source's rows). Dropping it without [`MirrorRepair::commit`]
/// rolls everything back: the mirror keeps its previous rows and applied seq.
#[async_trait]
pub trait MirrorRepair: Send {
    /// Apply one export batch (same allowlists and source binding as [`MirrorStore::apply_rows`]; no seq check).
    async fn apply(&mut self, batch: &RowsBatch) -> StoreResult<ApplyStats>;

    /// Record `through_seq` (the module's high-water mark) and `generation` as the source's applied state, then
    /// commit. The caller acknowledges the module's log through `through_seq` afterwards.
    async fn commit(
        self: Box<Self>,
        through_seq: u64,
        generation: Option<&str>,
    ) -> StoreResult<RepairStats>;
}

/// Inventory, findings and run history.
#[async_trait]
pub trait StateStore: Send + Sync {
    /// Upsert asset and components, record a scan; one transaction. Port of
    /// `engine/inventory.save_inventory` **without** the classify step (the engine classifies on ingest).
    /// Returns the scan id.
    async fn save_inventory(&self, inv: &Inventory, job_id: Option<i64>) -> StoreResult<i64>;

    /// Whether the asset exists.
    async fn asset_exists(&self, asset_id: &str) -> StoreResult<bool>;

    /// Facts for the image reuse rule.
    async fn asset_reuse_facts(&self, asset_id: &str) -> StoreResult<Option<AssetReuseFacts>>;

    /// Replace `asset.meta` (e.g. `id_verified`). Fails with `NotFound` for an unknown asset.
    async fn update_asset_meta(&self, asset_id: &str, meta: &Map<String, Value>)
    -> StoreResult<()>;

    /// The reuse rule's write (`ops._reuse_image`): set `name` and `meta`, `last_seen` = now, in one statement.
    /// Fails with `NotFound` for an unknown asset. No scan row is written (the stored inventory is reused).
    async fn update_asset_reused(
        &self,
        asset_id: &str,
        name: Option<&str>,
        meta: &Map<String, Value>,
    ) -> StoreResult<()>;

    /// The asset's latest scan id.
    async fn latest_scan_id(&self, asset_id: &str) -> StoreResult<Option<i64>>;

    /// Replace the asset's findings by the complete set from a persisted `engine.match`, in one transaction,
    /// after checking that the latest scan id is still `based_on.latest_scan_id` (else [`StoreError::Stale`]).
    /// Returns the number of rows written.
    async fn replace_findings(
        &self,
        asset_id: &str,
        set: &[Finding],
        based_on: &BasedOn,
    ) -> StoreResult<u64>;

    /// Record a run that starts now (`running`); prunes runs beyond `JOB_KEEP`. Returns its id.
    async fn job_insert(&self, job: &NewJob) -> StoreResult<i64>;

    /// Finish a run (keeps the last `JOB_LOG_LINES` lines, sets `log_lines`).
    async fn job_finish(&self, job_id: i64, fin: &JobFinish) -> StoreResult<()>;

    /// Runs, newest first, without their log.
    async fn job_rows(&self, kind: Option<JobKind>, limit: i64) -> StoreResult<Vec<JobRow>>;

    /// One run with its log.
    async fn job_row(&self, job_id: i64) -> StoreResult<Option<JobRow>>;

    /// Runs left `running` by a process that is gone -> `error`/`interrupted`. Returns how many.
    async fn job_mark_interrupted(&self) -> StoreResult<u64>;

    /// Whether anything was ever written (drives the API's `no-db`).
    async fn is_initialized(&self) -> StoreResult<bool>;
}

/// The vulnerability mirror.
#[async_trait]
pub trait MirrorStore: Send + Sync {
    /// Apply one `secmonk-mirror-rows/1` batch in one transaction (table and column allowlists, at most 5000 ops,
    /// every row's `source` equal to `batch.source`; anything else is refused and nothing of the batch is
    /// written). Idempotent: the source's last applied `seq` and the batch's staging `generation` are recorded in
    /// the same transaction and a batch at or below that seq is skipped (`ApplyStats::skipped`), so a replay after
    /// a crash between apply and `source.ack` writes nothing twice. A batch that carries a `generation` is only
    /// compared within it: another generation, or an `acked_through` above the applied seq, writes nothing and
    /// answers `ApplyStats::needs_repair`.
    async fn apply_rows(&self, batch: &RowsBatch) -> StoreResult<ApplyStats>;

    /// The last batch seq applied for a source.
    async fn applied_seq(&self, source: &str) -> StoreResult<Option<u64>>;

    /// The last batch seq applied for a source and the staging generation it belongs to.
    async fn applied_state(&self, source: &str) -> StoreResult<Option<AppliedState>>;

    /// Forget a source's applied seq (tests and manual recovery; the repair path is [`MirrorStore::begin_repair`]).
    async fn reset_applied_seq(&self, source: &str) -> StoreResult<()>;

    /// Start replacing a source's mirror rows by a `source.export` stream: one transaction that first deletes every
    /// row of the source (`source` = it, or `<source>:<qualifier>` in `source_sync`), then applies the export
    /// batches, then records the applied state on [`MirrorRepair::commit`]. Holds the mirror's write connection
    /// until committed or dropped.
    async fn begin_repair(&self, source: &str) -> StoreResult<Box<dyn MirrorRepair>>;

    /// A source's sync state.
    async fn sync_state(&self, source: &str) -> StoreResult<Option<SyncState>>;

    /// Number of rows of `table` whose `source` column is `source` (the snapshot guard of a native source,
    /// rust ADR-0011).
    async fn count_rows(&self, table: MirrorTable, source: &str) -> StoreResult<u64>;

    /// Primary keys (column -> text value) of the rows of `table` whose `source` column is `source`, in key order.
    /// `affected` has no natural key: `Invalid`. Used by native sources to compute their deletes (rust ADR-0011).
    async fn row_keys(
        &self,
        table: MirrorTable,
        source: &str,
    ) -> StoreResult<Vec<Map<String, Value>>>;

    /// The rows of `table` whose `source` column is `source` and whose id column (`MirrorTable::id_column`) is one of
    /// `ids` (at most [`MAX_ROWS_IDS`]), in storage order: every writable column (`mirror_schema::spec`), text as
    /// strings, integers and reals as numbers, JSON columns parsed. `source_sync` (no id column) and too many ids are
    /// `Invalid`. Native sources read the stored rows of the records they rewrite through it (rust ADR-0012).
    async fn rows_by_id(
        &self,
        table: MirrorTable,
        source: &str,
        ids: &[String],
    ) -> StoreResult<Vec<Map<String, Value>>>;

    /// One page of the rows of `table` whose `source` column is `source`, in rowid order after the rowid `after`
    /// (`None`: from the start), at most `limit` (1..=[`MAX_ROWS_PAGE`]) rows as in [`MirrorStore::rows_by_id`];
    /// returns the rows and the rowid to continue after (`None` when fewer than `limit` rows were left). Native
    /// sources that replace a whole source compare the stored rows page by page through it (rust ADR-0012). Each
    /// page is a range scan of the rowid after the cursor (no sort of the source's rows), so all pages together read
    /// each row once. Not a snapshot: rows inserted between pages (also deleted and re-inserted `affected` rows) get
    /// higher rowids and appear in later pages.
    async fn rows_page(
        &self,
        table: MirrorTable,
        source: &str,
        after: Option<u64>,
        limit: usize,
    ) -> StoreResult<(Vec<Map<String, Value>>, Option<u64>)>;

    /// Whether any row was ever written.
    async fn is_initialized(&self) -> StoreResult<bool>;

    /// `PRAGMA wal_checkpoint(TRUNCATE)` (after a sync, with no reader in flight).
    async fn checkpoint(&self) -> StoreResult<()>;
}

/// Python's `db.dumps`: compact JSON, insertion order, non-ASCII kept; `None` for null.
pub fn dumps(v: &Value) -> Option<String> {
    if v.is_null() {
        None
    } else {
        serde_json::to_string(v).ok()
    }
}
