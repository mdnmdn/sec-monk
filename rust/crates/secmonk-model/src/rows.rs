//! The source row stream (`secmonk-mirror-rows/1`) and the `source.*` params/results.
//! Schemas: `rust/contracts/schemas/source/`. Applied by `secmonk-store` (`MirrorStore::apply_rows`).

use serde::{Deserialize, Serialize};

use crate::JsonMap;

/// Version string of the row stream format.
pub const MIRROR_ROWS_SCHEMA: &str = "secmonk-mirror-rows/1";

/// The mirror tables a source may write. Anything else is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorTable {
    /// `source_sync` (sync state per source).
    SourceSync,
    /// `raw_record` (the record as published).
    RawRecord,
    /// `vulnerability`.
    Vulnerability,
    /// `alias` edges.
    Alias,
    /// `affected` (no natural key).
    Affected,
    /// `kev`.
    Kev,
    /// `epss`.
    Epss,
    /// `distro_triage`.
    DistroTriage,
}

impl MirrorTable {
    /// Every mirror table.
    pub const ALL: [MirrorTable; 8] = [
        MirrorTable::SourceSync,
        MirrorTable::RawRecord,
        MirrorTable::Vulnerability,
        MirrorTable::Alias,
        MirrorTable::Affected,
        MirrorTable::Kev,
        MirrorTable::Epss,
        MirrorTable::DistroTriage,
    ];

    /// The SQL table name.
    pub fn as_str(self) -> &'static str {
        match self {
            MirrorTable::SourceSync => "source_sync",
            MirrorTable::RawRecord => "raw_record",
            MirrorTable::Vulnerability => "vulnerability",
            MirrorTable::Alias => "alias",
            MirrorTable::Affected => "affected",
            MirrorTable::Kev => "kev",
            MirrorTable::Epss => "epss",
            MirrorTable::DistroTriage => "distro_triage",
        }
    }
}

/// One row operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum RowOp {
    /// Insert, or update the given columns on primary-key conflict (`affected`: plain insert).
    Upsert {
        /// Target table.
        table: MirrorTable,
        /// Column -> value (JSON columns carry JSON values).
        row: JsonMap,
    },
    /// Delete by primary key; on `affected` the key is a whole row and deletes one matching row.
    Delete {
        /// Target table.
        table: MirrorTable,
        /// Key column -> value.
        key: JsonMap,
    },
}

impl RowOp {
    /// The table this op writes.
    pub fn table(&self) -> MirrorTable {
        match self {
            RowOp::Upsert { table, .. } | RowOp::Delete { table, .. } => *table,
        }
    }
}

/// A `source.sync` / `source.export` stream item: one batch, applied in one transaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowsBatch {
    /// Always `"rows"`.
    pub kind: String,
    /// Batch sequence number (from 1), acknowledged with `source.ack`.
    pub seq: u64,
    /// The source that produced it.
    pub source: String,
    /// Operations, in order.
    pub ops: Vec<RowOp>,
    /// Identity of the module's staging database (random, persisted, new when the file is recreated). Seqs are
    /// only comparable within one generation: the host never skips a batch of another generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    /// The highest seq the module had acknowledged for this source when it streamed the batch. Above the host's
    /// applied seq, the mirror lost rows the staging log already dropped: the host repairs from `source.export`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acked_through: Option<u64>,
}

/// Options of `source.sync` (the CLI's `secmonk sync` flags).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncOptions {
    /// Local file or directory instead of a download.
    #[serde(
        default,
        deserialize_with = "crate::nullable::deserialize",
        skip_serializing_if = "Option::is_none"
    )]
    pub path: Option<Option<String>>,
    /// OSV ecosystems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystems: Option<Vec<String>>,
    /// Record ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    /// Only records modified since.
    #[serde(
        default,
        deserialize_with = "crate::nullable::deserialize",
        skip_serializing_if = "Option::is_none"
    )]
    pub since: Option<Option<String>>,
    /// Ignore cursors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<bool>,
    /// Stop after this many records.
    #[serde(
        default,
        deserialize_with = "crate::nullable::deserialize",
        skip_serializing_if = "Option::is_none"
    )]
    pub limit: Option<Option<u64>>,
}

/// Secrets passed to a source call (never in the module environment or a log).
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncSecrets {
    /// NVD API key.
    #[serde(default)]
    pub api_key: Option<String>,
}

impl std::fmt::Debug for SyncSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncSecrets")
            .field("api_key", &self.api_key.as_ref().map(|_| "***"))
            .finish()
    }
}

/// Params of `source.sync`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncParams {
    /// Source name.
    pub source: String,
    /// Options.
    pub options: SyncOptions,
    /// Secrets, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SyncSecrets>,
}

/// Params of `source.ack` and `source.export`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckParams {
    /// Source name.
    pub source: String,
    /// Last applied batch.
    pub through_seq: u64,
}

/// The run's sync entry (`ops.sync_source` result).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncEntry {
    /// Source name.
    pub source: String,
    /// `ok`, `partial` or `error`.
    pub status: String,
    /// Records processed.
    pub records: u64,
    /// Duration.
    pub seconds: f64,
    /// Message (error text, partial reason).
    pub message: Option<String>,
}

/// `end.result` of `source.sync`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncEnd {
    /// The sync entry.
    pub entry: SyncEntry,
    /// Batches streamed.
    pub batches: u64,
    /// Sequence number of the last batch.
    pub last_seq: u64,
    /// Operations streamed.
    pub ops: u64,
}
