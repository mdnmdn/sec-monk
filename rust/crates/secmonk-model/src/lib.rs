//! Domain records shared by every sec-monk crate (`secmonk-model`).
//!
//! Plain serde types mirroring the JSON contracts in `rust/contracts/schemas/` (inventory, collect stream,
//! mirror rows, engine match results, run history, process snapshot). No I/O, no async: a crate that only
//! needs the data shapes depends on this one alone.
//!
//! Field order follows the Python dataclasses so that `serde_json` (with `preserve_order`) writes the same
//! JSON text as Python's `json.dumps(dataclasses.asdict(...))`.

pub mod finding;
pub mod inventory;
pub mod job;
pub mod nullable;
pub mod rows;
pub mod snapshot;
pub mod time;

pub use finding::{
    BasedOn, Finding, FindingStatus, MatchMode, MatchParams, MatchResult, MatchStats,
};
pub use inventory::{
    Asset, Category, CollectEnd, CollectItem, CollectParams, Component, ExpandResult,
    INVENTORY_SCHEMA, Inventory,
};
pub use job::{
    JOB_KEEP, JOB_LOG_LINES, JobFinish, JobKind, JobOrigin, JobOwner, JobPayload, JobRow,
    JobStatus, NewJob,
};
pub use rows::{
    AckParams, MIRROR_ROWS_SCHEMA, MirrorTable, RowOp, RowsBatch, SyncEnd, SyncEntry, SyncOptions,
    SyncParams, SyncSecrets,
};
pub use snapshot::{PROCESS_SNAPSHOT_SCHEMA, ProcessRecord, ProcessSnapshot};

/// A JSON object (`dict` in Python). Insertion order is preserved.
pub type JsonMap = serde_json::Map<String, serde_json::Value>;
