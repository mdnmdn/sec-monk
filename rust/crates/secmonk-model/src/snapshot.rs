//! `secmonk-process-snapshot/1` (`collectors/process/snapshot.py`). Readers stay lenient: unknown keys are
//! kept (`extra`) so a snapshot round-trips; validation and caps are the reader's job.

use serde::{Deserialize, Serialize};

use crate::JsonMap;

/// Value of the `schema` key.
pub const PROCESS_SNAPSHOT_SCHEMA: &str = "secmonk-process-snapshot/1";

/// One process. Only `pid` is required; everything else is kept as given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessRecord {
    /// Process id.
    pub pid: i64,
    /// Other keys (`ppid`, `uid`, `user`, `exe`, `started`, `args`, `label`, `cgroup`, `container`, ...).
    #[serde(flatten)]
    pub extra: JsonMap,
}

/// A process snapshot of one host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    /// `secmonk-process-snapshot/1`.
    pub schema: String,
    /// `linux`, `darwin`, ...
    pub platform: String,
    /// Host name.
    pub host: String,
    /// When it was taken.
    pub taken_at: String,
    /// OS facts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<JsonMap>,
    /// Processes.
    pub processes: Vec<ProcessRecord>,
    /// Launch items (launchd, systemd, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_items: Option<Vec<JsonMap>>,
    /// Facts per executable path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executables: Option<JsonMap>,
    /// Warnings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
    /// Where it came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<JsonMap>,
    /// Unknown keys (kept).
    #[serde(flatten)]
    pub extra: JsonMap,
}
