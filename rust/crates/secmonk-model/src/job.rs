//! Run history (`job` table) and the API job payload (`api/job.schema.json`, `reports.job_payload`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Runs kept; older ones are pruned when a new one starts (`db.JOB_KEEP`).
pub const JOB_KEEP: i64 = 200;
/// Log lines kept per stored run (`db.JOB_LOG_LINES`).
pub const JOB_LOG_LINES: usize = 300;

/// Kind of run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobKind {
    /// Collect (+ save) + match.
    Scan,
    /// Vulnerability source sync.
    Sync,
}

/// Who started a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobOrigin {
    /// The command line.
    Cli,
    /// The UI.
    Ui,
}

/// Status of a run. `queued` and `cancelled` are reserved (not written by the prototype).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    /// Waiting (reserved).
    Queued,
    /// In progress.
    Running,
    /// Done.
    Ok,
    /// Done with skipped parts.
    Partial,
    /// Failed (or interrupted).
    Error,
    /// Cancelled (reserved).
    Cancelled,
}

impl JobKind {
    /// Stored string.
    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::Scan => "scan",
            JobKind::Sync => "sync",
        }
    }
}

impl JobOrigin {
    /// Stored string.
    pub fn as_str(self) -> &'static str {
        match self {
            JobOrigin::Cli => "cli",
            JobOrigin::Ui => "ui",
        }
    }
}

impl JobStatus {
    /// Stored string.
    pub fn as_str(self) -> &'static str {
        match self {
            JobStatus::Queued => "queued",
            JobStatus::Running => "running",
            JobStatus::Ok => "ok",
            JobStatus::Partial => "partial",
            JobStatus::Error => "error",
            JobStatus::Cancelled => "cancelled",
        }
    }

    /// Parse a stored string.
    pub fn parse(s: &str) -> Option<JobStatus> {
        Some(match s {
            "queued" => JobStatus::Queued,
            "running" => JobStatus::Running,
            "ok" => JobStatus::Ok,
            "partial" => JobStatus::Partial,
            "error" => JobStatus::Error,
            "cancelled" => JobStatus::Cancelled,
            _ => return None,
        })
    }
}

/// The process recording a run (`db.this_owner`): stale `running` detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobOwner {
    /// Process id.
    pub pid: i64,
    /// Host name.
    pub host: String,
}

/// A run that starts now (`db.job_insert` arguments). `params` must already be redacted.
#[derive(Debug, Clone, PartialEq)]
pub struct NewJob {
    /// Kind.
    pub kind: JobKind,
    /// Origin.
    pub origin: JobOrigin,
    /// Title shown in lists.
    pub title: Option<String>,
    /// Redacted parameters.
    pub params: Option<Value>,
    /// Start time (default: now).
    pub started_at: Option<String>,
    /// The recording process.
    pub owner: JobOwner,
}

/// The end of a run (`db.job_finish` arguments). Error and log must already be scrubbed.
#[derive(Debug, Clone, PartialEq)]
pub struct JobFinish {
    /// Final status.
    pub status: JobStatus,
    /// Result payload.
    pub result: Option<Value>,
    /// Error text.
    pub error: Option<String>,
    /// Log lines (the last `JOB_LOG_LINES` are kept).
    pub log: Vec<String>,
    /// `reports.job_summary` of the result.
    pub summary: Option<Value>,
}

/// One stored run. List queries leave `log` empty (`None`) and fill `log_lines`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobRow {
    /// Id.
    pub id: i64,
    /// Kind.
    pub kind: JobKind,
    /// Origin.
    pub origin: JobOrigin,
    /// Title.
    pub title: Option<String>,
    /// Redacted params.
    pub params: Option<Value>,
    /// Status (`None` only for rows written by foreign code).
    pub status: Option<JobStatus>,
    /// Start.
    pub started_at: Option<String>,
    /// End.
    pub finished_at: Option<String>,
    /// Error.
    pub error: Option<String>,
    /// Result.
    pub result: Option<Value>,
    /// Log lines (single-row reads only).
    pub log: Option<Vec<String>>,
    /// Summary.
    pub summary: Option<Value>,
    /// Owner.
    pub owner: Option<JobOwner>,
    /// Number of stored log lines.
    pub log_lines: i64,
}

/// The API's job payload (`reports.job_payload`, `api/job.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobPayload {
    /// Id.
    pub id: i64,
    /// Kind.
    pub kind: JobKind,
    /// Origin.
    pub origin: JobOrigin,
    /// Title.
    pub title: Option<String>,
    /// Redacted params.
    pub params: Value,
    /// Start.
    pub started: Option<String>,
    /// End.
    pub finished: Option<String>,
    /// Status.
    pub status: JobStatus,
    /// Error.
    pub error: Option<String>,
    /// Result.
    pub result: Option<Value>,
    /// Summary.
    pub summary: Value,
    /// Number of log lines.
    pub log_lines: i64,
    /// Log (detail view only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<Vec<String>>,
}
