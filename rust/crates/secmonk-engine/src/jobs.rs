//! Live jobs of this process (`web/jobs.py` `Job` and the in-memory half of `JobRunner`): the last `KEEP` jobs with
//! their live log; one job at a time. The stored half (run history) is the `job` table of the state store.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use secmonk_model::{JobKind, JobStatus};
use secmonk_safeio::scrub_text;
use serde_json::Value;
use tokio::task::{AbortHandle, JoinHandle};

use crate::payload::job_payload;

/// Jobs of this process kept in memory (`KEEP`).
pub const KEEP: usize = 20;
/// Live log lines per job (`MAX_LOG`).
pub const MAX_LOG: usize = 1000;
/// Characters per log line.
pub const MAX_LINE: usize = 500;

/// Mutable part of a job.
#[derive(Debug)]
pub struct JobState {
    pub status: JobStatus,
    pub finished: Option<String>,
    pub log: VecDeque<String>,
    pub result: Option<Value>,
    pub error: Option<String>,
}

/// One job of this process.
#[derive(Debug)]
pub struct Job {
    pub id: i64,
    pub kind: JobKind,
    pub title: String,
    /// Redacted (what is shown and stored).
    pub params: Value,
    pub started: String,
    pub state: Mutex<JobState>,
}

/// `_CTRL`: control characters except tab and newline.
fn is_ctrl(c: char) -> bool {
    matches!(c as u32, 0x00..=0x08 | 0x0b..=0x1f | 0x7f..=0x9f)
}

/// A log line as stored: control characters removed, URL secrets scrubbed, at most 500 chars.
pub fn log_line(msg: &str) -> String {
    let clean: String = msg.chars().filter(|c| !is_ctrl(*c)).collect();
    scrub_text(&clean).chars().take(MAX_LINE).collect()
}

impl Job {
    pub fn new(id: i64, kind: JobKind, title: String, params: Value, started: String) -> Job {
        Job {
            id,
            kind,
            title,
            params,
            started,
            state: Mutex::new(JobState {
                status: JobStatus::Running,
                finished: None,
                log: VecDeque::new(),
                result: None,
                error: None,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, JobState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `Job.say`.
    pub fn say(&self, msg: impl AsRef<str>) {
        let line = log_line(msg.as_ref());
        let mut st = self.lock();
        st.log.push_back(line);
        while st.log.len() > MAX_LOG {
            st.log.pop_front();
        }
    }

    pub fn is_running(&self) -> bool {
        self.lock().status == JobStatus::Running
    }

    pub fn log(&self) -> Vec<String> {
        self.lock().log.iter().cloned().collect()
    }

    /// Set the outcome (after it was stored).
    pub fn finish(&self, status: JobStatus, result: Option<Value>, error: Option<String>) {
        let mut st = self.lock();
        st.status = status;
        st.result = result;
        st.error = error;
        st.finished = Some(secmonk_model::time::now_iso());
    }

    /// `Job.to_dict`.
    pub fn to_dict(&self, include_log: bool) -> Value {
        let st = self.lock();
        let log: Vec<String> = st.log.iter().cloned().collect();
        job_payload(
            self.id,
            self.kind,
            "ui",
            Some(&self.title),
            Some(&self.params),
            Some(&self.started),
            st.finished.as_deref(),
            Some(st.status.as_str()),
            st.error.as_deref(),
            st.result.as_ref(),
            Some(&log),
            include_log,
            None,
            None,
        )
    }
}

/// The running job's task handles.
#[derive(Debug)]
pub struct Running {
    pub job: Arc<Job>,
    /// The work (collect/sync): aborting it drops every module call in flight (= `cancel`).
    pub work: AbortHandle,
    /// The supervisor that stores the outcome.
    pub done: JoinHandle<()>,
}

/// The in-memory half of `JobRunner`.
#[derive(Debug, Default)]
pub struct Live {
    pub jobs: VecDeque<Arc<Job>>,
    /// A start between its busy check and its job being listed (`JobRunner.starting`).
    pub starting: bool,
    pub running: Option<Running>,
}

impl Live {
    /// `JobRunner.busy`.
    pub fn busy(&self) -> bool {
        self.starting || self.jobs.iter().any(|j| j.is_running())
    }

    pub fn push(&mut self, job: Arc<Job>) {
        self.jobs.push_back(job);
        while self.jobs.len() > KEEP {
            self.jobs.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_lines_are_clean_and_capped() {
        let j = Job::new(
            1,
            JobKind::Scan,
            "t".into(),
            serde_json::json!({}),
            "s".into(),
        );
        j.say("a\x00b\x1bc https://u:p@h/x?k=v");
        j.say("x".repeat(900));
        let log = j.log();
        assert_eq!(log[0], "abc https://u@h/x");
        assert_eq!(log[1].len(), 500);
        for _ in 0..1100 {
            j.say("z");
        }
        assert_eq!(j.log().len(), MAX_LOG);
        let d = j.to_dict(false);
        assert_eq!(d["status"], "running");
        assert_eq!(d["log_lines"], 1000);
        assert!(d.get("log").is_none());
    }
}
