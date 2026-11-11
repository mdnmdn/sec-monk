//! Validated request parameters handed from `secmonk-api` to the engine (the API parses and bounds them like
//! `web/data.py`; the engine never sees a raw query string).

use serde::Serialize;

/// `GET /api/findings`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingsQuery {
    /// `P1..P4`, upper-cased.
    pub priority: Option<String>,
    pub asset: Option<String>,
    pub include_closed: bool,
    pub fixable: bool,
    pub hide_minor: bool,
    pub hide_deferred: bool,
    /// 1..=5000 (default 200).
    pub limit: u32,
}

/// `GET /api/vulns/search`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VulnSearchQuery {
    pub package: Option<String>,
    pub ecosystem: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    /// 1..=1000 (default 50).
    pub limit: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobKind {
    Scan,
    Sync,
}

/// `GET /api/jobs`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JobsQuery {
    pub kind: Option<JobKind>,
    /// 1..=200 (default 50).
    pub limit: u32,
}

/// `GET /api/discover`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscoverQuery {
    /// Blank (`None`) = this machine, else `[ssh://]user@host[:port]` or `k8s://<context>`.
    pub target: Option<String>,
    /// Repeatable `k=v`, blanks dropped; the allowed keys are checked by the engine (`DISCOVER_WEB_OPTS`).
    pub options: Vec<String>,
}

/// `GET /api/docker/containers`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DockerListQuery {
    pub host: Option<String>,
    pub context: Option<String>,
    pub all: bool,
    pub selector: Option<String>,
    pub options: Vec<String>,
}
