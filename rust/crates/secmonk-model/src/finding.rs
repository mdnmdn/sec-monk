//! Findings and `engine.match` params/results. Schema: `rust/contracts/schemas/engine/match.schema.json`.

use serde::{Deserialize, Serialize};

use crate::{Inventory, JsonMap};

/// Lifecycle status of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    /// Present in the latest scan.
    Open,
    /// The component no longer matches.
    Fixed,
    /// Hidden by the user (sticky).
    Suppressed,
}

impl FindingStatus {
    /// The stored string.
    pub fn as_str(self) -> &'static str {
        match self {
            FindingStatus::Open => "open",
            FindingStatus::Fixed => "fixed",
            FindingStatus::Suppressed => "suppressed",
        }
    }
}

/// One row of the `finding` table as `engine.match` returns it (`finding_set`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// `component.id` in the state database.
    pub component_id: i64,
    /// Canonical vulnerability id (CVE when available).
    pub vuln_id: String,
    /// Every matched advisory id or alias.
    pub advisory_ids: Vec<String>,
    /// `osv-package`, `cve-product`, `cpe-product`.
    pub matched_by: Option<String>,
    /// 1.0 for exact package matches.
    pub confidence: Option<f64>,
    /// First fixed version.
    #[serde(default)]
    pub fixed_version: Option<String>,
    /// `CRITICAL` ... `NONE`.
    #[serde(default)]
    pub severity: Option<String>,
    /// CVSS base score.
    #[serde(default)]
    pub cvss_score: Option<f64>,
    /// EPSS probability.
    #[serde(default)]
    pub epss: Option<f64>,
    /// In the CISA KEV catalog.
    pub kev: bool,
    /// `P1` ... `P4`.
    pub priority: Option<String>,
    /// Lifecycle status.
    pub status: FindingStatus,
    /// First seen.
    pub first_seen: Option<String>,
    /// Last seen.
    pub last_seen: Option<String>,
    /// When it became `fixed`.
    #[serde(default)]
    pub fixed_at: Option<String>,
    /// Distro triage label.
    #[serde(default)]
    pub triage: Option<String>,
    /// `debian-tracker` or `osv`.
    #[serde(default)]
    pub triage_source: Option<String>,
}

/// What a persisted match was computed from (staleness check of `replace_findings`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BasedOn {
    /// The asset's latest scan id when the module read the database.
    pub latest_scan_id: Option<i64>,
    /// Last mirror sync seen (informational).
    #[serde(
        default,
        deserialize_with = "crate::nullable::deserialize",
        skip_serializing_if = "Option::is_none"
    )]
    pub mirror_synced_at: Option<Option<String>>,
}

/// `engine.match` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    /// On the stored asset; returns the finding set for the host to store.
    Persisted,
    /// On an inventory in TEMP tables; nothing stored.
    Ephemeral,
}

/// `engine.match_asset` statistics.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MatchStats {
    /// Components considered.
    pub components: u64,
    /// Raw matches.
    pub matches: u64,
    /// Findings after merging.
    pub findings: u64,
    /// Withdrawn advisories skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<u64>,
    /// Patched by the distro.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patched: Option<u64>,
    /// Not affected per triage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_affected: Option<u64>,
}

/// Params of `engine.match`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum MatchParams {
    /// Match the stored asset.
    Persisted {
        /// Asset id.
        asset_id: String,
        /// Minimum confidence.
        min_confidence: f64,
        /// Rows in `view` (default 500).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        view_limit: Option<u32>,
    },
    /// Match an inventory without storing it.
    Ephemeral {
        /// The classified inventory.
        inventory: Box<Inventory>,
        /// Minimum confidence.
        min_confidence: f64,
        /// Rows in `view`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        view_limit: Option<u32>,
    },
}

/// Result of `engine.match`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchResult {
    /// Asset id.
    pub asset_id: String,
    /// Mode.
    pub mode: MatchMode,
    /// Statistics.
    pub stats: MatchStats,
    /// Persisted mode: what the set was computed from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub based_on: Option<BasedOn>,
    /// Persisted mode: the asset's complete finding set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_set: Option<Vec<Finding>>,
    /// API finding rows (`api/finding-row.schema.json`), at most `view_limit`.
    pub view: Vec<JsonMap>,
}
