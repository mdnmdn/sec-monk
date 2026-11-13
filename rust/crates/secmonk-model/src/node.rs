//! Mirror-node types (`secmonk-model::node`): what a state node sends to a match service, what it gets back,
//! source versions, the change feed and vulnerability summaries (proposal `_docs/inbox/2026-11-12-mirror-nodes-feed-match-service.md`
//! §3.2-3.5, brief `rust/_docs/plans/node-server-design.md` §6).
//!
//! Plain serde types; field order is the wire order. Request types refuse unknown fields; responses tolerate
//! them (a newer server may add fields). Traits: `secmonk-traits::node`. Storage: `secmonk-store::node`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Category, Component, JsonMap, RowsBatch};

// The matcher version (the engine's matching rules, version comparison and lookup keys) is not a constant of the
// model: it is computed by the build that serves it (`secmonk_engine::node::matcher_version`,
// `py-engine/<secmonk version>+keys/<KEYS_VERSION>`). **A change invalidates every match a client stored**, even
// when no vulnerability data changed (proposal §3.2 rule 6): a client that holds answers computed under another
// matcher version re-sends all its components.

/// Most components in one `match.components` request.
pub const MAX_COMPONENTS: usize = 1000;

/// Most ids in one `vulninfo.summaries` request.
pub const MAX_IDS: usize = 500;

/// Default overlap, in seconds, that deltas read below the client's version (upstream clocks are not exact,
/// proposal §3.2 rule 3). Records are replaced whole, so the overlap only costs bandwidth.
pub const DEFAULT_OVERLAP_S: u64 = 3600;

/// The `meta` keys of a component that identify what it is, and so travel to a match service. Anything else
/// (paths, users, labels, the asset's facts) stays on the state node. Proposal §1.
pub const IDENTITY_META_KEYS: [&str; 11] = [
    "source_package",
    "source_version",
    "product",
    "product_source",
    "product_alts",
    "vendor_alts",
    "vendor_hint",
    "brew_kind",
    "brew_name",
    "patched_cves",
    "confidence",
];

// ---------------------------------------------------------------------------------------------------------------
// component identity and lookup keys

/// The identity of a component, as sent to a match service: [`Component`] without where it was found
/// (`source_path`) and with only the allowlisted `meta` ([`IDENTITY_META_KEYS`]). Never carries an asset id, a
/// path, a user or labels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentIdentity {
    /// Name as found.
    pub name: String,
    /// Version as found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Category.
    pub category: Category,
    /// Package URL, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// CPE 2.3, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
    /// Vendor, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// OSV ecosystem used for matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    /// The allowlisted identity facts ([`IDENTITY_META_KEYS`]).
    #[serde(default, skip_serializing_if = "JsonMap::is_empty")]
    pub meta: JsonMap,
}

impl ComponentIdentity {
    /// The identity of `c`: copies the identity fields and, from `meta`, only the keys of
    /// [`IDENTITY_META_KEYS`] (in that order). `source_path`, `meta.paths` and every other key are dropped.
    pub fn from_component(c: &Component) -> ComponentIdentity {
        let mut meta = JsonMap::new();
        for k in IDENTITY_META_KEYS {
            if let Some(v) = c.meta.get(k) {
                meta.insert(k.to_owned(), v.clone());
            }
        }
        ComponentIdentity {
            name: c.name.clone(),
            version: c.version.clone(),
            category: c.category,
            purl: c.purl.clone(),
            cpe: c.cpe.clone(),
            vendor: c.vendor.clone(),
            ecosystem: c.ecosystem.clone(),
            meta,
        }
    }

    /// The component key: the same as [`Component::key`] of the component it came from (the purl if any, else
    /// `name:<category>/<vendor lowercase>/<name lowercase>@<version>`), so a client finds its stored component
    /// from an answer's `key` without recomputing anything.
    pub fn key(&self) -> String {
        if let Some(p) = self.purl.as_deref().filter(|p| !p.is_empty()) {
            return p.to_string();
        }
        format!(
            "name:{}/{}/{}@{}",
            self.category.as_str(),
            self.vendor.as_deref().unwrap_or("").to_lowercase(),
            self.name.to_lowercase(),
            self.version.as_deref().unwrap_or("")
        )
    }
}

/// Lookup key of a package row: `pkg:<lower(ecosystem)>/<lower(package)>`. **All lookup keys are lowercase**, on
/// both sides: the mirror derives them from `affected` rows with this function and the match service derives a
/// component's keys with it too (`secmonk-engine::node::component_lookup_keys`), so a case difference between an
/// ecosystem's spelling and a stored row can only add keys (a safe superset), never lose one.
pub fn pkg_key(ecosystem: &str, package: &str) -> String {
    format!(
        "pkg:{}/{}",
        ecosystem.to_lowercase(),
        package.to_lowercase()
    )
}

/// Lookup key of a product row: `prod:<product>`, normalized as `affected.product` is (Python
/// `norm_vendor_product`: lowercase, `_` as a space, runs of whitespace as one space, trimmed). Vendor is not part
/// of it: a coarse key is a safe superset.
pub fn prod_key(product: &str) -> String {
    let p = product.to_lowercase().replace('_', " ");
    format!(
        "prod:{}",
        p.split_whitespace().collect::<Vec<_>>().join(" ")
    )
}

/// The ecosystem of a `pkg:<ecosystem>/<package>` key (the text between `pkg:` and the first `/`), `None` for
/// any other key (lowercase, as every key). Used to pick the components a `resync` of one ecosystem concerns.
pub fn lookup_key_ecosystem(key: &str) -> Option<&str> {
    key.strip_prefix("pkg:")?.split_once('/').map(|(e, _)| e)
}

// ---------------------------------------------------------------------------------------------------------------
// match.components

/// One stored or answered match of a component with a vulnerability (what `finding` copies before scoring).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComponentMatch {
    /// Canonical vulnerability id (CVE when available).
    pub vuln_id: String,
    /// Every matched advisory id or alias.
    #[serde(default)]
    pub advisory_ids: Vec<String>,
    /// `osv-package`, `cve-product`, `cpe-product`.
    #[serde(default)]
    pub matched_by: Option<String>,
    /// 1.0 for exact package matches. The client applies its own `min_confidence`.
    #[serde(default)]
    pub confidence: Option<f64>,
    /// First fixed version.
    #[serde(default)]
    pub fixed_version: Option<String>,
    /// Distro triage label.
    #[serde(default)]
    pub triage: Option<String>,
    /// `debian-tracker` or `osv`.
    #[serde(default)]
    pub triage_source: Option<String>,
}

/// Request of `match.components`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchComponentsRequest {
    /// At most [`MAX_COMPONENTS`] distinct components.
    pub components: Vec<ComponentIdentity>,
    /// Only matches at or above this confidence; `None`: all (a client that applies its own threshold asks for all).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<f64>,
}

/// The answer for one component.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComponentResult {
    /// The component key ([`ComponentIdentity::key`]).
    pub key: String,
    /// The complete match set.
    pub matches: Vec<ComponentMatch>,
    /// The lookup keys the match used (`pkg:...`, `prod:...`); a change of a row under one of them can change
    /// this component's matches.
    pub lookup_keys: Vec<String>,
}

/// What a mirror covers: a "no match" outside it is not "not vulnerable" (proposal §3.3).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Coverage {
    /// Sources with a served version.
    pub sources: Vec<String>,
    /// Ecosystems that have `affected` rows (sorted).
    pub ecosystems: Vec<String>,
}

/// Response of `match.components`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchComponentsResponse {
    /// One per requested component, in request order.
    pub results: Vec<ComponentResult>,
    /// The versions the answer was computed at.
    pub as_of: Versions,
    /// What the mirror covers.
    pub coverage: Coverage,
}

// ---------------------------------------------------------------------------------------------------------------
// versions

/// Whether a source's updates are per record or the whole snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VersionKind {
    /// Per record: a delta is the records with `modified` after the version (nvd, osv, cvelist, euvd, msrc).
    Record,
    /// The whole table is replaced (kev, epss, debian-tracker).
    Snapshot,
}

impl VersionKind {
    /// The stored / wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            VersionKind::Record => "record",
            VersionKind::Snapshot => "snapshot",
        }
    }

    /// Parse the stored string.
    pub fn parse(s: &str) -> Option<VersionKind> {
        match s {
            "record" => Some(VersionKind::Record),
            "snapshot" => Some(VersionKind::Snapshot),
            _ => None,
        }
    }

    /// The kind of a source that has not recorded one: `snapshot` for `kev`, `epss` and `debian-tracker`, else
    /// `record`.
    pub fn default_for(source: &str) -> VersionKind {
        match source {
            "kev" | "epss" | "debian-tracker" => VersionKind::Snapshot,
            _ => VersionKind::Record,
        }
    }
}

/// The served version of one source: `(source, upstream version, importer version)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceVersion {
    /// Source name (`nvd`, `osv:PyPI`, `kev`, ...).
    pub source: String,
    /// The upstream version the last COMPLETE import reached (a `modified` high-water, a catalog version, a score
    /// date); `None` when the source never completed an import.
    pub version: Option<String>,
    /// The importer that wrote the rows (`rust/1`, `py-sources/1`, `unknown`). Must not contain `@`. A different
    /// importer is a different version: the rows can differ.
    pub importer: String,
    /// Per record or snapshot.
    pub kind: VersionKind,
    /// Records in the last sync (`source_sync.records`).
    pub records: u64,
    /// When the last sync finished.
    pub last_sync: Option<String>,
    /// Status of the last sync (`ok`, `partial`, `error`): informational, the version only moves on complete runs.
    pub status: Option<String>,
}

impl SourceVersion {
    /// The compact `since` token `"<importer>@<version>"`, `None` without a version.
    pub fn token(&self) -> Option<String> {
        self.version
            .as_deref()
            .map(|v| since_token(&self.importer, v))
    }
}

/// `"<importer>@<version>"`.
pub fn since_token(importer: &str, version: &str) -> String {
    format!("{importer}@{version}")
}

/// Split a `since` token at its first `@` into `(importer, version)` (the version may contain `@`, the importer
/// may not). `None` when there is no `@` or either side is empty.
pub fn parse_since_token(token: &str) -> Option<(&str, &str)> {
    token
        .split_once('@')
        .filter(|(i, v)| !i.is_empty() && !v.is_empty())
}

/// The versions of a node: its matcher and its sources.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Versions {
    /// The matcher version of the node (`secmonk_engine::node::matcher_version`).
    pub matcher: String,
    /// Per source name.
    pub sources: BTreeMap<String, SourceVersion>,
}

impl Versions {
    /// Versions of `sources` under `matcher`.
    pub fn new(matcher: &str, sources: impl IntoIterator<Item = SourceVersion>) -> Versions {
        Versions {
            matcher: matcher.to_owned(),
            sources: sources.into_iter().map(|s| (s.source.clone(), s)).collect(),
        }
    }

    /// The compact form a client sends back as `since`: source -> `"<importer>@<version>"`, for the sources that
    /// have a version.
    pub fn since(&self) -> BTreeMap<String, String> {
        self.sources
            .iter()
            .filter_map(|(k, v)| v.token().map(|t| (k.clone(), t)))
            .collect()
    }
}

/// The versions a stored answer was computed at, as a client keeps them: the matcher and the compact `since` map.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsOf {
    /// Matcher version.
    pub matcher: String,
    /// Source -> `"<importer>@<version>"`.
    pub since: BTreeMap<String, String>,
}

impl Versions {
    /// The [`AsOf`] of these versions.
    pub fn as_of(&self) -> AsOf {
        AsOf {
            matcher: self.matcher.clone(),
            since: self.since(),
        }
    }
}

/// `since` minus `overlap_s` seconds, in the same text shape (so it compares as text with stored `modified`
/// values); `since` unchanged when it is not an ISO timestamp (a version such as an ETag or a catalog version has
/// no overlap). Deltas read `modified > apply_overlap(since, DEFAULT_OVERLAP_S)`.
pub fn apply_overlap(since: &str, overlap_s: u64) -> String {
    i64::try_from(overlap_s)
        .ok()
        .and_then(|o| crate::time::shift_iso(since, -o))
        .unwrap_or_else(|| since.to_owned())
}

// ---------------------------------------------------------------------------------------------------------------
// match.changes

/// Request of `match.changes`: versions only, never an inventory.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangesRequest {
    /// Source -> `"<importer>@<version>"` of the client's last answer ([`Versions::since`]).
    pub since: BTreeMap<String, String>,
    /// The matcher version of the client's last answer. When it differs from the server's, every source answers
    /// `resync` (proposal §3.2 rule 6). Absent: not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
}

/// What changed in one source since the client's version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "SourceChangesWire", into = "SourceChangesWire")]
pub enum SourceChanges {
    /// `{ "changed_keys": [...], "changed_ids": [...] }`: lookup keys of the rows changed and ids of the
    /// vulnerabilities changed.
    Changed {
        /// Lookup keys of the changed `affected` rows (sorted, distinct).
        changed_keys: Vec<String>,
        /// Changed vulnerability ids (sorted, distinct).
        changed_ids: Vec<String>,
    },
    /// `{ "resync": "<reason>" }`: the client's version is unknown, too old, or from another importer or matcher.
    Resync(String),
    /// `{ "unchanged": true }`.
    Unchanged,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceChangesWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    changed_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    changed_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resync: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unchanged: Option<bool>,
}

impl From<SourceChanges> for SourceChangesWire {
    fn from(c: SourceChanges) -> Self {
        let empty = SourceChangesWire {
            changed_keys: None,
            changed_ids: None,
            resync: None,
            unchanged: None,
        };
        match c {
            SourceChanges::Changed {
                changed_keys,
                changed_ids,
            } => SourceChangesWire {
                changed_keys: Some(changed_keys),
                changed_ids: Some(changed_ids),
                ..empty
            },
            SourceChanges::Resync(r) => SourceChangesWire {
                resync: Some(r),
                ..empty
            },
            SourceChanges::Unchanged => SourceChangesWire {
                unchanged: Some(true),
                ..empty
            },
        }
    }
}

impl TryFrom<SourceChangesWire> for SourceChanges {
    type Error = String;

    fn try_from(w: SourceChangesWire) -> Result<Self, String> {
        match w {
            SourceChangesWire {
                changed_keys: Some(changed_keys),
                changed_ids: Some(changed_ids),
                resync: None,
                unchanged: None,
            } => Ok(SourceChanges::Changed {
                changed_keys,
                changed_ids,
            }),
            SourceChangesWire {
                changed_keys: None,
                changed_ids: None,
                resync: Some(r),
                unchanged: None,
            } => Ok(SourceChanges::Resync(r)),
            SourceChangesWire {
                changed_keys: None,
                changed_ids: None,
                resync: None,
                unchanged: Some(true),
            } => Ok(SourceChanges::Unchanged),
            _ => Err("a source's changes are exactly one of {changed_keys, changed_ids}, {resync}, {unchanged: true}".into()),
        }
    }
}

/// Response of `match.changes`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangesResponse {
    /// Per source the client named in `since`, plus the sources the server has that the client did not name
    /// (`resync`: new to the client).
    pub sources: BTreeMap<String, SourceChanges>,
    /// The versions the answer is current at: what the client stores as its next `since`.
    pub as_of: Versions,
}

// ---------------------------------------------------------------------------------------------------------------
// vulninfo

/// What a report shows about a vulnerability, merged over the mirror's sources (cvss from the nvd or cvelist row
/// first), plus KEV and EPSS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnSummary {
    /// The id asked for.
    pub id: String,
    /// Ids related to it through the alias table (both directions), sorted.
    pub aliases: Vec<String>,
    /// Short description.
    pub summary: Option<String>,
    /// `CRITICAL` ... `NONE`.
    pub severity: Option<String>,
    /// CVSS base score.
    pub cvss_score: Option<f64>,
    /// CVSS vector (of the row the score came from).
    pub cvss_vector: Option<String>,
    /// Earliest publication.
    pub published: Option<String>,
    /// Latest modification.
    pub modified: Option<String>,
    /// Withdrawal time, if withdrawn.
    pub withdrawn: Option<String>,
    /// In the CISA KEV catalog.
    pub kev: bool,
    /// KEV `date_added`.
    pub kev_date_added: Option<String>,
    /// EPSS probability.
    pub epss: Option<f64>,
    /// EPSS percentile.
    pub epss_percentile: Option<f64>,
    /// The sources that have a row for it (`kev` / `epss` included when they have one), sorted.
    pub sources: Vec<String>,
}

/// Request of `vulninfo.summaries`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummariesRequest {
    /// At most [`MAX_IDS`] ids.
    pub ids: Vec<String>,
}

/// Response of `vulninfo.summaries`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SummariesResponse {
    /// One per id the mirror knows, in request order.
    pub summaries: Vec<VulnSummary>,
    /// Ids the mirror has nothing for.
    pub missing: Vec<String>,
}

// ---------------------------------------------------------------------------------------------------------------
// feed

/// `feed.status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedStatus {
    /// The serving node, if it has an id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// The matcher version of the node (`secmonk_engine::node::matcher_version`).
    pub matcher: String,
    /// Per source, sorted by name.
    pub sources: Vec<SourceVersion>,
}

/// Request of `feed.since`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedSinceRequest {
    /// Source name (a base source: `osv`, not `osv:PyPI`).
    pub source: String,
    /// The version the follower holds (a `modified` high-water for a record source); `None`: everything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// The opaque cursor of the previous page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    /// Records (record sources) or rows (snapshot sources) per page; the server clamps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Whether a feed page continues a delta or is part of a whole snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedMode {
    /// Records changed since the follower's version; replace each whole.
    Delta,
    /// The whole source: the follower deletes what is not in it.
    Snapshot,
}

/// One page of `feed.since`.
///
/// Batches are `secmonk-mirror-rows/1` with page-local `seq` (from 1) and no generation: the follower renumbers
/// when it applies them. A record is a replace unit, in this op order: `delete affected {source, vuln_id}` (the
/// marker: "replace this record's children"; the follower expands it against its own rows, see
/// `secmonk-store` `MirrorNodeStore::localize_feed_batch`), `upsert vulnerability`, `upsert raw_record`, `upsert
/// alias` per alias, `upsert affected` per row. A snapshot page is upserts only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedPage {
    /// Source name.
    pub source: String,
    /// The server's version of that source now.
    pub version: SourceVersion,
    /// Delta or snapshot.
    pub mode: FeedMode,
    /// The rows.
    pub batches: Vec<RowsBatch>,
    /// Cursor of the next page; `None` on the last page.
    pub next_page: Option<String>,
}

/// What a node is and offers (`GET /node/v1/info`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node identity.
    pub node_id: String,
    /// Roles it serves (`feed`, `match`, `vulninfo`).
    pub roles: Vec<String>,
    /// The matcher version of the node (`secmonk_engine::node::matcher_version`).
    pub matcher: String,
    /// Whether it has a mirror.
    pub mirror: bool,
    /// Its source versions (empty without a mirror).
    pub sources: Vec<SourceVersion>,
}

/// A recorded difference between two versions of a snapshot source (so a client one or few versions behind gets
/// a delta instead of the whole snapshot).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotDiff {
    /// Source.
    pub source: String,
    /// The version this diff leads to.
    pub version: String,
    /// The version it started from (`None`: the first recorded one).
    pub prev_version: Option<String>,
    /// When it was recorded.
    pub created_at: String,
    /// Changed vulnerability ids.
    pub ids: Vec<String>,
    /// Lookup keys of the changed rows.
    pub keys: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn component() -> Component {
        serde_json::from_value(json!({
            "name": "OpenSSL", "version": "3.0.2", "category": "os-package",
            "purl": "pkg:deb/ubuntu/openssl@3.0.2", "vendor": "Ubuntu", "ecosystem": "Ubuntu:22.04",
            "source_path": "/home/alice/x",
            "meta": {"paths": ["/home/alice/x"], "user": "alice", "labels": {"a": "b"},
                     "source_package": "openssl", "patched_cves": ["CVE-1"], "product": "openssl"}
        }))
        .unwrap()
    }

    #[test]
    fn identity_copies_only_the_allowlist() {
        let c = component();
        let id = ComponentIdentity::from_component(&c);
        assert_eq!(id.key(), c.key());
        let j = serde_json::to_string(&id).unwrap();
        for leak in ["alice", "paths", "labels", "/home"] {
            assert!(!j.contains(leak), "{leak} in {j}");
        }
        assert_eq!(
            id.meta.keys().collect::<Vec<_>>(),
            ["source_package", "product", "patched_cves"]
        );
        let mut c = component();
        c.purl = None;
        assert_eq!(
            ComponentIdentity::from_component(&c).key(),
            "name:os-package/ubuntu/openssl@3.0.2"
        );
        assert_eq!(ComponentIdentity::from_component(&c).key(), c.key());
    }

    #[test]
    fn requests_refuse_unknown_fields() {
        assert!(
            serde_json::from_value::<MatchComponentsRequest>(
                json!({"components": [], "asset_id": "x"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<ComponentIdentity>(
                json!({"name": "a", "category": "library", "source_path": "/x"})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<SummariesRequest>(json!({"ids": [], "x": 1})).is_err());
        assert!(serde_json::from_value::<ChangesRequest>(json!({"since": {}, "x": 1})).is_err());
        assert!(
            serde_json::from_value::<FeedSinceRequest>(json!({"source": "nvd", "x": 1})).is_err()
        );
    }

    #[test]
    fn lookup_keys() {
        assert_eq!(pkg_key("PyPI", "requests"), "pkg:pypi/requests");
        assert_eq!(
            pkg_key("Maven", "org.Apache:Log4j"),
            "pkg:maven/org.apache:log4j"
        );
        assert_eq!(prod_key("OpenSSL"), "prod:openssl");
        assert_eq!(
            prod_key(" Internet_Explorer  11 "),
            "prod:internet explorer 11"
        );
        assert_eq!(
            lookup_key_ecosystem(&pkg_key("Debian:12", "openssl")),
            Some("debian:12")
        );
        assert_eq!(lookup_key_ecosystem("prod:openssl"), None);
    }

    #[test]
    fn since_tokens_and_versions() {
        let sv = |s: &str, v: Option<&str>| SourceVersion {
            source: s.into(),
            version: v.map(Into::into),
            importer: "rust/1".into(),
            kind: VersionKind::Record,
            records: 3,
            last_sync: None,
            status: Some("ok".into()),
        };
        let v = Versions::new(
            "py-engine/test",
            [sv("nvd", Some("2026-01-01T00:00:00Z")), sv("osv", None)],
        );
        let since = v.since();
        assert_eq!(since.len(), 1);
        assert_eq!(since["nvd"], "rust/1@2026-01-01T00:00:00Z");
        assert_eq!(
            parse_since_token(&since["nvd"]),
            Some(("rust/1", "2026-01-01T00:00:00Z"))
        );
        assert_eq!(parse_since_token("a@b@c"), Some(("a", "b@c")));
        assert_eq!(parse_since_token("@x"), None);
        assert_eq!(parse_since_token("none"), None);
    }

    #[test]
    fn source_changes_wire_shapes() {
        let c = SourceChanges::Changed {
            changed_keys: vec!["pkg:npm/x".into()],
            changed_ids: vec!["CVE-1".into()],
        };
        assert_eq!(
            serde_json::to_value(&c).unwrap(),
            json!({"changed_keys": ["pkg:npm/x"], "changed_ids": ["CVE-1"]})
        );
        assert_eq!(
            serde_json::to_value(SourceChanges::Resync("importer changed".into())).unwrap(),
            json!({"resync": "importer changed"})
        );
        assert_eq!(
            serde_json::to_value(SourceChanges::Unchanged).unwrap(),
            json!({"unchanged": true})
        );
        for c in [
            c,
            SourceChanges::Resync("r".into()),
            SourceChanges::Unchanged,
        ] {
            let back: SourceChanges =
                serde_json::from_value(serde_json::to_value(&c).unwrap()).unwrap();
            assert_eq!(back, c);
        }
        assert!(serde_json::from_value::<SourceChanges>(json!({})).is_err());
        assert!(
            serde_json::from_value::<SourceChanges>(json!({"resync": "x", "unchanged": true}))
                .is_err()
        );
    }
}
