//! Allowlists of the mirror tables a source may write: columns, primary key, JSON columns
//! (`source/rows.schema.json`, v2 columns).

use secmonk_model::MirrorTable;

/// Shape of one mirror table.
#[derive(Debug, Clone, Copy)]
pub struct TableSpec {
    /// Table.
    pub table: MirrorTable,
    /// Every writable column.
    pub columns: &'static [&'static str],
    /// Primary key (empty for `affected`: no natural key).
    pub key: &'static [&'static str],
    /// Columns stored as JSON text.
    pub json: &'static [&'static str],
}

impl TableSpec {
    /// Whether `c` is a writable column.
    pub fn has(&self, c: &str) -> bool {
        self.columns.contains(&c)
    }

    /// Whether `c` holds JSON.
    pub fn is_json(&self, c: &str) -> bool {
        self.json.contains(&c)
    }
}

/// The spec of a table.
pub fn spec(t: MirrorTable) -> TableSpec {
    use MirrorTable as T;
    let (columns, key, json): (
        &'static [&'static str],
        &'static [&'static str],
        &'static [&'static str],
    ) = match t {
        T::SourceSync => (
            &[
                "source",
                "last_sync",
                "cursor",
                "records",
                "status",
                "message",
            ],
            &["source"],
            &[],
        ),
        T::RawRecord => (
            &["source", "record_id", "modified", "fetched_at", "data"],
            &["source", "record_id"],
            &["data"],
        ),
        T::Vulnerability => (
            &[
                "source",
                "id",
                "summary",
                "details",
                "published",
                "modified",
                "withdrawn",
                "state",
                "severity",
                "cvss_score",
                "cvss_vector",
                "cvss_version",
                "cwes",
                "extra",
            ],
            &["source", "id"],
            &["cwes", "extra"],
        ),
        T::Alias => (
            &["vuln_id", "alias", "source", "kind"],
            &["vuln_id", "alias", "source"],
            &[],
        ),
        T::Affected => (
            &[
                "source",
                "vuln_id",
                "ecosystem",
                "package",
                "purl",
                "vendor",
                "product",
                "cpe",
                "range_type",
                "version_type",
                "events",
                "versions",
                "status",
                "extra",
            ],
            &[],
            &["events", "versions", "extra"],
        ),
        T::Kev => (
            &[
                "cve_id",
                "vendor",
                "product",
                "name",
                "date_added",
                "due_date",
                "ransomware",
                "source",
                "extra",
            ],
            &["cve_id"],
            &["extra"],
        ),
        T::Epss => (
            &["cve_id", "score", "percentile", "date", "source"],
            &["cve_id"],
            &[],
        ),
        T::DistroTriage => (
            &[
                "ecosystem",
                "package",
                "cve_id",
                "status",
                "urgency",
                "fixed_version",
                "nodsa",
                "note",
                "advisory",
                "source",
            ],
            &["ecosystem", "package", "cve_id", "source"],
            &[],
        ),
    };
    TableSpec {
        table: t,
        columns,
        key,
        json,
    }
}
