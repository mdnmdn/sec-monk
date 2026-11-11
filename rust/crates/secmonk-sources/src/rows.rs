//! The write helpers of `src/secmonk/sources/base.py` as row operations, for the native importers: `store_raw`,
//! `upsert_vulnerability`, `add_alias`, `add_affected` (with `norm_vendor_product`), `severity_from_score`,
//! `normalize_severity`, and `replace_children` computed against the stored rows a [`secmonk_traits::MirrorView`]
//! returns (rust ADR-0012). Rows carry every column in the mirror's column order, so a row read back through the view
//! compares equal to the row that wrote it.

use std::collections::HashMap;

use secmonk_model::{JsonMap, MirrorTable, RowOp};
use serde_json::{Value, json};

use crate::py;

fn text(v: Option<&str>) -> Value {
    v.map_or(Value::Null, |s| Value::String(s.to_owned()))
}

/// `store_raw`: `INSERT OR REPLACE INTO raw_record` (`data` as JSON).
pub fn raw_record(
    source: &str,
    record_id: &str,
    modified: Option<&str>,
    fetched_at: &str,
    data: Value,
) -> RowOp {
    let mut row = JsonMap::new();
    row.insert("source".into(), json!(source));
    row.insert("record_id".into(), json!(record_id));
    row.insert("modified".into(), text(modified));
    row.insert("fetched_at".into(), json!(fetched_at));
    row.insert("data".into(), data);
    RowOp::Upsert {
        table: MirrorTable::RawRecord,
        row,
    }
}

/// The columns of `upsert_vulnerability` after `source` and `id` (`None` = NULL).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Vulnerability {
    /// `summary`.
    pub summary: Option<String>,
    /// `details`.
    pub details: Option<String>,
    /// `published`.
    pub published: Option<String>,
    /// `modified`.
    pub modified: Option<String>,
    /// `withdrawn`.
    pub withdrawn: Option<String>,
    /// `state`.
    pub state: Option<String>,
    /// `severity`.
    pub severity: Option<String>,
    /// `cvss_score` (a NaN is stored as NULL, as SQLite does).
    pub cvss_score: Option<f64>,
    /// `cvss_vector`.
    pub cvss_vector: Option<String>,
    /// `cvss_version`.
    pub cvss_version: Option<String>,
    /// `cwes` (`dumps(cwes or [])`: an empty list is stored as `[]`).
    pub cwes: Vec<String>,
    /// `extra` (JSON; `Value::Null` is NULL).
    pub extra: Value,
}

/// `upsert_vulnerability`: `INSERT OR REPLACE INTO vulnerability` with every column.
pub fn vulnerability(source: &str, id: &str, v: Vulnerability) -> RowOp {
    let mut row = JsonMap::new();
    row.insert("source".into(), json!(source));
    row.insert("id".into(), json!(id));
    row.insert("summary".into(), json!(v.summary));
    row.insert("details".into(), json!(v.details));
    row.insert("published".into(), json!(v.published));
    row.insert("modified".into(), json!(v.modified));
    row.insert("withdrawn".into(), json!(v.withdrawn));
    row.insert("state".into(), json!(v.state));
    row.insert("severity".into(), json!(v.severity));
    row.insert(
        "cvss_score".into(),
        v.cvss_score
            .and_then(serde_json::Number::from_f64)
            .map_or(Value::Null, Value::Number),
    );
    row.insert("cvss_vector".into(), json!(v.cvss_vector));
    row.insert("cvss_version".into(), json!(v.cvss_version));
    row.insert("cwes".into(), json!(v.cwes));
    row.insert("extra".into(), v.extra);
    RowOp::Upsert {
        table: MirrorTable::Vulnerability,
        row,
    }
}

/// `norm_vendor_product`: lower-case, `_` and runs of whitespace become one space; `""`, `n/a`, `-`, `*`, `unknown`
/// are NULL.
pub fn norm_vendor_product(s: Option<&str>) -> Option<String> {
    let s = py::strip(s?).to_lowercase();
    if matches!(s.as_str(), "" | "n/a" | "-" | "*" | "unknown") {
        return None;
    }
    let s = s.replace('_', " ");
    Some(py::split_ws(&s).collect::<Vec<_>>().join(" "))
}

/// `severity_from_score` (`None` for no score).
pub fn severity_from_score(score: Option<f64>) -> Option<&'static str> {
    let s = score?;
    Some(if s >= 9.0 {
        "CRITICAL"
    } else if s >= 7.0 {
        "HIGH"
    } else if s >= 4.0 {
        "MEDIUM"
    } else if s > 0.0 {
        "LOW"
    } else {
        "NONE"
    })
}

/// `normalize_severity`: MODERATE -> MEDIUM, NEGLIGIBLE -> LOW, UNTRIAGED / UNKNOWN / blank -> NULL, else upper-cased.
pub fn normalize_severity(label: Option<&str>) -> Option<String> {
    let u = py::strip(label?).to_uppercase();
    match u.as_str() {
        "" | "UNTRIAGED" | "UNKNOWN" => None,
        "MODERATE" => Some("MEDIUM".into()),
        "NEGLIGIBLE" => Some("LOW".into()),
        _ => Some(u),
    }
}

/// The columns of `add_affected` after `source` and `vuln_id`.
#[derive(Debug, Clone, PartialEq)]
pub struct Affected {
    /// `ecosystem`.
    pub ecosystem: Option<String>,
    /// `package`.
    pub package: Option<String>,
    /// `purl`.
    pub purl: Option<String>,
    /// `vendor` (normalized by [`affected`]).
    pub vendor: Option<String>,
    /// `product` (normalized by [`affected`]).
    pub product: Option<String>,
    /// `cpe`.
    pub cpe: Option<String>,
    /// `range_type`.
    pub range_type: Option<String>,
    /// `version_type`.
    pub version_type: Option<String>,
    /// `events` (`dumps(events) if events is not None`).
    pub events: Option<Vec<Value>>,
    /// `versions` (`dumps(versions) if versions else None`: an empty list is NULL).
    pub versions: Vec<Value>,
    /// `status` (`affected` by default).
    pub status: String,
    /// `extra` (JSON; `Value::Null` is NULL).
    pub extra: Value,
}

impl Default for Affected {
    fn default() -> Self {
        Affected {
            ecosystem: None,
            package: None,
            purl: None,
            vendor: None,
            product: None,
            cpe: None,
            range_type: None,
            version_type: None,
            events: None,
            versions: Vec::new(),
            status: "affected".into(),
            extra: Value::Null,
        }
    }
}

/// `add_affected`: the `affected` row (every column, the mirror's order; vendor and product normalized).
pub fn affected(source: &str, vuln_id: &str, a: Affected) -> JsonMap {
    let mut row = JsonMap::new();
    row.insert("source".into(), json!(source));
    row.insert("vuln_id".into(), json!(vuln_id));
    row.insert("ecosystem".into(), json!(a.ecosystem));
    row.insert("package".into(), json!(a.package));
    row.insert("purl".into(), json!(a.purl));
    row.insert(
        "vendor".into(),
        json!(norm_vendor_product(a.vendor.as_deref())),
    );
    row.insert(
        "product".into(),
        json!(norm_vendor_product(a.product.as_deref())),
    );
    row.insert("cpe".into(), json!(a.cpe));
    row.insert("range_type".into(), json!(a.range_type));
    row.insert("version_type".into(), json!(a.version_type));
    row.insert("events".into(), json!(a.events));
    row.insert(
        "versions".into(),
        if a.versions.is_empty() {
            Value::Null
        } else {
            Value::Array(a.versions)
        },
    );
    row.insert("status".into(), json!(a.status));
    row.insert("extra".into(), a.extra);
    row
}

/// The alias rows `add_alias` leaves for a sequence of `(alias, kind)` calls on one record after `replace_children`:
/// empty aliases and the record's own id skipped, the first call of an alias sets its kind, a later `alias` call
/// upgrades it to `alias`. In first-call order.
pub fn alias_set<'a>(
    vuln_id: &str,
    adds: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    for (alias, kind) in adds {
        if alias.is_empty() || alias == vuln_id {
            continue;
        }
        match at.get(alias) {
            Some(&i) => {
                if kind == "alias" {
                    out[i].1 = "alias".into();
                }
            }
            None => {
                at.insert(alias.to_owned(), out.len());
                out.push((alias.to_owned(), kind.to_owned()));
            }
        }
    }
    out
}

/// `replace_children` for the aliases of one record, against `stored` (its `alias` rows of `source`, as
/// `MirrorView::rows_by_id` returns them): a delete for every stored alias that is not in `new`, an upsert for every
/// new alias that is not stored with the same kind. Nothing when they are equal.
pub fn replace_aliases(
    source: &str,
    vuln_id: &str,
    stored: &[&JsonMap],
    new: &[(String, String)],
) -> Vec<RowOp> {
    let have: HashMap<&str, &str> = stored
        .iter()
        .filter_map(|r| {
            Some((
                r.get("alias")?.as_str()?,
                r.get("kind").and_then(Value::as_str).unwrap_or("alias"),
            ))
        })
        .collect();
    let mut ops = Vec::new();
    for alias in have.keys() {
        if !new.iter().any(|(a, _)| a == alias) {
            ops.push(RowOp::Delete {
                table: MirrorTable::Alias,
                key: obj(json!({"vuln_id": vuln_id, "alias": alias, "source": source})),
            });
        }
    }
    ops.sort_by_key(|o| match o {
        RowOp::Delete { key, .. } => key.get("alias").map(Value::to_string),
        RowOp::Upsert { .. } => None,
    });
    for (alias, kind) in new {
        if have.get(alias.as_str()) != Some(&kind.as_str()) {
            ops.push(RowOp::Upsert {
                table: MirrorTable::Alias,
                row: obj(
                    json!({"vuln_id": vuln_id, "alias": alias, "source": source, "kind": kind}),
                ),
            });
        }
    }
    ops
}

/// How [`replace_affected`] keys its deletes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteKey {
    /// `{source, vuln_id}`: deletes any one row of the record. Only when `stored` is every row of the record
    /// (`DELETE FROM affected WHERE source=? AND vuln_id=?`); exact whatever the JSON columns hold.
    Record,
    /// The stored row itself: deletes one row equal to it (a subset of the record's rows, e.g. one document's).
    Row,
}

/// `DELETE FROM affected …` of the `stored` rows (as `MirrorView::rows_by_id` returns them) followed by
/// `add_affected` of the `new` rows ([`affected`]): nothing when both hold the same rows (as a multiset), else a delete
/// per stored row then an insert per new row, in order.
pub fn replace_affected(stored: &[&JsonMap], new: Vec<JsonMap>, key: DeleteKey) -> Vec<RowOp> {
    let canon = |r: &JsonMap| serde_json::to_string(r).unwrap_or_default();
    let mut a: Vec<String> = stored.iter().map(|r| canon(r)).collect();
    let mut b: Vec<String> = new.iter().map(canon).collect();
    a.sort();
    b.sort();
    if a == b {
        return Vec::new();
    }
    let mut ops: Vec<RowOp> = stored
        .iter()
        .map(|r| RowOp::Delete {
            table: MirrorTable::Affected,
            key: match key {
                DeleteKey::Row => (*r).clone(),
                DeleteKey::Record => r
                    .iter()
                    .filter(|(k, _)| *k == "source" || *k == "vuln_id")
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            },
        })
        .collect();
    ops.extend(new.into_iter().map(|row| RowOp::Upsert {
        table: MirrorTable::Affected,
        row,
    }));
    ops
}

/// Rows grouped by their `vuln_id` (or another text column), for the per-record diff of a chunk read through
/// `MirrorView::rows_by_id`.
pub fn group_by<'a>(rows: &'a [JsonMap], column: &str) -> HashMap<&'a str, Vec<&'a JsonMap>> {
    let mut out: HashMap<&str, Vec<&JsonMap>> = HashMap::new();
    for r in rows {
        if let Some(id) = r.get(column).and_then(Value::as_str) {
            out.entry(id).or_default().push(r);
        }
    }
    out
}

fn obj(v: Value) -> JsonMap {
    match v {
        Value::Object(m) => m,
        _ => JsonMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_follow_base_py() {
        assert_eq!(
            norm_vendor_product(Some("  Apache_Software  Foundation ")),
            Some("apache software foundation".into())
        );
        assert_eq!(norm_vendor_product(Some(" N/A ")), None);
        assert_eq!(norm_vendor_product(None), None);
        assert_eq!(severity_from_score(Some(9.0)), Some("CRITICAL"));
        assert_eq!(severity_from_score(Some(0.0)), Some("NONE"));
        assert_eq!(severity_from_score(Some(f64::NAN)), Some("NONE"));
        assert_eq!(severity_from_score(None), None);
        assert_eq!(normalize_severity(Some("moderate")), Some("MEDIUM".into()));
        assert_eq!(normalize_severity(Some(" ")), None);
        assert_eq!(
            alias_set(
                "X",
                [
                    ("A", "related"),
                    ("X", "alias"),
                    ("", "alias"),
                    ("A", "alias"),
                    ("B", "upstream")
                ]
            ),
            vec![
                ("A".into(), "alias".into()),
                ("B".into(), "upstream".into())
            ]
        );
    }

    #[test]
    fn children_are_replaced_only_when_they_differ() {
        let row = |p: &str| {
            affected(
                "s",
                "V",
                Affected {
                    product: Some(p.into()),
                    extra: json!({"n": 1.5}),
                    ..Affected::default()
                },
            )
        };
        let stored = [row("a"), row("b")];
        let refs: Vec<&JsonMap> = stored.iter().collect();
        assert!(replace_affected(&refs, vec![row("b"), row("a")], DeleteKey::Record).is_empty());
        let ops = replace_affected(&refs, vec![row("c")], DeleteKey::Record);
        assert_eq!(ops.len(), 3);
        match &ops[0] {
            RowOp::Delete { key, .. } => {
                assert_eq!(key, &obj(json!({"source": "s", "vuln_id": "V"})));
            }
            other => panic!("{other:?}"),
        }
        let ops = replace_affected(&refs, Vec::new(), DeleteKey::Row);
        assert!(matches!(&ops[1], RowOp::Delete { key, .. } if *key == stored[1]));

        let a = obj(json!({"vuln_id": "V", "alias": "A", "source": "s", "kind": "alias"}));
        let b = obj(json!({"vuln_id": "V", "alias": "B", "source": "s", "kind": "related"}));
        let new = vec![
            ("A".to_owned(), "alias".to_owned()),
            ("B".to_owned(), "alias".to_owned()),
        ];
        let ops = replace_aliases("s", "V", &[&a, &b], &new);
        assert_eq!(ops.len(), 1, "only B changes kind: {ops:?}");
        let ops = replace_aliases("s", "V", &[&a, &b], &[]);
        assert_eq!(ops.len(), 2);
        assert!(ops.iter().all(|o| matches!(o, RowOp::Delete { .. })));
    }
}
