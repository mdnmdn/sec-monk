//! `MirrorNodeStore` (mirror database) and `NodeCacheStore` (state database) on SQLite.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use secmonk_model::node::{
    AsOf, ComponentMatch, ComponentResult, SnapshotDiff, SourceVersion, VersionKind, Versions,
    VulnSummary, apply_overlap, pkg_key, prod_key,
};
use secmonk_model::time::now_iso;
use secmonk_model::{JsonMap, MirrorTable, RowOp, RowsBatch};
use serde_json::{Value, json};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Row, SqliteConnection};

use super::SqliteStore;
use super::mirror::{decode_row, rows_by_id_on, rows_page_on, select_list};
use crate::mirror_schema::spec;
use crate::node::{
    MAX_FEED_RECORDS, MirrorNodeStore, NodeCacheStore, SNAPSHOT_DIFF_KEEP, SUMMARY_MAX_AGE_DAYS,
};
use crate::{MAX_ROWS_IDS, MAX_ROWS_PAGE, MirrorStore, StoreError, StoreResult};

/// Ids per `IN (...)` list.
const CHUNK: usize = 500;
/// Most ops per batch built by `rows_since` (the store's own limit).
const BATCH_OPS: usize = 5_000;
/// Approximate JSON bytes per batch built by `rows_since`.
const BATCH_BYTES: usize = 2 * 1024 * 1024;

impl SqliteStore {
    /// This store as the mirror side of a node (`Arc<dyn MirrorNodeStore>`; cheap: clones the pools' handles).
    pub fn mirror_node_store(&self) -> Arc<dyn MirrorNodeStore> {
        Arc::new(self.clone())
    }

    /// This store as the state side of a node (`Arc<dyn NodeCacheStore>`).
    pub fn node_cache_store(&self) -> Arc<dyn NodeCacheStore> {
        Arc::new(self.clone())
    }
}

/// Rows of `sql` for every chunk of `ids`: each `{IN}` in `sql` becomes a list of placeholders and the chunk is
/// bound once per `{IN}`.
async fn fetch_in(pool: &SqlitePool, sql: &str, ids: &[String]) -> StoreResult<Vec<SqliteRow>> {
    fetch_in_with(pool, sql, &[], ids).await
}

/// [`fetch_in`] with leading plain parameters (`lead`, bound first, once).
async fn fetch_in_with(
    pool: &SqlitePool,
    sql: &str,
    lead: &[&str],
    ids: &[String],
) -> StoreResult<Vec<SqliteRow>> {
    let times = sql.matches("{IN}").count();
    let mut out = Vec::new();
    for chunk in ids.chunks(CHUNK) {
        let marks = vec!["?"; chunk.len()].join(", ");
        let mut q = sqlx::query(sqlx::AssertSqlSafe(sql.replace("{IN}", &marks)));
        for l in lead {
            q = q.bind(*l);
        }
        for _ in 0..times {
            for i in chunk {
                q = q.bind(i);
            }
        }
        out.extend(q.fetch_all(pool).await?);
    }
    Ok(out)
}

fn text(r: &SqliteRow, c: &str) -> StoreResult<Option<String>> {
    Ok(r.try_get::<Option<String>, _>(c)?)
}

fn real(r: &SqliteRow, c: &str) -> StoreResult<Option<f64>> {
    Ok(r.try_get::<Option<f64>, _>(c)?)
}

fn obj(v: Value) -> JsonMap {
    v.as_object().cloned().unwrap_or_default()
}

fn json_list(s: &str) -> StoreResult<Vec<String>> {
    serde_json::from_str(s).map_err(|e| StoreError::Corrupt(format!("JSON list: {e}")))
}

// ---------------------------------------------------------------------------------------------------------------
// mirror side

/// The tables a snapshot source writes.
fn snapshot_tables(source: &str) -> StoreResult<&'static [MirrorTable]> {
    match source {
        "kev" => Ok(&[MirrorTable::Kev]),
        "epss" => Ok(&[MirrorTable::Epss]),
        "debian-tracker" => Ok(&[MirrorTable::DistroTriage]),
        _ => Err(StoreError::Invalid(format!(
            "{source}: not a snapshot source (kev, epss, debian-tracker)"
        ))),
    }
}

/// Cuts ops into page-local batches of at most `BATCH_OPS` ops and about `BATCH_BYTES`.
struct Cutter<'a> {
    source: &'a str,
    done: Vec<RowsBatch>,
    cur: Vec<RowOp>,
    bytes: usize,
}

impl<'a> Cutter<'a> {
    fn new(source: &'a str) -> Self {
        Cutter {
            source,
            done: Vec::new(),
            cur: Vec::new(),
            bytes: 0,
        }
    }

    fn flush(&mut self) {
        if self.cur.is_empty() {
            return;
        }
        self.done.push(RowsBatch {
            kind: "rows".into(),
            seq: self.done.len() as u64 + 1,
            source: self.source.to_owned(),
            ops: std::mem::take(&mut self.cur),
            generation: None,
            acked_through: None,
        });
        self.bytes = 0;
    }

    fn push(&mut self, op: RowOp) {
        let size = serde_json::to_string(&op).map_or(0, |s| s.len());
        if !self.cur.is_empty() && (self.cur.len() >= BATCH_OPS || self.bytes + size > BATCH_BYTES)
        {
            self.flush();
        }
        self.bytes += size;
        self.cur.push(op);
    }

    fn finish(mut self) -> Vec<RowsBatch> {
        self.flush();
        self.done
    }
}

fn upsert(table: MirrorTable, row: JsonMap) -> RowOp {
    RowOp::Upsert { table, row }
}

/// Group rows by a text column.
fn group(rows: Vec<JsonMap>, col: &str) -> HashMap<String, Vec<JsonMap>> {
    let mut m: HashMap<String, Vec<JsonMap>> = HashMap::new();
    for r in rows {
        if let Some(id) = r.get(col).and_then(Value::as_str).map(str::to_owned) {
            m.entry(id).or_default().push(r);
        }
    }
    m
}

/// A marker op: `delete affected {source, vuln_id}` and nothing else in the key.
fn marker_vuln_id(op: &RowOp) -> Option<&str> {
    match op {
        RowOp::Delete {
            table: MirrorTable::Affected,
            key,
        } if key.len() == 2 && key.contains_key("source") => key.get("vuln_id")?.as_str(),
        _ => None,
    }
}

#[async_trait]
impl MirrorNodeStore for SqliteStore {
    async fn source_versions(&self) -> StoreResult<Vec<SourceVersion>> {
        let mut out: BTreeMap<String, SourceVersion> = BTreeMap::new();
        let rows = sqlx::query(
            "SELECT s.source, s.last_sync, s.cursor, s.records, s.status,
                    v.version AS v_version, v.importer AS v_importer, v.kind AS v_kind
             FROM source_sync s LEFT JOIN source_version v ON v.source = s.source",
        )
        .fetch_all(&self.mirror.read)
        .await?;
        for r in &rows {
            let source: String = r.try_get("source")?;
            let status = text(r, "status")?;
            let version = match text(r, "v_version")? {
                Some(v) => Some(v),
                None if status.as_deref() == Some("ok") => text(r, "cursor")?,
                None => None,
            };
            let records: Option<i64> = r.try_get("records")?;
            out.insert(
                source.clone(),
                SourceVersion {
                    version,
                    importer: text(r, "v_importer")?.unwrap_or_else(|| "unknown".into()),
                    kind: text(r, "v_kind")?
                        .and_then(|k| VersionKind::parse(&k))
                        .unwrap_or_else(|| VersionKind::default_for(&source)),
                    records: records.and_then(|n| u64::try_from(n).ok()).unwrap_or(0),
                    last_sync: text(r, "last_sync")?,
                    status,
                    source,
                },
            );
        }
        let orphans = sqlx::query(
            "SELECT source, version, importer, kind FROM source_version
             WHERE source NOT IN (SELECT source FROM source_sync)",
        )
        .fetch_all(&self.mirror.read)
        .await?;
        for r in &orphans {
            let source: String = r.try_get("source")?;
            out.insert(
                source.clone(),
                SourceVersion {
                    version: text(r, "version")?,
                    importer: text(r, "importer")?.unwrap_or_else(|| "unknown".into()),
                    kind: text(r, "kind")?
                        .and_then(|k| VersionKind::parse(&k))
                        .unwrap_or_else(|| VersionKind::default_for(&source)),
                    records: 0,
                    last_sync: None,
                    status: None,
                    source,
                },
            );
        }
        Ok(out.into_values().collect())
    }

    async fn record_complete_version(
        &self,
        source: &str,
        version: &str,
        importer: &str,
        kind: VersionKind,
    ) -> StoreResult<()> {
        if source.is_empty() || version.is_empty() || importer.is_empty() || importer.contains('@')
        {
            return Err(StoreError::Invalid(
                "source_version: source, version and importer (without '@') required".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO source_version(source, version, importer, kind, completed_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(source) DO UPDATE SET version=excluded.version, importer=excluded.importer,
             kind=excluded.kind, completed_at=excluded.completed_at",
        )
        .bind(source)
        .bind(version)
        .bind(importer)
        .bind(kind.as_str())
        .bind(now_iso())
        .execute(&self.mirror.write)
        .await?;
        Ok(())
    }

    async fn changed_vulns(
        &self,
        source: &str,
        since_modified: &str,
        overlap_s: u64,
        limit: usize,
    ) -> StoreResult<Vec<(String, String)>> {
        let lower = apply_overlap(since_modified, overlap_s);
        let rows = sqlx::query(
            "SELECT id, modified FROM vulnerability WHERE source = ? AND modified > ?
             ORDER BY modified, id LIMIT ?",
        )
        .bind(source)
        .bind(lower)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.mirror.read)
        .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("id")?, r.try_get("modified")?)))
            .collect()
    }

    async fn lookup_keys_for_vulns(&self, ids: &[String]) -> StoreResult<Vec<String>> {
        let rows = fetch_in(
            &self.mirror.read,
            "SELECT DISTINCT ecosystem, package, product FROM affected WHERE vuln_id IN ({IN})",
            ids,
        )
        .await?;
        let mut keys = BTreeSet::new();
        for r in &rows {
            if let Some(p) = text(r, "package")? {
                keys.insert(pkg_key(&text(r, "ecosystem")?.unwrap_or_default(), &p));
            }
            if let Some(p) = text(r, "product")? {
                keys.insert(prod_key(&p));
            }
        }
        Ok(keys.into_iter().collect())
    }

    async fn summaries(&self, ids: &[String]) -> StoreResult<Vec<VulnSummary>> {
        let mut want: Vec<&String> = Vec::new();
        let mut seen = HashSet::new();
        for i in ids {
            if seen.insert(i) {
                want.push(i);
            }
        }
        let want_owned: Vec<String> = want.iter().map(|s| (*s).clone()).collect();
        // relatives through the alias table, both directions
        let mut rel: HashMap<String, BTreeSet<String>> = HashMap::new();
        let pairs = fetch_in(
            &self.mirror.read,
            "SELECT vuln_id, alias FROM alias WHERE vuln_id IN ({IN}) OR alias IN ({IN})",
            &want_owned,
        )
        .await?;
        let wanted: HashSet<&str> = want_owned.iter().map(String::as_str).collect();
        for r in &pairs {
            let (a, b): (String, String) = (r.try_get("vuln_id")?, r.try_get("alias")?);
            if wanted.contains(a.as_str()) && a != b {
                rel.entry(a.clone()).or_default().insert(b.clone());
            }
            if wanted.contains(b.as_str()) && a != b {
                rel.entry(b).or_default().insert(a);
            }
        }
        let mut all: BTreeSet<String> = want_owned.iter().cloned().collect();
        for s in rel.values() {
            all.extend(s.iter().cloned());
        }
        let all: Vec<String> = all.into_iter().collect();

        let mut vrows: HashMap<String, Vec<VRow>> = HashMap::new();
        for r in fetch_in(
            &self.mirror.read,
            "SELECT source, id, summary, published, modified, withdrawn, severity, cvss_score, cvss_vector
             FROM vulnerability WHERE id IN ({IN})",
            &all,
        )
        .await?
        {
            let v = VRow {
                source: r.try_get("source")?,
                id: r.try_get("id")?,
                summary: text(&r, "summary")?,
                published: text(&r, "published")?,
                modified: text(&r, "modified")?,
                withdrawn: text(&r, "withdrawn")?,
                severity: text(&r, "severity")?,
                cvss_score: real(&r, "cvss_score")?,
                cvss_vector: text(&r, "cvss_vector")?,
            };
            vrows.entry(v.id.clone()).or_default().push(v);
        }
        let mut kev: HashMap<String, (Option<String>,)> = HashMap::new();
        for r in fetch_in(
            &self.mirror.read,
            "SELECT cve_id, date_added FROM kev WHERE cve_id IN ({IN})",
            &all,
        )
        .await?
        {
            kev.insert(r.try_get("cve_id")?, (text(&r, "date_added")?,));
        }
        let mut epss: HashMap<String, (Option<f64>, Option<f64>)> = HashMap::new();
        for r in fetch_in(
            &self.mirror.read,
            "SELECT cve_id, score, percentile FROM epss WHERE cve_id IN ({IN})",
            &all,
        )
        .await?
        {
            epss.insert(
                r.try_get("cve_id")?,
                (real(&r, "score")?, real(&r, "percentile")?),
            );
        }

        let mut out = Vec::new();
        for id in want_owned {
            let relatives: Vec<String> = rel
                .get(&id)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            let mut rows: Vec<&VRow> = std::iter::once(&id)
                .chain(relatives.iter())
                .filter_map(|i| vrows.get(i))
                .flatten()
                .collect();
            rows.sort_by(|a, b| {
                (rank(&a.source), a.id != id, &a.source, &a.id).cmp(&(
                    rank(&b.source),
                    b.id != id,
                    &b.source,
                    &b.id,
                ))
            });
            let k = std::iter::once(&id)
                .chain(relatives.iter())
                .find_map(|i| kev.get(i));
            let e = std::iter::once(&id)
                .chain(relatives.iter())
                .find_map(|i| epss.get(i));
            if rows.is_empty() && k.is_none() && e.is_none() {
                continue;
            }
            let own: Vec<&&VRow> = rows.iter().filter(|r| r.id == id).collect();
            let primary: Vec<&VRow> = if own.is_empty() {
                rows.clone()
            } else {
                own.into_iter().copied().collect()
            };
            let cvss = rows.iter().find(|r| r.cvss_score.is_some());
            let mut sources: BTreeSet<String> = rows.iter().map(|r| r.source.clone()).collect();
            if k.is_some() {
                sources.insert("kev".into());
            }
            if e.is_some() {
                sources.insert("epss".into());
            }
            out.push(VulnSummary {
                id: id.clone(),
                aliases: relatives,
                summary: primary
                    .iter()
                    .find_map(|r| r.summary.clone().filter(|s| !s.is_empty())),
                severity: cvss
                    .and_then(|r| r.severity.clone())
                    .or_else(|| rows.iter().find_map(|r| r.severity.clone())),
                cvss_score: cvss.and_then(|r| r.cvss_score),
                cvss_vector: cvss.and_then(|r| r.cvss_vector.clone()),
                published: rows.iter().filter_map(|r| r.published.clone()).min(),
                modified: rows.iter().filter_map(|r| r.modified.clone()).max(),
                withdrawn: primary.iter().find_map(|r| r.withdrawn.clone()),
                kev: k.is_some(),
                kev_date_added: k.and_then(|k| k.0.clone()),
                epss: e.and_then(|e| e.0),
                epss_percentile: e.and_then(|e| e.1),
                sources: sources.into_iter().collect(),
            });
        }
        Ok(out)
    }

    async fn covered_ecosystems(&self) -> StoreResult<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT DISTINCT ecosystem FROM affected WHERE ecosystem IS NOT NULL ORDER BY ecosystem",
        )
        .fetch_all(&self.mirror.read)
        .await?)
    }

    async fn snapshot_diff_put(&self, d: &SnapshotDiff) -> StoreResult<()> {
        let mut tx = self.mirror.write.begin().await?;
        sqlx::query(
            "INSERT OR REPLACE INTO snapshot_diff(source, version, prev_version, created_at, ids, keys)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&d.source)
        .bind(&d.version)
        .bind(&d.prev_version)
        .bind(&d.created_at)
        .bind(serde_json::to_string(&d.ids).unwrap_or_else(|_| "[]".into()))
        .bind(serde_json::to_string(&d.keys).unwrap_or_else(|_| "[]".into()))
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM snapshot_diff WHERE source = ?1 AND rowid NOT IN
             (SELECT rowid FROM snapshot_diff WHERE source = ?1 ORDER BY rowid DESC LIMIT ?2)",
        )
        .bind(&d.source)
        .bind(i64::from(SNAPSHOT_DIFF_KEEP))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn snapshot_diffs_since(
        &self,
        source: &str,
        since_version: &str,
    ) -> StoreResult<Option<Vec<SnapshotDiff>>> {
        let rows = sqlx::query(
            "SELECT source, version, prev_version, created_at, ids, keys FROM snapshot_diff
             WHERE source = ? ORDER BY rowid DESC",
        )
        .bind(source)
        .fetch_all(&self.mirror.read)
        .await?;
        let mut diffs: Vec<SnapshotDiff> = Vec::new();
        for r in &rows {
            diffs.push(SnapshotDiff {
                source: r.try_get("source")?,
                version: r.try_get("version")?,
                prev_version: r.try_get("prev_version")?,
                created_at: r.try_get("created_at")?,
                ids: json_list(&r.try_get::<String, _>("ids")?)?,
                keys: json_list(&r.try_get::<String, _>("keys")?)?,
            });
        }
        let Some(newest) = diffs.first() else {
            return Ok(None);
        };
        let by_version: HashMap<&str, &SnapshotDiff> =
            diffs.iter().map(|d| (d.version.as_str(), d)).collect();
        let mut chain = Vec::new();
        let mut cur = newest;
        loop {
            if cur.version == since_version {
                break;
            }
            chain.push(cur.clone());
            match cur.prev_version.as_deref() {
                Some(p) if p == since_version => break,
                Some(p) => match by_version.get(p) {
                    Some(d) => cur = d,
                    None => return Ok(None),
                },
                None => return Ok(None),
            }
        }
        chain.reverse();
        Ok(Some(chain))
    }

    async fn rows_since(
        &self,
        source: &str,
        since_modified: Option<&str>,
        page: Option<&str>,
        limit: usize,
    ) -> StoreResult<(Vec<RowsBatch>, Option<String>)> {
        let limit = limit.clamp(1, MAX_FEED_RECORDS);
        // one read transaction for the page: the records and their children come from one WAL snapshot
        let mut tx = self.mirror.read.begin().await?;
        let t = spec(MirrorTable::Vulnerability);
        let cols = select_list(&t);
        let lim = i64::try_from(limit).unwrap_or(i64::MAX);
        let bad = || StoreError::Invalid("rows_since: bad page cursor".into());
        let (rows, cursor_of): (Vec<SqliteRow>, fn(&JsonMap) -> String) = match since_modified {
            Some(since) => {
                let after = match page {
                    None => None,
                    Some(p) => {
                        let mut it = p.splitn(3, '|');
                        match (it.next(), it.next(), it.next()) {
                            (Some("d1"), Some(m), Some(id)) => Some((m.to_owned(), id.to_owned())),
                            _ => return Err(bad()),
                        }
                    }
                };
                let sql = format!(
                    "SELECT rowid, {cols} FROM vulnerability WHERE source = ?1 AND modified > ?2
                     AND (?3 IS NULL OR modified > ?3 OR (modified = ?3 AND id > ?4))
                     ORDER BY modified, id LIMIT ?5"
                );
                let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(source)
                    .bind(since)
                    .bind(after.as_ref().map(|a| a.0.clone()))
                    .bind(after.map(|a| a.1).unwrap_or_default())
                    .bind(lim)
                    .fetch_all(&mut *tx)
                    .await?;
                (rows, |m| {
                    format!(
                        "d1|{}|{}",
                        m.get("modified").and_then(Value::as_str).unwrap_or(""),
                        m.get("id").and_then(Value::as_str).unwrap_or("")
                    )
                })
            }
            None => {
                let after = match page {
                    None => None,
                    Some(p) => Some(p.strip_prefix("i1|").ok_or_else(bad)?.to_owned()),
                };
                let sql = format!(
                    "SELECT rowid, {cols} FROM vulnerability WHERE source = ?1 AND (?2 IS NULL OR id > ?2)
                     ORDER BY id LIMIT ?3"
                );
                let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(source)
                    .bind(after)
                    .bind(lim)
                    .fetch_all(&mut *tx)
                    .await?;
                (rows, |m| {
                    format!("i1|{}", m.get("id").and_then(Value::as_str).unwrap_or(""))
                })
            }
        };
        let mut vulns = Vec::with_capacity(rows.len());
        for r in &rows {
            vulns.push(decode_row(&t, r)?.1);
        }
        let next = if vulns.len() == limit {
            vulns.last().map(cursor_of)
        } else {
            None
        };
        let ids: Vec<String> = vulns
            .iter()
            .filter_map(|m| m.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        let mut affected = group(
            rows_by_id_on(&mut tx, MirrorTable::Affected, source, &ids).await?,
            "vuln_id",
        );
        let mut aliases = group(
            rows_by_id_on(&mut tx, MirrorTable::Alias, source, &ids).await?,
            "vuln_id",
        );
        let mut raw = group(
            rows_by_id_on(&mut tx, MirrorTable::RawRecord, source, &ids).await?,
            "record_id",
        );
        tx.rollback().await?;
        let mut cut = Cutter::new(source);
        for v in vulns {
            let id = v
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            cut.push(RowOp::Delete {
                table: MirrorTable::Affected,
                key: obj(json!({"source": source, "vuln_id": id})),
            });
            cut.push(upsert(MirrorTable::Vulnerability, v));
            for r in raw.remove(&id).unwrap_or_default() {
                cut.push(upsert(MirrorTable::RawRecord, r));
            }
            for r in aliases.remove(&id).unwrap_or_default() {
                cut.push(upsert(MirrorTable::Alias, r));
            }
            for r in affected.remove(&id).unwrap_or_default() {
                cut.push(upsert(MirrorTable::Affected, r));
            }
        }
        Ok((cut.finish(), next))
    }

    async fn rows_snapshot(
        &self,
        source: &str,
        page: Option<&str>,
        limit: usize,
    ) -> StoreResult<(Vec<RowsBatch>, Option<String>)> {
        let tables = snapshot_tables(source)?;
        let limit = limit.clamp(1, MAX_ROWS_PAGE);
        let cursor = match page {
            None => None,
            Some(p) => Some(SnapshotCursor::parse(p)?),
        };
        // one read transaction: the version check and the rows come from one WAL snapshot
        let mut tx = self.mirror.read.begin().await?;
        let version = served_version(&mut tx, source).await?.unwrap_or_default();
        let (idx, after) = match cursor {
            None => (0, None),
            Some(c) if c.version != version => {
                return Err(StoreError::Stale(format!(
                    "{source}: the snapshot changed version while it was paged; restart from the first page"
                )));
            }
            Some(c) => (c.table, c.after),
        };
        let table = *tables.get(idx).ok_or_else(bad_cursor)?;
        let (rows, next_rowid) = rows_page_on(&mut tx, table, source, after, limit).await?;
        tx.rollback().await?;
        let next = match next_rowid {
            Some(r) => Some(SnapshotCursor::text(idx, r, &version)),
            None if idx + 1 < tables.len() => Some(SnapshotCursor::text(idx + 1, 0, &version)),
            None => None,
        };
        let mut cut = Cutter::new(source);
        for r in rows {
            cut.push(upsert(table, r));
        }
        Ok((cut.finish(), next))
    }

    async fn localize_feed_batch(&self, batch: &RowsBatch) -> StoreResult<Vec<RowOp>> {
        let ids: Vec<String> = batch
            .ops
            .iter()
            .filter_map(|o| marker_vuln_id(o).map(str::to_owned))
            .collect();
        if ids.is_empty() {
            return Ok(batch.ops.clone());
        }
        let mut counts: HashMap<String, usize> = HashMap::new();
        for r in fetch_in_with(
            &self.mirror.read,
            "SELECT vuln_id, COUNT(*) AS n FROM affected WHERE source = ? AND vuln_id IN ({IN}) GROUP BY vuln_id",
            &[batch.source.as_str()],
            &ids,
        )
        .await?
        {
            let n: i64 = r.try_get("n")?;
            counts.insert(r.try_get("vuln_id")?, usize::try_from(n).unwrap_or(0));
        }
        let mut stored_aliases: HashMap<String, Vec<String>> = HashMap::new();
        for chunk in ids.chunks(MAX_ROWS_IDS) {
            for r in self
                .rows_by_id(MirrorTable::Alias, &batch.source, chunk)
                .await?
            {
                if let (Some(v), Some(a)) = (
                    r.get("vuln_id").and_then(Value::as_str),
                    r.get("alias").and_then(Value::as_str),
                ) {
                    stored_aliases
                        .entry(v.to_owned())
                        .or_default()
                        .push(a.to_owned());
                }
            }
        }
        // aliases the batch itself upserts, per record
        let mut new_aliases: HashMap<&str, HashSet<&str>> = HashMap::new();
        for op in &batch.ops {
            if let RowOp::Upsert {
                table: MirrorTable::Alias,
                row,
            } = op
                && let (Some(v), Some(a)) = (
                    row.get("vuln_id").and_then(Value::as_str),
                    row.get("alias").and_then(Value::as_str),
                )
            {
                new_aliases.entry(v).or_default().insert(a);
            }
        }
        let mut out = Vec::with_capacity(batch.ops.len());
        for op in &batch.ops {
            let Some(id) = marker_vuln_id(op) else {
                out.push(op.clone());
                continue;
            };
            for _ in 0..counts.get(id).copied().unwrap_or(0) {
                out.push(op.clone());
            }
            let keep = new_aliases.get(id);
            let mut stale: Vec<&String> = stored_aliases
                .get(id)
                .map(|v| v.iter().collect())
                .unwrap_or_default();
            stale.sort();
            for a in stale {
                if !keep.is_some_and(|k| k.contains(a.as_str())) {
                    out.push(RowOp::Delete {
                        table: MirrorTable::Alias,
                        key: obj(json!({"vuln_id": id, "alias": a, "source": batch.source})),
                    });
                }
            }
        }
        Ok(out)
    }
}

fn bad_cursor() -> StoreError {
    StoreError::Invalid("rows_snapshot: bad page cursor".into())
}

/// The page cursor of `rows_snapshot`: `s2|<table index>|<rowid after>|<served version>` (version last: it may
/// contain anything). The version pins the paging to the snapshot the first page came from.
struct SnapshotCursor {
    table: usize,
    after: Option<u64>,
    version: String,
}

impl SnapshotCursor {
    fn text(table: usize, after: u64, version: &str) -> String {
        format!("s2|{table}|{after}|{version}")
    }

    fn parse(p: &str) -> StoreResult<SnapshotCursor> {
        let mut it = p.splitn(4, '|');
        match (it.next(), it.next(), it.next(), it.next()) {
            (Some("s2"), Some(i), Some(a), Some(v)) => Ok(SnapshotCursor {
                table: i.parse().map_err(|_| bad_cursor())?,
                after: match a.parse::<u64>().map_err(|_| bad_cursor())? {
                    0 => None,
                    n => Some(n),
                },
                version: v.to_owned(),
            }),
            // a cursor of the previous format carries no version: the follower restarts
            (Some("s1"), _, _, _) => Err(StoreError::Stale(
                "rows_snapshot: a cursor without a version; restart from the first page".into(),
            )),
            _ => Err(bad_cursor()),
        }
    }
}

/// The served version of `source` (the rule of `MirrorNodeStore::source_versions`), read on `conn`.
async fn served_version(conn: &mut SqliteConnection, source: &str) -> StoreResult<Option<String>> {
    let recorded: Option<String> =
        sqlx::query_scalar("SELECT version FROM source_version WHERE source = ?")
            .bind(source)
            .fetch_optional(&mut *conn)
            .await?
            .flatten();
    if recorded.is_some() {
        return Ok(recorded);
    }
    Ok(
        sqlx::query_scalar("SELECT cursor FROM source_sync WHERE source = ? AND status = 'ok'")
            .bind(source)
            .fetch_optional(&mut *conn)
            .await?
            .flatten(),
    )
}

#[derive(Debug)]
struct VRow {
    source: String,
    id: String,
    summary: Option<String>,
    published: Option<String>,
    modified: Option<String>,
    withdrawn: Option<String>,
    severity: Option<String>,
    cvss_score: Option<f64>,
    cvss_vector: Option<String>,
}

/// Preference of a source for the merged summary: nvd, cvelist, then the others.
fn rank(source: &str) -> u8 {
    match source {
        "nvd" => 0,
        "cvelist" => 1,
        _ => 2,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// state side

/// The marker row of a component that matched nothing.
const NO_MATCH: &str = "";

async fn insert_match(
    tx: &mut SqliteConnection,
    key: &str,
    m: Option<&ComponentMatch>,
    as_of: &str,
) -> StoreResult<()> {
    let (vuln_id, adv, by, conf, fixed, triage, tsrc) = match m {
        Some(m) => (
            m.vuln_id.as_str(),
            Some(serde_json::to_string(&m.advisory_ids).unwrap_or_else(|_| "[]".into())),
            m.matched_by.as_deref(),
            m.confidence,
            m.fixed_version.as_deref(),
            m.triage.as_deref(),
            m.triage_source.as_deref(),
        ),
        None => (NO_MATCH, None, None, None, None, None, None),
    };
    sqlx::query(
        "INSERT OR REPLACE INTO component_match(component_key, vuln_id, advisory_ids, matched_by, confidence,
         fixed_version, triage, triage_source, as_of) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(key)
    .bind(vuln_id)
    .bind(adv)
    .bind(by)
    .bind(conf)
    .bind(fixed)
    .bind(triage)
    .bind(tsrc)
    .bind(as_of)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

#[async_trait]
impl NodeCacheStore for SqliteStore {
    async fn put_component_results(
        &self,
        results: &[ComponentResult],
        as_of: &Versions,
    ) -> StoreResult<()> {
        let as_of = serde_json::to_string(&as_of.as_of())
            .map_err(|e| StoreError::Invalid(format!("as_of: {e}")))?;
        if let Some(r) = results
            .iter()
            .find(|r| r.matches.iter().any(|m| m.vuln_id.is_empty()))
        {
            return Err(StoreError::Invalid(format!(
                "component_match: an empty vuln_id for {:?} (the marker of \"no match\")",
                r.key
            )));
        }
        let mut tx = self.state.write.begin().await?;
        for r in results {
            sqlx::query("DELETE FROM component_match WHERE component_key = ?")
                .bind(&r.key)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM component_lookup WHERE component_key = ?")
                .bind(&r.key)
                .execute(&mut *tx)
                .await?;
            if r.matches.is_empty() {
                insert_match(&mut tx, &r.key, None, &as_of).await?;
            }
            for m in &r.matches {
                insert_match(&mut tx, &r.key, Some(m), &as_of).await?;
            }
            for k in &r.lookup_keys {
                sqlx::query(
                    "INSERT OR IGNORE INTO component_lookup(component_key, lookup_key) VALUES (?, ?)",
                )
                .bind(&r.key)
                .bind(k)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    async fn component_matches(
        &self,
        keys: &[String],
    ) -> StoreResult<BTreeMap<String, Vec<ComponentMatch>>> {
        let rows = fetch_in(
            &self.state.read,
            "SELECT component_key, vuln_id, advisory_ids, matched_by, confidence, fixed_version, triage,
             triage_source FROM component_match WHERE component_key IN ({IN}) ORDER BY component_key, vuln_id",
            keys,
        )
        .await?;
        let mut out: BTreeMap<String, Vec<ComponentMatch>> = BTreeMap::new();
        for r in &rows {
            let key: String = r.try_get("component_key")?;
            let entry = out.entry(key).or_default();
            let vuln_id: String = r.try_get("vuln_id")?;
            if vuln_id == NO_MATCH {
                continue;
            }
            entry.push(ComponentMatch {
                vuln_id,
                advisory_ids: match text(r, "advisory_ids")? {
                    Some(s) => json_list(&s)?,
                    None => Vec::new(),
                },
                matched_by: text(r, "matched_by")?,
                confidence: real(r, "confidence")?,
                fixed_version: text(r, "fixed_version")?,
                triage: text(r, "triage")?,
                triage_source: text(r, "triage_source")?,
            });
        }
        Ok(out)
    }

    async fn component_as_of(&self, keys: &[String]) -> StoreResult<BTreeMap<String, AsOf>> {
        let rows = fetch_in(
            &self.state.read,
            "SELECT component_key, MAX(as_of) AS as_of FROM component_match
             WHERE component_key IN ({IN}) GROUP BY component_key",
            keys,
        )
        .await?;
        let mut out = BTreeMap::new();
        for r in &rows {
            if let Some(s) = text(r, "as_of")? {
                let a: AsOf = serde_json::from_str(&s)
                    .map_err(|e| StoreError::Corrupt(format!("component_match.as_of: {e}")))?;
                out.insert(r.try_get("component_key")?, a);
            }
        }
        Ok(out)
    }

    async fn components_by_lookup_keys(&self, keys: &[String]) -> StoreResult<Vec<String>> {
        let rows = fetch_in(
            &self.state.read,
            "SELECT DISTINCT component_key FROM component_lookup WHERE lookup_key IN ({IN})",
            keys,
        )
        .await?;
        rows.iter()
            .map(|r| Ok(r.try_get::<String, _>("component_key")?))
            .collect::<StoreResult<BTreeSet<_>>>()
            .map(|s| s.into_iter().collect())
    }

    async fn components_by_vuln_ids(&self, ids: &[String]) -> StoreResult<Vec<String>> {
        let mut out = BTreeSet::new();
        for sql in [
            "SELECT DISTINCT component_key FROM component_match WHERE vuln_id IN ({IN})",
            "SELECT DISTINCT m.component_key AS component_key FROM component_match m, json_each(m.advisory_ids) j
             WHERE j.value IN ({IN})",
        ] {
            for r in fetch_in(&self.state.read, sql, ids).await? {
                out.insert(r.try_get::<String, _>("component_key")?);
            }
        }
        Ok(out.into_iter().collect())
    }

    async fn put_summaries(&self, summaries: &[VulnSummary]) -> StoreResult<()> {
        let now = now_iso();
        let mut tx = self.state.write.begin().await?;
        for s in summaries {
            sqlx::query(
                "INSERT OR REPLACE INTO vuln_summary(id, data, fetched_at) VALUES (?, ?, ?)",
            )
            .bind(&s.id)
            .bind(
                serde_json::to_string(s)
                    .map_err(|e| StoreError::Invalid(format!("summary: {e}")))?,
            )
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
        // summaries not refreshed for SUMMARY_MAX_AGE_DAYS days go: the cache does not grow forever
        let cutoff = apply_overlap(&now, SUMMARY_MAX_AGE_DAYS * 86_400);
        sqlx::query("DELETE FROM vuln_summary WHERE fetched_at < ?")
            .bind(cutoff)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn cached_summaries(&self, ids: &[String]) -> StoreResult<Vec<VulnSummary>> {
        let rows = fetch_in(
            &self.state.read,
            "SELECT id, data FROM vuln_summary WHERE id IN ({IN})",
            ids,
        )
        .await?;
        let mut by_id: HashMap<String, VulnSummary> = HashMap::new();
        for r in &rows {
            let s: VulnSummary = serde_json::from_str(&r.try_get::<String, _>("data")?)
                .map_err(|e| StoreError::Corrupt(format!("vuln_summary.data: {e}")))?;
            by_id.insert(r.try_get("id")?, s);
        }
        let mut seen = HashSet::new();
        Ok(ids
            .iter()
            .filter(|i| seen.insert(i.as_str()))
            .filter_map(|i| by_id.remove(i))
            .collect())
    }

    async fn node_sync_get(&self, name: &str) -> StoreResult<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT value FROM node_sync WHERE name = ?")
                .bind(name)
                .fetch_optional(&self.state.read)
                .await?
                .flatten(),
        )
    }

    async fn node_sync_set(&self, name: &str, value: &str) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO node_sync(name, value) VALUES (?, ?)
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
        )
        .bind(name)
        .bind(value)
        .execute(&self.state.write)
        .await?;
        Ok(())
    }

    async fn node_sync_set_many(&self, values: &[(&str, &str)]) -> StoreResult<()> {
        let mut tx = self.state.write.begin().await?;
        for (name, value) in values {
            sqlx::query(
                "INSERT INTO node_sync(name, value) VALUES (?, ?)
                 ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            )
            .bind(*name)
            .bind(*value)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn stored_lookup_keys(
        &self,
        keys: &[String],
    ) -> StoreResult<BTreeMap<String, Vec<String>>> {
        let rows = fetch_in(
            &self.state.read,
            "SELECT component_key, lookup_key FROM component_lookup WHERE component_key IN ({IN})
             ORDER BY component_key, lookup_key",
            keys,
        )
        .await?;
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for r in &rows {
            out.entry(r.try_get("component_key")?)
                .or_default()
                .push(r.try_get("lookup_key")?);
        }
        Ok(out)
    }
}
