//! `StateStore` on SQLite: ports of `engine/inventory.save_inventory` and the run-history helpers of
//! `db.py`, plus the finding-set replacement.

use async_trait::async_trait;
use secmonk_model::{
    BasedOn, Component, Finding, Inventory, JOB_KEEP, JOB_LOG_LINES, JobFinish, JobKind, JobOwner,
    JobRow, NewJob, time::now_iso,
};
use serde_json::{Map, Value};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;

use super::SqliteStore;
use crate::{AssetReuseFacts, StateStore, StoreError, StoreResult, dumps, jobs};

/// Python truthiness of a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `[c.source_path] + list(c.meta.get("paths") or [])`, truthy items only (as Python, a string `paths`
/// iterates its characters).
fn component_paths(c: &Component) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    if let Some(p) = c.source_path.as_ref().filter(|p| !p.is_empty()) {
        out.push(Value::String(p.clone()));
    }
    match c.meta.get("paths") {
        Some(Value::Array(a)) => out.extend(a.iter().filter(|v| truthy(v)).cloned()),
        Some(Value::String(s)) => out.extend(s.chars().map(|ch| Value::String(ch.to_string()))),
        Some(Value::Object(o)) => out.extend(o.keys().map(|k| Value::String(k.clone()))),
        _ => {}
    }
    out
}

/// `scan.meta` (`_scan_meta`).
fn scan_meta(inv: &Inventory) -> Value {
    let mut m = Map::new();
    m.insert("warnings".into(), Value::from(inv.warnings.clone()));
    if inv.partial {
        m.insert("partial".into(), Value::Bool(true));
        m.insert(
            "partial_reason".into(),
            inv.partial_reason
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
    }
    Value::Object(m)
}

fn opt_json(row: &SqliteRow, col: &str) -> StoreResult<Option<Value>> {
    let s: Option<String> = row.try_get(col)?;
    s.filter(|s| !s.is_empty())
        .map(|s| serde_json::from_str(&s).map_err(|e| StoreError::Corrupt(format!("{col}: {e}"))))
        .transpose()
}

fn enum_col<T: serde::de::DeserializeOwned>(row: &SqliteRow, col: &str) -> StoreResult<Option<T>> {
    let s: Option<String> = row.try_get(col)?;
    s.map(|s| {
        serde_json::from_value(Value::String(s.clone()))
            .map_err(|_| StoreError::Corrupt(format!("{col}: {s:?}")))
    })
    .transpose()
}

fn job_from_row(row: &SqliteRow, with_log: bool) -> StoreResult<JobRow> {
    let owner: Option<JobOwner> =
        opt_json(row, "owner")?.and_then(|v| serde_json::from_value(v).ok());
    let log: Option<Vec<String>> = if with_log {
        Some(
            opt_json(row, "log")?
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default(),
        )
    } else {
        None
    };
    Ok(JobRow {
        id: row.try_get("id")?,
        kind: enum_col(row, "kind")?.ok_or_else(|| StoreError::Corrupt("job.kind".into()))?,
        origin: enum_col(row, "origin")?.ok_or_else(|| StoreError::Corrupt("job.origin".into()))?,
        title: row.try_get("title")?,
        params: opt_json(row, "params")?,
        status: enum_col(row, "status")?,
        started_at: row.try_get("started_at")?,
        finished_at: row.try_get("finished_at")?,
        error: row.try_get("error")?,
        result: opt_json(row, "result")?,
        log,
        summary: opt_json(row, "summary")?,
        owner,
        log_lines: row.try_get("log_lines")?,
    })
}

const JOB_LIST_COLS: &str = "id, kind, origin, title, params, status, started_at, finished_at, error, result, summary, owner, log_lines";

#[async_trait]
impl StateStore for SqliteStore {
    async fn save_inventory(&self, inv: &Inventory, job_id: Option<i64>) -> StoreResult<i64> {
        let ts = now_iso();
        let a = &inv.asset;
        let mut tx = self.state.write.begin().await?;
        sqlx::query(
            "INSERT INTO asset(id,type,name,os_name,os_version,platform,meta,first_seen,last_seen)
             VALUES (?,?,?,?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET type=excluded.type, name=excluded.name,
               os_name=excluded.os_name, os_version=excluded.os_version, platform=excluded.platform,
               meta=excluded.meta, last_seen=excluded.last_seen",
        )
        .bind(&a.id)
        .bind(&a.kind)
        .bind(&a.name)
        .bind(&a.os_name)
        .bind(&a.os_version)
        .bind(&a.platform)
        .bind(dumps(&Value::Object(a.meta.clone())))
        .bind(&ts)
        .bind(&ts)
        .execute(&mut *tx)
        .await?;
        let scan_id = sqlx::query(
            "INSERT INTO scan(asset_id, collector, started_at, finished_at, components, meta, partial,
                              partial_reason, job_id) VALUES (?,?,?,?,?,?,?,?,?)",
        )
        .bind(&a.id)
        .bind(&inv.collector)
        .bind(&ts)
        .bind(&ts)
        .bind(inv.components.len() as i64)
        .bind(dumps(&scan_meta(inv)))
        .bind(i64::from(inv.partial))
        .bind(if inv.partial { inv.partial_reason.clone() } else { None })
        .bind(job_id)
        .execute(&mut *tx)
        .await?
        .last_insert_rowid();

        // Several copies of one component on one asset share a key: one row with all their paths.
        let mut order: Vec<String> = Vec::new();
        let mut grouped: std::collections::HashMap<String, (&Component, Vec<Value>)> =
            Default::default();
        for c in &inv.components {
            let key = c.key();
            let paths = component_paths(c);
            match grouped.get_mut(&key) {
                Some((_, all)) => {
                    for p in paths {
                        if !all.contains(&p) {
                            all.push(p);
                        }
                    }
                }
                None => {
                    let mut uniq: Vec<Value> = Vec::new();
                    for p in paths {
                        if !uniq.contains(&p) {
                            uniq.push(p);
                        }
                    }
                    order.push(key.clone());
                    grouped.insert(key, (c, uniq));
                }
            }
        }
        for key in &order {
            let (c, paths) = &grouped[key];
            let meta = dumps(&Value::Object(c.meta.clone()));
            sqlx::query(
                "INSERT INTO component(key,name,version,category,ecosystem,purl,cpe,vendor,meta,
                                       product,product_source,bundle_id)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                 ON CONFLICT(key) DO UPDATE SET category=excluded.category, ecosystem=excluded.ecosystem,
                   cpe=COALESCE(excluded.cpe, component.cpe), vendor=COALESCE(excluded.vendor, component.vendor),
                   meta=excluded.meta, product=excluded.product, product_source=excluded.product_source,
                   bundle_id=excluded.bundle_id",
            )
            .bind(key)
            .bind(&c.name)
            .bind(&c.version)
            .bind(c.category.as_str())
            .bind(&c.ecosystem)
            .bind(&c.purl)
            .bind(&c.cpe)
            .bind(&c.vendor)
            .bind(&meta)
            .bind(c.meta_str("product"))
            .bind(c.meta_str("product_source"))
            .bind(c.meta_str("bundle_id"))
            .execute(&mut *tx)
            .await?;
            let comp_id: i64 = sqlx::query_scalar("SELECT id FROM component WHERE key=?")
                .bind(key)
                .fetch_one(&mut *tx)
                .await?;
            let source_path = match paths.first() {
                Some(Value::String(s)) => Some(s.clone()),
                Some(other) => Some(other.to_string()),
                None => c.source_path.clone(),
            };
            sqlx::query(
                "INSERT INTO asset_component(asset_id, component_id, source_path, first_seen, last_seen,
                                             last_scan_id, paths, meta)
                 VALUES (?,?,?,?,?,?,?,?)
                 ON CONFLICT(asset_id, component_id) DO UPDATE SET source_path=excluded.source_path,
                   last_seen=excluded.last_seen, last_scan_id=excluded.last_scan_id,
                   paths=excluded.paths, meta=excluded.meta",
            )
            .bind(&a.id)
            .bind(comp_id)
            .bind(source_path)
            .bind(&ts)
            .bind(&ts)
            .bind(scan_id)
            .bind(dumps(&Value::Array(paths.clone())))
            .bind(&meta)
            .execute(&mut *tx)
            .await?;
        }
        mark_initialized(&mut tx).await?;
        tx.commit().await?;
        Ok(scan_id)
    }

    async fn asset_exists(&self, asset_id: &str) -> StoreResult<bool> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asset WHERE id=?")
            .bind(asset_id)
            .fetch_one(&self.state.read)
            .await?;
        Ok(n > 0)
    }

    async fn asset_reuse_facts(&self, asset_id: &str) -> StoreResult<Option<AssetReuseFacts>> {
        let Some(row) = sqlx::query(
            "SELECT a.id, a.name, a.platform, a.meta, a.last_seen,
                    (SELECT MAX(id) FROM scan WHERE asset_id = a.id) AS latest,
                    (SELECT partial FROM scan WHERE asset_id = a.id ORDER BY id DESC LIMIT 1) AS latest_partial
             FROM asset a WHERE a.id = ?",
        )
        .bind(asset_id)
        .fetch_optional(&self.state.read)
        .await?
        else {
            return Ok(None);
        };
        let meta = match opt_json(&row, "meta")? {
            Some(Value::Object(m)) => m,
            _ => Map::new(),
        };
        Ok(Some(AssetReuseFacts {
            asset_id: row.try_get("id")?,
            name: row.try_get("name")?,
            platform: row.try_get("platform")?,
            meta,
            last_seen: row.try_get("last_seen")?,
            latest_scan_id: row.try_get("latest")?,
            latest_scan_partial: row
                .try_get::<Option<i64>, _>("latest_partial")?
                .unwrap_or(0)
                != 0,
        }))
    }

    async fn update_asset_meta(
        &self,
        asset_id: &str,
        meta: &Map<String, Value>,
    ) -> StoreResult<()> {
        let r = sqlx::query("UPDATE asset SET meta=? WHERE id=?")
            .bind(dumps(&Value::Object(meta.clone())))
            .bind(asset_id)
            .execute(&self.state.write)
            .await?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound(format!("asset {asset_id}")));
        }
        Ok(())
    }

    async fn update_asset_reused(
        &self,
        asset_id: &str,
        name: Option<&str>,
        meta: &Map<String, Value>,
    ) -> StoreResult<()> {
        let r = sqlx::query("UPDATE asset SET name=?, meta=?, last_seen=? WHERE id=?")
            .bind(name)
            .bind(dumps(&Value::Object(meta.clone())))
            .bind(now_iso())
            .bind(asset_id)
            .execute(&self.state.write)
            .await?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound(format!("asset {asset_id}")));
        }
        Ok(())
    }

    async fn latest_scan_id(&self, asset_id: &str) -> StoreResult<Option<i64>> {
        Ok(
            sqlx::query_scalar("SELECT MAX(id) FROM scan WHERE asset_id=?")
                .bind(asset_id)
                .fetch_one(&self.state.read)
                .await?,
        )
    }

    async fn replace_findings(
        &self,
        asset_id: &str,
        set: &[Finding],
        based_on: &BasedOn,
    ) -> StoreResult<u64> {
        let mut tx = self.state.write.begin().await?;
        let latest: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM scan WHERE asset_id=?")
            .bind(asset_id)
            .fetch_one(&mut *tx)
            .await?;
        if latest != based_on.latest_scan_id {
            return Err(StoreError::Stale(format!(
                "asset {asset_id}: finding set computed on scan {:?}, latest is {latest:?}",
                based_on.latest_scan_id
            )));
        }
        sqlx::query("DELETE FROM finding WHERE asset_id=?")
            .bind(asset_id)
            .execute(&mut *tx)
            .await?;
        for f in set {
            sqlx::query(
                "INSERT INTO finding(asset_id, component_id, vuln_id, advisory_ids, matched_by, confidence,
                   fixed_version, severity, cvss_score, epss, kev, priority, status, first_seen, last_seen,
                   fixed_at, triage, triage_source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            )
            .bind(asset_id)
            .bind(f.component_id)
            .bind(&f.vuln_id)
            .bind(dumps(&Value::from(f.advisory_ids.clone())))
            .bind(&f.matched_by)
            .bind(f.confidence)
            .bind(&f.fixed_version)
            .bind(&f.severity)
            .bind(f.cvss_score)
            .bind(f.epss)
            .bind(i64::from(f.kev))
            .bind(&f.priority)
            .bind(f.status.as_str())
            .bind(&f.first_seen)
            .bind(&f.last_seen)
            .bind(&f.fixed_at)
            .bind(&f.triage)
            .bind(&f.triage_source)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(set.len() as u64)
    }

    async fn job_insert(&self, job: &NewJob) -> StoreResult<i64> {
        let mut tx = self.state.write.begin().await?;
        let id = sqlx::query(
            "INSERT INTO job(kind, origin, title, params, status, started_at, owner) VALUES (?,?,?,?,?,?,?)",
        )
        .bind(job.kind.as_str())
        .bind(job.origin.as_str())
        .bind(&job.title)
        .bind(job.params.as_ref().and_then(dumps))
        .bind("running")
        .bind(job.started_at.clone().unwrap_or_else(now_iso))
        .bind(serde_json::to_string(&job.owner).ok())
        .execute(&mut *tx)
        .await?
        .last_insert_rowid();
        sqlx::query("DELETE FROM job WHERE id <= ?")
            .bind(id - JOB_KEEP)
            .execute(&mut *tx)
            .await?;
        mark_initialized(&mut tx).await?;
        tx.commit().await?;
        Ok(id)
    }

    async fn job_finish(&self, job_id: i64, fin: &JobFinish) -> StoreResult<()> {
        let skip = fin.log.len().saturating_sub(JOB_LOG_LINES);
        let log: Vec<String> = fin.log[skip..].to_vec();
        sqlx::query(
            "UPDATE job SET status=?, finished_at=?, error=?, result=?, log=?, summary=?, log_lines=? WHERE id=?",
        )
        .bind(fin.status.as_str())
        .bind(now_iso())
        .bind(&fin.error)
        .bind(fin.result.as_ref().and_then(dumps))
        .bind(dumps(&Value::from(log.clone())))
        .bind(fin.summary.as_ref().and_then(dumps))
        .bind(log.len() as i64)
        .bind(job_id)
        .execute(&self.state.write)
        .await?;
        Ok(())
    }

    async fn job_rows(&self, kind: Option<JobKind>, limit: i64) -> StoreResult<Vec<JobRow>> {
        let rows = match kind {
            Some(k) => {
                sqlx::query(sqlx::AssertSqlSafe(format!(
                    "SELECT {JOB_LIST_COLS} FROM job WHERE kind=? ORDER BY id DESC LIMIT ?"
                )))
                .bind(k.as_str())
                .bind(limit)
                .fetch_all(&self.state.read)
                .await?
            }
            None => {
                sqlx::query(sqlx::AssertSqlSafe(format!(
                    "SELECT {JOB_LIST_COLS} FROM job ORDER BY id DESC LIMIT ?"
                )))
                .bind(limit)
                .fetch_all(&self.state.read)
                .await?
            }
        };
        rows.iter().map(|r| job_from_row(r, false)).collect()
    }

    async fn job_row(&self, job_id: i64) -> StoreResult<Option<JobRow>> {
        let row = sqlx::query("SELECT * FROM job WHERE id=?")
            .bind(job_id)
            .fetch_optional(&self.state.read)
            .await?;
        row.map(|r| job_from_row(&r, true)).transpose()
    }

    async fn job_mark_interrupted(&self) -> StoreResult<u64> {
        let rows = sqlx::query("SELECT id, owner FROM job WHERE status='running'")
            .fetch_all(&self.state.write)
            .await?;
        let mut dead = Vec::new();
        for r in &rows {
            let owner: Option<JobOwner> =
                opt_json(r, "owner")?.and_then(|v| serde_json::from_value(v).ok());
            if !jobs::owner_alive(owner.as_ref()) {
                dead.push(r.try_get::<i64, _>("id")?);
            }
        }
        if dead.is_empty() {
            return Ok(0);
        }
        let now = now_iso();
        let mut tx = self.state.write.begin().await?;
        for id in &dead {
            sqlx::query(
                "UPDATE job SET status='error', error='interrupted', finished_at=COALESCE(finished_at, ?)
                 WHERE id=? AND status='running'",
            )
            .bind(&now)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(dead.len() as u64)
    }

    async fn is_initialized(&self) -> StoreResult<bool> {
        is_initialized(&self.state.read).await
    }
}

/// Set `store_meta.initialized` (first write of an asset, a job or a mirror row).
pub(crate) async fn mark_initialized(tx: &mut sqlx::SqliteConnection) -> StoreResult<()> {
    sqlx::query(
        "INSERT INTO store_meta(key, value) VALUES ('initialized', ?) ON CONFLICT(key) DO NOTHING",
    )
    .bind(now_iso())
    .execute(tx)
    .await?;
    Ok(())
}

pub(crate) async fn is_initialized(pool: &sqlx::SqlitePool) -> StoreResult<bool> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM store_meta WHERE key='initialized'")
        .fetch_one(pool)
        .await?;
    Ok(n > 0)
}
