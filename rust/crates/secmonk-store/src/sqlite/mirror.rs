//! `MirrorStore` on SQLite: `secmonk-mirror-rows/1` batches with table/column allowlists. Upserts and
//! primary-key deletes are built with sea-query (the dialect-specific part); the single-row `affected` delete
//! is SQLite SQL with null-safe `IS` comparisons.

use async_trait::async_trait;
use sea_query::{Alias, Expr, ExprTrait, OnConflict, Query, SqliteQueryBuilder};
use secmonk_model::{MirrorTable, RowOp, RowsBatch};
use serde_json::{Map, Value};
use sqlx::Row;

use super::SqliteStore;
use super::bind::Bind;
use super::state::{is_initialized, mark_initialized};
use crate::mirror_schema::{TableSpec, spec};
use crate::{
    AppliedState, ApplyStats, MirrorRepair, MirrorStore, RepairStats, StoreError, StoreResult,
    SyncState,
};

/// Largest batch accepted: `source/rows.schema.json` `ops.maxItems` (py-sources cuts batches at 5000 ops).
pub const MAX_OPS_PER_BATCH: usize = 5_000;

/// Tables whose primary key has no `source` column, and the source that owns them (it may replace another
/// source's row, as its Python `INSERT OR REPLACE` does; e.g. FIRST EPSS scores replace EUVD's).
fn owner_of_sourceless_key(t: MirrorTable) -> Option<&'static str> {
    match t {
        MirrorTable::Kev => Some("kev"),
        MirrorTable::Epss => Some("epss"),
        _ => None,
    }
}

/// The `source` value of a row or key must be the batch's source: one source never writes another's rows.
fn check_source(
    t: &TableSpec,
    cols: &[(&'static str, Bind)],
    batch_source: &str,
    what: &str,
) -> StoreResult<()> {
    match cols.iter().find(|(c, _)| *c == "source") {
        Some((_, Bind::Text(s))) if s == batch_source => Ok(()),
        // per-qualifier sync cursors of one source (`osv:PyPI`): `<batch source>:<qualifier>`
        Some((_, Bind::Text(s)))
            if t.table == MirrorTable::SourceSync
                && s.strip_prefix(batch_source)
                    .is_some_and(|q| q.len() > 1 && q.starts_with(':')) =>
        {
            Ok(())
        }
        Some((_, b)) => Err(StoreError::Invalid(format!(
            "{} {what}: source {b:?} is not the batch's source {batch_source:?}",
            t.table.as_str()
        ))),
        None if what == "upsert" || t.key.contains(&"source") || t.key.is_empty() => {
            Err(StoreError::Invalid(format!(
                "{} {what}: source missing (must be {batch_source:?})",
                t.table.as_str()
            )))
        }
        None => Ok(()), // kev / epss deletes by cve_id: restricted to the batch source's rows in SQL
    }
}

/// A validated statement: SQL text + values.
struct Stmt {
    sql: String,
    values: Vec<Bind>,
    deletes: bool,
}

fn columns(
    t: &TableSpec,
    row: &Map<String, Value>,
    what: &str,
) -> StoreResult<Vec<(&'static str, Bind)>> {
    let mut out = Vec::with_capacity(row.len());
    for (k, v) in row {
        let col = t
            .columns
            .iter()
            .find(|c| **c == k.as_str())
            .ok_or_else(|| {
                StoreError::Invalid(format!("{} {what}: unknown column {k:?}", t.table.as_str()))
            })?;
        out.push((
            *col,
            Bind::from_json(t.table.as_str(), col, v, t.is_json(col))?,
        ));
    }
    Ok(out)
}

fn build(op: &RowOp, batch_source: &str) -> StoreResult<Stmt> {
    let t = spec(op.table());
    let table = Alias::new(t.table.as_str());
    match op {
        RowOp::Upsert { row, .. } => {
            let cols = columns(&t, row, "upsert")?;
            check_source(&t, &cols, batch_source, "upsert")?;
            for k in t.key {
                if !cols.iter().any(|(c, b)| c == k && *b != Bind::Null) {
                    return Err(StoreError::Invalid(format!(
                        "{} upsert: key column {k} missing",
                        t.table.as_str()
                    )));
                }
            }
            if t.table == MirrorTable::Affected && !cols.iter().any(|(c, _)| *c == "vuln_id") {
                return Err(StoreError::Invalid(
                    "affected upsert: source and vuln_id required".into(),
                ));
            }
            let mut q = Query::insert();
            q.into_table(table)
                .columns(cols.iter().map(|(c, _)| Alias::new(*c)));
            q.values(cols.iter().map(|(_, b)| Expr::val(b.to_sea())))
                .map_err(|e| StoreError::Invalid(format!("{}: {e}", t.table.as_str())))?;
            if !t.key.is_empty() {
                let rest: Vec<Alias> = cols
                    .iter()
                    .filter(|(c, _)| !t.key.contains(c))
                    .map(|(c, _)| Alias::new(*c))
                    .collect();
                let mut oc = OnConflict::columns(t.key.iter().map(|k| Alias::new(*k)));
                if rest.is_empty() {
                    oc.do_nothing();
                } else {
                    oc.update_columns(rest);
                    if owner_of_sourceless_key(t.table).is_some_and(|o| o != batch_source) {
                        // another source's row is never overwritten (`... WHERE epss.source='euvd'`)
                        oc.action_and_where(ExprTrait::eq(
                            Expr::col((Alias::new(t.table.as_str()), Alias::new("source"))),
                            batch_source,
                        ));
                    }
                }
                q.on_conflict(oc);
            }
            let (sql, values) = q.build(SqliteQueryBuilder);
            Ok(Stmt {
                sql,
                values: values
                    .into_iter()
                    .map(Bind::from_sea)
                    .collect::<StoreResult<_>>()?,
                deletes: false,
            })
        }
        RowOp::Delete { key, .. } if t.key.is_empty() => {
            // affected: delete ONE row matching every given column (null-safe).
            let cols = columns(&t, key, "delete")?;
            check_source(&t, &cols, batch_source, "delete")?;
            if !(cols.iter().any(|(c, _)| *c == "source")
                && cols.iter().any(|(c, _)| *c == "vuln_id"))
            {
                return Err(StoreError::Invalid(
                    "affected delete: source and vuln_id required".into(),
                ));
            }
            let cond: Vec<String> = cols.iter().map(|(c, _)| format!("\"{c}\" IS ?")).collect();
            let sql = format!(
                "DELETE FROM affected WHERE rowid_ = (SELECT rowid_ FROM affected WHERE {} LIMIT 1)",
                cond.join(" AND ")
            );
            Ok(Stmt {
                sql,
                values: cols.into_iter().map(|(_, b)| b).collect(),
                deletes: true,
            })
        }
        RowOp::Delete { key, .. } => {
            let cols = columns(&t, key, "delete")?;
            check_source(&t, &cols, batch_source, "delete")?;
            if cols.len() != t.key.len() || !t.key.iter().all(|k| cols.iter().any(|(c, _)| c == k))
            {
                return Err(StoreError::Invalid(format!(
                    "{} delete: key must be exactly {:?}",
                    t.table.as_str(),
                    t.key
                )));
            }
            let mut q = Query::delete();
            q.from_table(table);
            for (c, b) in &cols {
                if *b == Bind::Null {
                    return Err(StoreError::Invalid(format!(
                        "{} delete: null key {c}",
                        t.table.as_str()
                    )));
                }
                q.and_where(ExprTrait::eq(Expr::col(Alias::new(*c)), b.to_sea()));
            }
            if !t.key.contains(&"source") {
                q.and_where(ExprTrait::eq(Expr::col(Alias::new("source")), batch_source));
            }
            let (sql, values) = q.build(SqliteQueryBuilder);
            Ok(Stmt {
                sql,
                values: values
                    .into_iter()
                    .map(Bind::from_sea)
                    .collect::<StoreResult<_>>()?,
                deletes: true,
            })
        }
    }
}

/// Checks of a batch that need no database: kind, size, seq, source; then every op built.
fn prepare(batch: &RowsBatch) -> StoreResult<Vec<Stmt>> {
    if batch.kind != "rows" {
        return Err(StoreError::Invalid(format!("batch kind {:?}", batch.kind)));
    }
    if batch.ops.len() > MAX_OPS_PER_BATCH {
        return Err(StoreError::Invalid(format!(
            "batch of {} ops exceeds {MAX_OPS_PER_BATCH}",
            batch.ops.len()
        )));
    }
    if batch.seq == 0 || batch.source.is_empty() {
        return Err(StoreError::Invalid(
            "batch: seq >= 1 and a source required".into(),
        ));
    }
    // Validate everything before the transaction: a bad op refuses the whole batch.
    batch
        .ops
        .iter()
        .map(|op| build(op, &batch.source))
        .collect()
}

/// Run built statements in an open transaction.
async fn execute(
    tx: &mut sqlx::SqliteConnection,
    stmts: Vec<Stmt>,
    stats: &mut ApplyStats,
) -> StoreResult<()> {
    for s in stmts {
        let mut q = sqlx::query(sqlx::AssertSqlSafe(s.sql));
        for v in s.values {
            q = v.bind_to(q);
        }
        let n = q.execute(&mut *tx).await?.rows_affected();
        if s.deletes {
            stats.deleted += n;
        } else {
            stats.upserts += 1;
        }
    }
    Ok(())
}

fn seq_i64(seq: u64) -> StoreResult<i64> {
    i64::try_from(seq).map_err(|_| StoreError::Invalid(format!("seq {seq} out of range")))
}

async fn read_applied(
    conn: &mut sqlx::SqliteConnection,
    source: &str,
) -> StoreResult<Option<AppliedState>> {
    let row: Option<(i64, Option<String>)> =
        sqlx::query_as("SELECT seq, generation FROM source_applied WHERE source=?")
            .bind(source)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(row.map(|(seq, generation)| AppliedState {
        seq: u64::try_from(seq).unwrap_or(0),
        generation,
    }))
}

async fn write_applied(
    conn: &mut sqlx::SqliteConnection,
    source: &str,
    seq: i64,
    generation: Option<&str>,
) -> StoreResult<()> {
    sqlx::query(
        "INSERT INTO source_applied(source, seq, applied_at, generation) VALUES (?, ?, ?, ?)
         ON CONFLICT(source) DO UPDATE SET seq=excluded.seq, applied_at=excluded.applied_at,
         generation=excluded.generation",
    )
    .bind(source)
    .bind(seq)
    .bind(secmonk_model::time::now_iso())
    .bind(generation)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Whether a batch can be compared with the applied state at all (rust ADR-0010, review M1): seqs only compare
/// within one staging generation, and a module that acknowledged more than the mirror applied means the mirror
/// lost rows the module's log no longer holds. A batch without a generation keeps the plain seq rule.
fn needs_repair(applied: Option<&AppliedState>, batch: &RowsBatch) -> bool {
    let Some(generation) = batch.generation.as_deref() else {
        return false;
    };
    if applied.is_some_and(|a| a.generation.as_deref() != Some(generation)) {
        return true;
    }
    batch.acked_through.unwrap_or(0) > applied.map_or(0, |a| a.seq)
}

#[async_trait]
impl MirrorStore for SqliteStore {
    async fn apply_rows(&self, batch: &RowsBatch) -> StoreResult<ApplyStats> {
        let stmts = prepare(batch)?;
        let seq = seq_i64(batch.seq)?;
        let mut stats = ApplyStats::default();
        let mut tx = self.mirror.write.begin().await?;
        let applied = read_applied(&mut tx, &batch.source).await?;
        if needs_repair(applied.as_ref(), batch) {
            stats.needs_repair = true;
            return Ok(stats);
        }
        // Idempotent replay: a batch at or below the source's last applied seq was applied before (the host
        // stopped between apply and `source.ack`); applying it again would duplicate `affected` rows.
        if applied.as_ref().is_some_and(|a| batch.seq <= a.seq) {
            stats.skipped = true;
            return Ok(stats);
        }
        execute(&mut tx, stmts, &mut stats).await?;
        let generation = batch
            .generation
            .clone()
            .or_else(|| applied.and_then(|a| a.generation));
        write_applied(&mut tx, &batch.source, seq, generation.as_deref()).await?;
        if !batch.ops.is_empty() {
            mark_initialized(&mut tx).await?;
        }
        tx.commit().await?;
        Ok(stats)
    }

    async fn applied_seq(&self, source: &str) -> StoreResult<Option<u64>> {
        Ok(self.applied_state(source).await?.map(|a| a.seq))
    }

    async fn applied_state(&self, source: &str) -> StoreResult<Option<AppliedState>> {
        let mut conn = self.mirror.read.acquire().await?;
        read_applied(&mut conn, source).await
    }

    async fn reset_applied_seq(&self, source: &str) -> StoreResult<()> {
        sqlx::query("DELETE FROM source_applied WHERE source=?")
            .bind(source)
            .execute(&self.mirror.write)
            .await?;
        Ok(())
    }

    async fn begin_repair(&self, source: &str) -> StoreResult<Box<dyn MirrorRepair>> {
        if source.is_empty() {
            return Err(StoreError::Invalid("repair: a source required".into()));
        }
        let mut tx = self.mirror.write.begin().await?;
        let mut deleted = 0;
        for t in MirrorTable::ALL {
            let sql = if t == MirrorTable::SourceSync {
                // per-qualifier cursors (`osv:PyPI`) belong to the source too
                "DELETE FROM source_sync WHERE source = ?1 OR substr(source, 1, length(?1) + 1) = ?1 || ':'"
                    .to_owned()
            } else {
                format!("DELETE FROM {} WHERE source = ?1", t.as_str())
            };
            deleted += sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(source)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        }
        Ok(Box::new(SqliteRepair {
            tx,
            source: source.to_owned(),
            stats: RepairStats {
                deleted,
                ..RepairStats::default()
            },
        }))
    }

    async fn sync_state(&self, source: &str) -> StoreResult<Option<SyncState>> {
        let row = sqlx::query("SELECT source, last_sync, cursor, records, status, message FROM source_sync WHERE source=?")
            .bind(source)
            .fetch_optional(&self.mirror.read)
            .await?;
        row.map(|r| {
            Ok(SyncState {
                source: r.try_get("source")?,
                last_sync: r.try_get("last_sync")?,
                cursor: r.try_get("cursor")?,
                records: r.try_get("records")?,
                status: r.try_get("status")?,
                message: r.try_get("message")?,
            })
        })
        .transpose()
    }

    async fn count_rows(&self, table: MirrorTable, source: &str) -> StoreResult<u64> {
        // table names come from the closed enum, never from input
        let sql = format!("SELECT COUNT(*) FROM {} WHERE source = ?", table.as_str());
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(source)
            .fetch_one(&self.mirror.read)
            .await?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    async fn row_keys(
        &self,
        table: MirrorTable,
        source: &str,
    ) -> StoreResult<Vec<Map<String, Value>>> {
        let t = spec(table);
        if t.key.is_empty() {
            return Err(StoreError::Invalid(format!(
                "{}: no natural key",
                table.as_str()
            )));
        }
        let cols: Vec<String> = t.key.iter().map(|c| format!("\"{c}\"")).collect();
        let sql = format!(
            "SELECT {} FROM {} WHERE source = ? ORDER BY {}",
            cols.join(", "),
            table.as_str(),
            cols.join(", ")
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(source)
            .fetch_all(&self.mirror.read)
            .await?;
        rows.iter()
            .map(|r| {
                t.key
                    .iter()
                    .enumerate()
                    .map(|(i, c)| {
                        let v: Option<String> = r.try_get(i)?;
                        Ok(((*c).to_owned(), v.map_or(Value::Null, Value::String)))
                    })
                    .collect::<StoreResult<Map<String, Value>>>()
            })
            .collect()
    }

    async fn rows_by_id(
        &self,
        table: MirrorTable,
        source: &str,
        ids: &[String],
    ) -> StoreResult<Vec<Map<String, Value>>> {
        let id = table
            .id_column()
            .ok_or_else(|| StoreError::Invalid(format!("{}: no id column", table.as_str())))?;
        if ids.len() > crate::MAX_ROWS_IDS {
            return Err(StoreError::Invalid(format!(
                "rows_by_id: {} ids (at most {})",
                ids.len(),
                crate::MAX_ROWS_IDS
            )));
        }
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let t = spec(table);
        // table and column names come from the closed enum and the allowlist, never from input
        let marks = vec!["?"; ids.len()].join(", ");
        let sql = format!(
            "SELECT rowid, {} FROM {} WHERE source = ? AND \"{id}\" IN ({marks}) ORDER BY rowid",
            select_list(&t),
            table.as_str()
        );
        let mut q = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(source);
        for i in ids {
            q = q.bind(i);
        }
        let rows = q.fetch_all(&self.mirror.read).await?;
        rows.iter()
            .map(|r| decode_row(&t, r).map(|(_, m)| m))
            .collect()
    }

    async fn rows_page(
        &self,
        table: MirrorTable,
        source: &str,
        after: Option<u64>,
        limit: usize,
    ) -> StoreResult<(Vec<Map<String, Value>>, Option<u64>)> {
        if limit == 0 || limit > crate::MAX_ROWS_PAGE {
            return Err(StoreError::Invalid(format!(
                "rows_page: limit {limit} (1..={})",
                crate::MAX_ROWS_PAGE
            )));
        }
        let t = spec(table);
        let sql = rows_page_sql(table);
        let after = i64::try_from(after.unwrap_or(0))
            .map_err(|_| StoreError::Invalid("rows_page: cursor out of range".into()))?;
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(source)
            .bind(after)
            .bind(i64::try_from(limit).unwrap_or(i64::MAX))
            .fetch_all(&self.mirror.read)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        let mut last = None;
        for r in &rows {
            let (rowid, m) = decode_row(&t, r)?;
            last = Some(rowid);
            out.push(m);
        }
        let next = if out.len() == limit { last } else { None };
        Ok((out, next))
    }

    async fn is_initialized(&self) -> StoreResult<bool> {
        is_initialized(&self.mirror.read).await
    }

    async fn checkpoint(&self) -> StoreResult<()> {
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.mirror.write)
            .await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.state.write)
            .await?;
        Ok(())
    }
}

/// The statement of `rows_page`: a scan of the rowid range after the cursor, the source filtered per row. `+source`
/// keeps SQLite from choosing a `source` index, which would sort all of the source's rows into a temporary B-tree for
/// `ORDER BY rowid` on every page (paging quadratic in the size of the source); the rowid range scan reads each row
/// once over all pages and stops after `limit` matches. Public for the store's query-plan test.
#[doc(hidden)]
pub fn rows_page_sql(table: MirrorTable) -> String {
    format!(
        "SELECT rowid, {} FROM {} WHERE +source = ? AND rowid > ? ORDER BY rowid LIMIT ?",
        select_list(&spec(table)),
        table.as_str()
    )
}

/// The quoted writable columns of a table, in spec order.
fn select_list(t: &TableSpec) -> String {
    t.columns
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A row of `SELECT rowid, <writable columns>`: its rowid and its columns as JSON (text as strings, integers and
/// reals as numbers, JSON columns parsed). A JSON column whose text does not parse is `Invalid` (the store only
/// writes JSON it serialized itself).
fn decode_row(
    t: &TableSpec,
    r: &sqlx::sqlite::SqliteRow,
) -> StoreResult<(u64, Map<String, Value>)> {
    use sqlx::{TypeInfo, ValueRef};
    let rowid: i64 = r.try_get(0)?;
    let mut m = Map::with_capacity(t.columns.len());
    for (i, c) in t.columns.iter().enumerate() {
        let raw = r.try_get_raw(i + 1)?;
        let v = if raw.is_null() {
            Value::Null
        } else {
            let kind = raw.type_info().name().to_owned();
            match kind.as_str() {
                "INTEGER" => Value::from(r.try_get::<i64, _>(i + 1)?),
                "REAL" => {
                    let f: f64 = r.try_get(i + 1)?;
                    serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
                }
                _ => {
                    let s: String = r.try_get(i + 1)?;
                    if t.is_json(c) {
                        serde_json::from_str(&s).map_err(|e| {
                            StoreError::Invalid(format!(
                                "{}.{c}: stored JSON does not parse: {e}",
                                t.table.as_str()
                            ))
                        })?
                    } else {
                        Value::String(s)
                    }
                }
            }
        };
        m.insert((*c).to_owned(), v);
    }
    Ok((u64::try_from(rowid).unwrap_or(0), m))
}

/// The export repair of one source: one open transaction on the mirror's write connection.
struct SqliteRepair {
    tx: sqlx::Transaction<'static, sqlx::Sqlite>,
    source: String,
    stats: RepairStats,
}

#[async_trait]
impl MirrorRepair for SqliteRepair {
    async fn apply(&mut self, batch: &RowsBatch) -> StoreResult<ApplyStats> {
        if batch.source != self.source {
            return Err(StoreError::Invalid(format!(
                "repair of {:?}: a batch of source {:?}",
                self.source, batch.source
            )));
        }
        let stmts = prepare(batch)?;
        let mut stats = ApplyStats::default();
        execute(&mut self.tx, stmts, &mut stats).await?;
        self.stats.upserts += stats.upserts;
        self.stats.batches += 1;
        Ok(stats)
    }

    async fn commit(
        mut self: Box<Self>,
        through_seq: u64,
        generation: Option<&str>,
    ) -> StoreResult<RepairStats> {
        let seq = seq_i64(through_seq)?;
        write_applied(&mut self.tx, &self.source, seq, generation).await?;
        if self.stats.upserts > 0 || self.stats.deleted > 0 {
            mark_initialized(&mut self.tx).await?;
        }
        let stats = self.stats;
        self.tx.commit().await?;
        Ok(stats)
    }
}
