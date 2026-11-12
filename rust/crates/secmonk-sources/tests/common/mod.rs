//! Helpers shared by the native source tests: run a sync to its end, pick operations, local HTTP servers (never
//! the network).

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_traits::{CallCtx, ProgressUpdate, RowsBatch, Source, StreamMsg, SyncEnd, SyncParams};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn params(source: &str, options: Value) -> SyncParams {
    serde_json::from_value(json!({"source": source, "options": options})).unwrap()
}

/// Run one sync to its end: batches, end, progress lines.
pub async fn run(
    src: &dyn Source,
    source: &str,
    options: Value,
) -> (Vec<RowsBatch>, SyncEnd, Vec<String>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let l = lines.clone();
    let ctx = CallCtx {
        deadline: None,
        progress: Some(Arc::new(move |u: ProgressUpdate| {
            l.lock().unwrap().extend(u.message);
        })),
    };
    let mut s = src.sync(params(source, options), ctx).await.unwrap();
    let mut batches = Vec::new();
    let mut end = None;
    while let Some(m) = s.next().await {
        match m.unwrap() {
            StreamMsg::Item(b) => {
                assert!(end.is_none(), "no batch after the end");
                batches.push(b)
            }
            StreamMsg::End(e) => end = Some(e),
        }
    }
    let lines = lines.lock().unwrap().clone();
    (batches, end.unwrap(), lines)
}

pub fn ops(b: &[RowsBatch]) -> Vec<RowOp> {
    b.iter().flat_map(|b| b.ops.clone()).collect()
}

/// Upserted rows (`upsert`) or delete keys (`!upsert`) of `table`.
pub fn of(ops: &[RowOp], table: MirrorTable, upsert: bool) -> Vec<JsonMap> {
    ops.iter()
        .filter_map(|o| match o {
            RowOp::Upsert { table: t, row } if upsert && *t == table => Some(row.clone()),
            RowOp::Delete { table: t, key } if !upsert && *t == table => Some(key.clone()),
            _ => None,
        })
        .collect()
}

/// A local HTTP server answering each connection with the next canned response; the request lines are recorded.
pub async fn serve_logged(responses: Vec<(u16, Vec<u8>)>) -> (String, Arc<Mutex<Vec<String>>>) {
    serve_headers(
        responses
            .into_iter()
            .map(|(status, body)| (status, Vec::new(), body))
            .collect(),
    )
    .await
}

/// A canned answer: status, extra headers, body.
pub type Answer = (u16, Vec<(&'static str, String)>, Vec<u8>);

/// [`serve_logged`] with extra response headers per response (`Location` of a redirect).
pub async fn serve_headers(responses: Vec<Answer>) -> (String, Arc<Mutex<Vec<String>>>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    tokio::spawn(async move {
        for (status, headers, body) in responses {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]);
            seen.lock()
                .unwrap()
                .push(head.lines().next().unwrap_or("").to_owned());
            let extra: String = headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}\r\n"))
                .collect();
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&body).await;
            let _ = s.shutdown().await;
        }
    });
    (format!("http://{addr}"), log)
}

/// [`serve_headers`] that records the whole request head of each connection (request line and headers, as sent),
/// and closes a connection without an answer for a status of 0 (a transport error for the client).
pub async fn serve_heads(responses: Vec<Answer>) -> (String, Arc<Mutex<Vec<String>>>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    tokio::spawn(async move {
        for (status, headers, body) in responses {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 16384];
            let mut n = 0;
            while n < buf.len() {
                let k = s.read(&mut buf[n..]).await.unwrap_or(0);
                n += k;
                if k == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            seen.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[..n]).into_owned());
            if status == 0 {
                let _ = s.shutdown().await;
                continue;
            }
            let extra: String = headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}\r\n"))
                .collect();
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&body).await;
            let _ = s.shutdown().await;
        }
    });
    (format!("http://{addr}"), log)
}

/// [`serve_logged`] without the log.
pub async fn serve(responses: Vec<(u16, Vec<u8>)>) -> String {
    serve_logged(responses).await.0
}

/// A one-shot local server writing `raw` (status line, headers and body as given) and closing.
pub async fn serve_raw(raw: Vec<u8>) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf).await;
        let _ = s.write_all(&raw).await;
        let _ = s.shutdown().await;
    });
    format!("http://{addr}/feed.json")
}

/// An in-memory mirror for importer tests: a [`MirrorView`] over rows held here, and [`MemView::apply`] that
/// applies batches the way `MirrorStore::apply_rows` does for the cases an importer test needs (an upsert updates the
/// given columns of the row with the same key in place or inserts one, `affected` upserts insert, a delete removes the
/// row with that key, an `affected` delete the first row (by rowid) equal on every given column; no source binding or
/// owner rule). Every row gets a rowid from a counter that never goes back, and `rows_page` pages by it as the store
/// does (`rowid > after ORDER BY rowid`, `next` = the last rowid of a full page): rows deleted between pages skip
/// nothing, and an exactly full last page is followed by an empty one. Keyed rows and `affected` rows are indexed, so
/// applying and reading cost no scan of the table per operation. The engine tests use the real store.
#[derive(Default)]
pub struct MemView {
    pub state: Mutex<MemState>,
}

#[derive(Default)]
pub struct MemState {
    pub applied: Option<secmonk_traits::AppliedMark>,
    next_rowid: u64,
    tables: HashMap<MirrorTable, Table>,
}

/// The rows of one table: by rowid, the primary key index (keyed tables), the id index (`(source, id column)`).
#[derive(Default)]
struct Table {
    rows: BTreeMap<u64, JsonMap>,
    by_key: HashMap<String, u64>,
    by_id: HashMap<String, BTreeSet<u64>>,
}

impl Table {
    /// `(source, id column)` of a row as text (`None`: a table without an id column).
    fn id_of(t: MirrorTable, row: &JsonMap) -> Option<String> {
        let col = t.id_column()?;
        Some(id_text(
            row.get("source").unwrap_or(&Value::Null),
            row.get(col).unwrap_or(&Value::Null),
        ))
    }

    fn insert(&mut self, t: MirrorTable, rowid: u64, row: JsonMap) {
        if let Some(k) = key_of(t, &row) {
            self.by_key.insert(k, rowid);
        }
        if let Some(id) = Table::id_of(t, &row) {
            self.by_id.entry(id).or_default().insert(rowid);
        }
        self.rows.insert(rowid, row);
    }

    fn remove(&mut self, t: MirrorTable, rowid: u64) {
        let Some(row) = self.rows.remove(&rowid) else {
            return;
        };
        if let Some(k) = key_of(t, &row) {
            self.by_key.remove(&k);
        }
        if let Some(id) = Table::id_of(t, &row)
            && let Some(set) = self.by_id.get_mut(&id)
        {
            set.remove(&rowid);
            if set.is_empty() {
                self.by_id.remove(&id);
            }
        }
    }
}

/// Primary key columns of a mirror table (`secmonk-store` `mirror_schema`; empty for `affected`).
pub fn key_columns(t: MirrorTable) -> &'static [&'static str] {
    match t {
        MirrorTable::SourceSync => &["source"],
        MirrorTable::RawRecord => &["source", "record_id"],
        MirrorTable::Vulnerability => &["source", "id"],
        MirrorTable::Alias => &["vuln_id", "alias", "source"],
        MirrorTable::Affected => &[],
        MirrorTable::Kev | MirrorTable::Epss => &["cve_id"],
        MirrorTable::DistroTriage => &["ecosystem", "package", "cve_id", "source"],
    }
}

fn id_text(source: &Value, id: &Value) -> String {
    serde_json::to_string(&[source, id]).unwrap()
}

/// The primary key of a row or a delete key as text (`None`: a table without one, or a key column missing).
fn key_of(t: MirrorTable, row: &JsonMap) -> Option<String> {
    let cols = key_columns(t);
    if cols.is_empty() {
        return None;
    }
    let vals: Option<Vec<&Value>> = cols.iter().map(|c| row.get(*c)).collect();
    Some(serde_json::to_string(&vals?).unwrap())
}

impl MemView {
    pub fn new() -> Arc<MemView> {
        Arc::new(MemView::default())
    }

    /// Apply batches in order and record the last one as the applied state.
    pub fn apply(&self, batches: &[RowsBatch]) {
        let mut st = self.state.lock().unwrap();
        let st = &mut *st;
        for b in batches {
            for op in &b.ops {
                match op {
                    RowOp::Upsert { table, row } => {
                        let tab = st.tables.entry(*table).or_default();
                        let at = key_of(*table, row).and_then(|k| tab.by_key.get(&k).copied());
                        match at {
                            Some(rowid) => {
                                // the given columns updated in place (the rowid stays, as `ON CONFLICT DO UPDATE`)
                                let mut merged = tab.rows[&rowid].clone();
                                merged.extend(row.clone());
                                tab.remove(*table, rowid);
                                tab.insert(*table, rowid, merged);
                            }
                            None => {
                                st.next_rowid += 1;
                                tab.insert(*table, st.next_rowid, row.clone());
                            }
                        }
                    }
                    RowOp::Delete { table, key } => {
                        let tab = st.tables.entry(*table).or_default();
                        let hit = match key_of(*table, key) {
                            Some(k) => tab.by_key.get(&k).copied(),
                            None => {
                                let equal =
                                    |r: &JsonMap| key.iter().all(|(k, v)| r.get(k) == Some(v));
                                let candidates: Vec<u64> =
                                    match Table::id_of(*table, key).filter(|_| {
                                        table.id_column().is_some_and(|c| key.contains_key(c))
                                    }) {
                                        Some(id) => tab
                                            .by_id
                                            .get(&id)
                                            .into_iter()
                                            .flatten()
                                            .copied()
                                            .collect(),
                                        None => tab.rows.keys().copied().collect(),
                                    };
                                candidates.into_iter().find(|i| equal(&tab.rows[i]))
                            }
                        };
                        if let Some(rowid) = hit {
                            tab.remove(*table, rowid);
                        }
                    }
                }
            }
            st.applied = Some(secmonk_traits::AppliedMark {
                seq: b.seq,
                generation: b.generation.clone(),
            });
        }
    }

    /// The rows of `table` (of every source), in rowid order.
    pub fn rows(&self, table: MirrorTable) -> Vec<JsonMap> {
        let st = self.state.lock().unwrap();
        st.tables
            .get(&table)
            .map(|t| t.rows.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Apply `f` to the rows of `table` of `source`, in rowid order (no copy of the others).
    fn with_source<R>(
        &self,
        table: MirrorTable,
        source: &str,
        f: impl FnOnce(&mut dyn Iterator<Item = (u64, &JsonMap)>) -> R,
    ) -> R {
        let st = self.state.lock().unwrap();
        let empty = BTreeMap::new();
        let rows = st.tables.get(&table).map_or(&empty, |t| &t.rows);
        let mut it = rows
            .iter()
            .filter(|(_, r)| r.get("source").and_then(Value::as_str) == Some(source))
            .map(|(i, r)| (*i, r));
        f(&mut it)
    }
}

#[async_trait::async_trait]
impl secmonk_traits::MirrorView for MemView {
    async fn applied(
        &self,
        _: &str,
    ) -> secmonk_traits::StepResult<Option<secmonk_traits::AppliedMark>> {
        Ok(self.state.lock().unwrap().applied.clone())
    }
    async fn count_rows(&self, t: MirrorTable, s: &str) -> secmonk_traits::StepResult<u64> {
        Ok(self.with_source(t, s, |it| it.count()) as u64)
    }
    async fn row_keys(&self, t: MirrorTable, s: &str) -> secmonk_traits::StepResult<Vec<JsonMap>> {
        let key = key_columns(t);
        Ok(self.with_source(t, s, |it| {
            it.map(|(_, r)| {
                r.iter()
                    .filter(|(k, _)| key.contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .collect()
        }))
    }
    async fn rows_by_id(
        &self,
        t: MirrorTable,
        s: &str,
        ids: &[String],
    ) -> secmonk_traits::StepResult<Vec<JsonMap>> {
        assert!(
            ids.len() <= secmonk_traits::MAX_VIEW_IDS,
            "{} ids",
            ids.len()
        );
        t.id_column().expect("a table with an id column");
        let st = self.state.lock().unwrap();
        let Some(tab) = st.tables.get(&t) else {
            return Ok(Vec::new());
        };
        // storage order, as the store's `ORDER BY rowid`
        let mut hits: Vec<u64> = ids
            .iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .filter_map(|id| tab.by_id.get(&id_text(&json!(s), &json!(id))))
            .flatten()
            .copied()
            .collect();
        hits.sort_unstable();
        Ok(hits.into_iter().map(|i| tab.rows[&i].clone()).collect())
    }
    async fn rows_page(
        &self,
        t: MirrorTable,
        s: &str,
        after: Option<u64>,
        limit: usize,
    ) -> secmonk_traits::StepResult<secmonk_traits::RowPage> {
        assert!(
            (1..=secmonk_traits::MAX_VIEW_PAGE).contains(&limit),
            "limit {limit}"
        );
        let st = self.state.lock().unwrap();
        let mut rows = Vec::new();
        let mut last = None;
        if let Some(tab) = st.tables.get(&t) {
            let from = after.unwrap_or(0).saturating_add(1);
            for (i, r) in tab
                .rows
                .range(from..)
                .filter(|(_, r)| r.get("source").and_then(Value::as_str) == Some(s))
                .take(limit)
            {
                last = Some(*i);
                rows.push(r.clone());
            }
        }
        let next = if rows.len() == limit { last } else { None };
        Ok(secmonk_traits::RowPage { rows, next })
    }
}
