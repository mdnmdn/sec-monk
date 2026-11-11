//! Helpers shared by the native source tests: run a sync to its end, pick operations, local HTTP servers (never
//! the network).

#![allow(dead_code)]

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
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    tokio::spawn(async move {
        for (status, body) in responses {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]);
            seen.lock()
                .unwrap()
                .push(head.lines().next().unwrap_or("").to_owned());
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
