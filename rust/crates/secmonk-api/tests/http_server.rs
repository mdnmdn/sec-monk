//! The loopback HTTP binding under hostile clients: an endless header line is not buffered past the head budget,
//! and a silent or trickling client is dropped after the read timeout instead of holding a task forever.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use secmonk_api::{HostPolicy, Router, RouterOptions, StaticDir, serve_http_with, serve_listener};
use secmonk_engine::{EngineInfo, SkeletonEngine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn start(read_timeout: Duration) -> SocketAddr {
    // find a free port, then let the server bind it
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let engine = Arc::new(SkeletonEngine::new(EngineInfo::new(
        "0.1.0",
        "/x/state.sqlite3",
    )));
    let router = Arc::new(Router::new(
        engine,
        RouterOptions {
            static_dir: StaticDir::new(std::env::temp_dir().join("secmonk-http-none")),
            host_policy: HostPolicy::http("127.0.0.1", addr.port(), &[]),
            actions: true,
        },
    ));
    tokio::spawn(serve_http_with(router, addr, read_timeout, |_| {}));
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not start");
}

#[async_trait]
trait ReadAll {
    async fn read_to_end_within(&mut self, d: Duration) -> Option<Vec<u8>>;
}

#[async_trait]
impl ReadAll for TcpStream {
    async fn read_to_end_within(&mut self, d: Duration) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        tokio::time::timeout(d, self.read_to_end(&mut buf))
            .await
            .ok()?
            .ok()?;
        Some(buf)
    }
}

#[tokio::test]
async fn a_silent_client_is_dropped_after_the_read_timeout() {
    let addr = start(Duration::from_millis(300)).await;
    let mut c = TcpStream::connect(addr).await.unwrap();
    let got = c.read_to_end_within(Duration::from_secs(3)).await;
    assert_eq!(
        got,
        Some(Vec::new()),
        "the server closes a client that sends nothing"
    );
}

#[tokio::test]
async fn a_trickling_client_is_dropped_too() {
    let addr = start(Duration::from_millis(400)).await;
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(b"GET /api/meta HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        .await
        .unwrap();
    // never finishes the head: one byte now and then does not extend the deadline
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = c.write_all(b"X").await;
    }
    let got = c.read_to_end_within(Duration::from_secs(3)).await;
    assert_eq!(got, Some(Vec::new()));
}

#[tokio::test]
async fn an_endless_header_line_is_refused_at_the_budget() {
    let addr = start(Duration::from_secs(5)).await;
    let mut c = TcpStream::connect(addr).await.unwrap();
    // a head line of exactly budget + 1 bytes (64 KiB + 1) without a newline: refused with 400 at once, instead of
    // waiting for a newline that never comes
    let line = vec![b'a'; 64 * 1024 + 1];
    c.write_all(&line).await.unwrap();
    let sent = line.len();
    let got = c
        .read_to_end_within(Duration::from_secs(3))
        .await
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&got);
    assert!(
        text.starts_with("HTTP/1.1 400"),
        "got {text:?} after {sent} bytes"
    );
}

#[tokio::test]
async fn a_normal_request_still_works() {
    let addr = start(Duration::from_secs(5)).await;
    let mut c = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET /api/meta HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-SecMonk-Request: 1\r\n\r\n",
        addr.port()
    );
    c.write_all(req.as_bytes()).await.unwrap();
    let got = c.read_to_end_within(Duration::from_secs(3)).await.unwrap();
    assert!(String::from_utf8_lossy(&got).starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn connections_are_limited_and_a_freed_slot_serves_the_next() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let engine = Arc::new(SkeletonEngine::new(EngineInfo::new(
        "0.1.0",
        "/x/state.sqlite3",
    )));
    let router = Arc::new(Router::new(
        engine,
        RouterOptions {
            static_dir: StaticDir::new(std::env::temp_dir().join("secmonk-http-none")),
            host_policy: HostPolicy::http("127.0.0.1", addr.port(), &[]),
            actions: true,
        },
    ));
    tokio::spawn(serve_listener(router, listener, Duration::from_secs(30), 2));
    // two silent clients take both slots
    let a = TcpStream::connect(addr).await.unwrap();
    let b = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let req = format!(
        "GET /api/meta HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-SecMonk-Request: 1\r\n\r\n",
        addr.port()
    );
    // past the cap a connection is accepted and closed at once (no answer, no waiting in the backlog)
    let mut c = TcpStream::connect(addr).await.unwrap();
    let _ = c.write_all(req.as_bytes()).await;
    // closed without an answer (a clean EOF, or a reset when our request was still unread)
    let got = tokio::time::timeout(Duration::from_secs(2), async {
        let mut buf = Vec::new();
        let _ = c.read_to_end(&mut buf).await;
        buf
    })
    .await
    .expect("closed at once, not left waiting");
    assert!(got.is_empty(), "no answer while both slots are taken");
    drop(a); // a slot frees: the next client is served
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut d = TcpStream::connect(addr).await.unwrap();
    d.write_all(req.as_bytes()).await.unwrap();
    let got = d.read_to_end_within(Duration::from_secs(3)).await.unwrap();
    assert!(String::from_utf8_lossy(&got).starts_with("HTTP/1.1 200"));
    drop(b);
}
