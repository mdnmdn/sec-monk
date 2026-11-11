//! Tauri-free loopback HTTP binding of the router: the Linux headless build, headless tests and the optional dev binding (`[ui] http_listen`): a minimal
//! HTTP/1.1 server (one request per connection, `Connection: close`). It builds the request URI from the `Host`
//! header, so the router's Host rules apply exactly as on the Python server.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::{ApiError, MAX_BODY, Router};
use http::{Method, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const MAX_HEAD: usize = 64 * 1024;

/// How long a client may take to send its request (head and body together); a slow or silent one is dropped.
pub const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a client may take to receive the response; a peer that stops reading is dropped.
pub const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Connections served at once; further ones wait in the accept backlog (a loopback server has no use for more).
pub const MAX_CONNECTIONS: usize = 64;

/// Listen on `addr` and answer every connection with `router`. `on_bound` gets the real address (port 0 works).
pub async fn serve_http(
    router: Arc<Router>,
    addr: SocketAddr,
    on_bound: impl FnOnce(SocketAddr),
) -> std::io::Result<()> {
    serve_http_with(router, addr, READ_TIMEOUT, on_bound).await
}

/// [`serve_http`] with another request read timeout (tests).
pub async fn serve_http_with(
    router: Arc<Router>,
    addr: SocketAddr,
    read_timeout: std::time::Duration,
    on_bound: impl FnOnce(SocketAddr),
) -> std::io::Result<()> {
    serve_listener(
        router,
        bind(addr, on_bound).await?,
        read_timeout,
        MAX_CONNECTIONS,
    )
    .await
}

async fn bind(addr: SocketAddr, on_bound: impl FnOnce(SocketAddr)) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(addr).await?;
    on_bound(listener.local_addr()?);
    Ok(listener)
}

/// The accept loop: an accept error (out of file descriptors, a connection reset before accept) is logged and the
/// loop goes on after a short pause; it never ends the server. At most `max_connections` are served at once.
pub async fn serve_listener(
    router: Arc<Router>,
    listener: TcpListener,
    read_timeout: std::time::Duration,
    max_connections: usize,
) -> std::io::Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(max_connections));
    let mut failures = 0u32;
    loop {
        // take the slot before accepting: past the limit the kernel queues new connections
        let Ok(permit) = slots.clone().acquire_owned().await else {
            return Ok(());
        };
        let stream = match listener.accept().await {
            Ok((stream, _)) => {
                failures = 0;
                stream
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                let pause = std::time::Duration::from_millis(50u64 << failures.min(6));
                tracing::warn!("accept failed: {e}; retrying in {pause:?}");
                tokio::time::sleep(pause).await;
                continue;
            }
        };
        let router = router.clone();
        tokio::spawn(async move {
            let _ = connection(router, stream, read_timeout).await;
            drop(permit);
        });
    }
}

async fn connection(
    router: Arc<Router>,
    stream: TcpStream,
    read_timeout: std::time::Duration,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    // a client that stalls (or trickles bytes) is cut off; nothing is answered to a silent peer
    let read = tokio::time::timeout(read_timeout, read_request(&mut reader)).await;
    let Ok(read) = read else {
        return Ok(());
    };
    let Some(request) = read? else {
        let r = bad_request();
        return write_timed(reader.get_mut(), r).await;
    };
    let response = router.handle(request).await;
    write_timed(reader.get_mut(), response).await
}

async fn write_timed(stream: &mut TcpStream, response: Response<Vec<u8>>) -> std::io::Result<()> {
    match tokio::time::timeout(WRITE_TIMEOUT, write_response(stream, response)).await {
        Ok(r) => r,
        Err(_) => Ok(()), // the peer stopped reading: dropped
    }
}

fn bad_request() -> Response<Vec<u8>> {
    crate::router::error_response(&ApiError::bad_request("bad request"))
}

async fn read_line(
    r: &mut BufReader<TcpStream>,
    budget: &mut usize,
) -> std::io::Result<Option<String>> {
    use tokio::io::AsyncBufReadExt;
    let mut line = Vec::new();
    // never buffer more than the head budget left: `take` stops the read, a line that fills it is refused
    let n = (&mut *r)
        .take(*budget as u64 + 1)
        .read_until(b'\n', &mut line)
        .await?;
    if n == 0 || n > *budget {
        return Ok(None);
    }
    *budget -= n;
    Ok(Some(String::from_utf8_lossy(&line).trim_end().to_owned()))
}

async fn read_request(r: &mut BufReader<TcpStream>) -> std::io::Result<Option<Request<Vec<u8>>>> {
    let mut budget = MAX_HEAD;
    let Some(line) = read_line(r, &mut budget).await? else {
        return Ok(None);
    };
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Ok(None);
    };
    let Ok(method) = method.parse::<Method>() else {
        return Ok(None);
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let Some(h) = read_line(r, &mut budget).await? else {
            return Ok(None);
        };
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    let host = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone());
    // the authority comes from Host, so a request without one (or a bad one) has none and is refused (421)
    let uri = match &host {
        Some(h) => format!("http://{h}{target}"),
        None => target.to_owned(),
    };
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in &headers {
        b = b.header(k.as_str(), v.as_str());
    }
    let declared: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    // never read more than the router would accept; a larger declared length is answered 413 from the header
    let mut body = vec![0; declared.min(MAX_BODY + 1)];
    r.read_exact(&mut body).await?;
    Ok(b.body(body).ok())
}

async fn write_response(
    stream: &mut TcpStream,
    response: Response<Vec<u8>>,
) -> std::io::Result<()> {
    let mut head = format!("HTTP/1.1 {}\r\nConnection: close\r\n", response.status());
    for (k, v) in response.headers() {
        head.push_str(&format!("{}: {}\r\n", k, v.to_str().unwrap_or("")));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(response.body()).await?;
    stream.shutdown().await
}
