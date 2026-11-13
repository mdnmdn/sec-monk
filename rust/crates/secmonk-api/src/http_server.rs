//! HTTP/1.1 binding of the [`Server`] (and so of the router): one request per connection, `Connection: close`,
//! over plain TCP (the Linux headless build, tests, the optional dev binding `[ui] http_listen`) or TLS (server
//! mode). It builds the request URI from the `Host` header, so the router's Host rules apply exactly as on the
//! Python server.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{ApiError, Router, Server};
use http::{Method, Request, Response, StatusCode, Uri};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;
use tokio_util::sync::CancellationToken;

const MAX_HEAD: usize = 64 * 1024;

/// How long a client may take to send its request (head and body together); a slow or silent one is dropped.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a TLS handshake may take; a client that stalls in it is dropped (then [`READ_TIMEOUT`] starts).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a client may take to receive the response; a peer that stops reading is dropped.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Connections served at once by the loopback bindings ([`ServerOptions::new`]).
pub const MAX_CONNECTIONS: usize = 64;

/// Connections served at once in server mode ([`ServerOptions::server_mode`]).
pub const SERVER_MODE_MAX_CONNECTIONS: usize = 512;

/// Connections served at once for one client address (trusted proxies are exempt).
pub const MAX_PER_IP: usize = 16;

/// How long in-flight connections may run on after a shutdown was requested.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// First pause after a failed `accept` (doubled per failure, up to 2^[`ACCEPT_BACKOFF_MAX_SHIFT`] times).
const ACCEPT_BACKOFF_BASE: Duration = Duration::from_millis(50);
const ACCEPT_BACKOFF_MAX_SHIFT: u32 = 6;

/// PEM files of the server certificate chain and its private key.
#[derive(Debug, Clone)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// How [`serve`] listens.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub listen: SocketAddr,
    /// `Some`: HTTPS (TLS 1.2/1.3, ALPN `http/1.1`); `None`: plain HTTP (see [`check_exposure`]).
    pub tls: Option<TlsFiles>,
    pub read_timeout: Duration,
    /// Connections served at once; a connection past the cap is accepted and closed at once.
    pub max_connections: usize,
    /// Connections served at once per client address (TCP peer; trusted proxies are exempt).
    pub max_per_ip: usize,
    /// How long a TLS handshake may take.
    pub handshake_timeout: Duration,
}

impl ServerOptions {
    /// The loopback defaults ([`READ_TIMEOUT`], [`MAX_CONNECTIONS`], [`MAX_PER_IP`], [`HANDSHAKE_TIMEOUT`]) for
    /// `listen`, plain HTTP.
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            tls: None,
            read_timeout: READ_TIMEOUT,
            max_connections: MAX_CONNECTIONS,
            max_per_ip: MAX_PER_IP,
            handshake_timeout: HANDSHAKE_TIMEOUT,
        }
    }

    /// The server-mode defaults: as [`ServerOptions::new`] with [`SERVER_MODE_MAX_CONNECTIONS`].
    pub fn server_mode(listen: SocketAddr) -> Self {
        Self {
            max_connections: SERVER_MODE_MAX_CONNECTIONS,
            ..Self::new(listen)
        }
    }

    fn limits(&self) -> Limits {
        Limits {
            read_timeout: self.read_timeout,
            handshake_timeout: self.handshake_timeout,
            max_connections: self.max_connections,
            max_per_ip: self.max_per_ip,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    read_timeout: Duration,
    handshake_timeout: Duration,
    max_connections: usize,
    max_per_ip: usize,
}

/// May the server listen like this? A non-loopback address needs authentication on, and TLS or an explicit
/// `insecure_http` (plain HTTP behind a TLS-terminating proxy). The error is the message for the operator.
pub fn check_exposure(
    listen: &SocketAddr,
    tls: bool,
    auth_on: bool,
    insecure_http: bool,
) -> Result<(), String> {
    if listen.ip().to_canonical().is_loopback() {
        return Ok(());
    }
    if !auth_on {
        return Err(format!(
            "listening on {listen} (not a loopback address) requires authentication: create an API key \
             (`secmonk-server apikey create`) and leave [server] auth = \"auto\" or set \"required\""
        ));
    }
    if !tls && !insecure_http {
        return Err(format!(
            "listening on {listen} (not a loopback address) requires TLS: pass --tls-cert and --tls-key \
             (or set [server] tls_cert / tls_key), or set [server] insecure_http = true behind a \
             TLS-terminating proxy"
        ));
    }
    Ok(())
}

/// Load the certificate chain and key into a TLS acceptor (aws-lc-rs provider, ALPN `http/1.1`).
pub fn tls_acceptor(files: &TlsFiles) -> io::Result<TlsAcceptor> {
    let bad = |what: &str, path: &Path, e: &dyn std::fmt::Display| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} {}: {e}", path.display()),
        )
    };
    let certs = CertificateDer::pem_file_iter(&files.cert)
        .map_err(|e| bad("TLS certificate", &files.cert, &e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| bad("TLS certificate", &files.cert, &e))?;
    if certs.is_empty() {
        return Err(bad(
            "TLS certificate",
            &files.cert,
            &"no certificate in the file",
        ));
    }
    let key =
        PrivateKeyDer::from_pem_file(&files.key).map_err(|e| bad("TLS key", &files.key, &e))?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| io::Error::other(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| bad("TLS key", &files.key, &e))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Listen as `opts` say and answer every connection with `server`, until the process ends. `on_bound` gets the
/// real address (port 0 works). Certificate problems are reported before anything is bound.
pub async fn serve(
    server: Arc<Server>,
    opts: ServerOptions,
    on_bound: impl FnOnce(SocketAddr),
) -> io::Result<()> {
    serve_until(server, opts, on_bound, CancellationToken::new()).await
}

/// [`serve`] until `shutdown` is cancelled: then the listener closes (no new connection), the connections in
/// flight get up to [`SHUTDOWN_GRACE`] to finish (the rest are aborted), and the function returns `Ok(())`.
pub async fn serve_until(
    server: Arc<Server>,
    opts: ServerOptions,
    on_bound: impl FnOnce(SocketAddr),
    shutdown: CancellationToken,
) -> io::Result<()> {
    let acceptor = opts.tls.as_ref().map(tls_acceptor).transpose()?;
    let listener = bind(opts.listen, on_bound).await?;
    run(server, listener, acceptor, opts.limits(), shutdown).await
}

/// Listen on `addr` and answer every connection with `router` (no authentication, plain HTTP, loopback use).
/// `on_bound` gets the real address (port 0 works). For the example and tests; the apps use [`serve`].
#[doc(hidden)]
pub async fn serve_http(
    router: Arc<Router>,
    addr: SocketAddr,
    on_bound: impl FnOnce(SocketAddr),
) -> io::Result<()> {
    serve_http_with(router, addr, READ_TIMEOUT, on_bound).await
}

/// [`serve_http`] with another request read timeout (tests).
#[doc(hidden)]
pub async fn serve_http_with(
    router: Arc<Router>,
    addr: SocketAddr,
    read_timeout: Duration,
    on_bound: impl FnOnce(SocketAddr),
) -> io::Result<()> {
    serve_listener(
        router,
        bind(addr, on_bound).await?,
        read_timeout,
        MAX_CONNECTIONS,
    )
    .await
}

async fn bind(addr: SocketAddr, on_bound: impl FnOnce(SocketAddr)) -> io::Result<TcpListener> {
    let listener = TcpListener::bind(addr).await?;
    on_bound(listener.local_addr()?);
    Ok(listener)
}

/// The accept loop over an existing listener, router only, plain HTTP (tests).
#[doc(hidden)]
pub async fn serve_listener(
    router: Arc<Router>,
    listener: TcpListener,
    read_timeout: Duration,
    max_connections: usize,
) -> io::Result<()> {
    accept_loop(
        Arc::new(Server::new(router)),
        listener,
        None,
        read_timeout,
        max_connections,
    )
    .await
}

/// The accept loop over an existing listener (tests of this crate and of secmonk-node). The per-address cap is
/// `max_connections` (no stricter than the global one); the TLS handshake gets at most [`HANDSHAKE_TIMEOUT`].
#[doc(hidden)]
pub async fn accept_loop(
    server: Arc<Server>,
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    read_timeout: Duration,
    max_connections: usize,
) -> io::Result<()> {
    let limits = Limits {
        read_timeout,
        handshake_timeout: HANDSHAKE_TIMEOUT.min(read_timeout),
        max_connections,
        max_per_ip: max_connections,
    };
    run(server, listener, tls, limits, CancellationToken::new()).await
}

/// Open connections per client address.
#[derive(Debug)]
struct PerIp {
    max: usize,
    open: Mutex<HashMap<IpAddr, usize>>,
}

/// One connection's share of [`PerIp`], given back on drop.
struct IpSlot {
    per_ip: Arc<PerIp>,
    ip: IpAddr,
}

impl PerIp {
    fn take(self: &Arc<Self>, ip: IpAddr) -> Option<IpSlot> {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        let n = open.entry(ip).or_insert(0);
        if *n >= self.max {
            return None;
        }
        *n += 1;
        Some(IpSlot {
            per_ip: self.clone(),
            ip,
        })
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut open = self.per_ip.open.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = open.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                open.remove(&self.ip);
            }
        }
    }
}

/// The accept loop: accept first, then check the global and the per-address caps and close an excess connection
/// at once (an idle socket never holds a slot it was not given; the backlog never fills with waiting clients).
/// An accept error (out of file descriptors, a reset before accept) is logged and the loop goes on after a short
/// pause; it never ends the server. A failed TLS handshake only drops that connection. On `shutdown` the
/// listener is dropped and the connections in flight get [`SHUTDOWN_GRACE`].
async fn run(
    server: Arc<Server>,
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    limits: Limits,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let per_ip = Arc::new(PerIp {
        max: limits.max_per_ip,
        open: Mutex::new(HashMap::new()),
    });
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut failures = 0u32;
    loop {
        let accepted = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
            r = listener.accept() => r,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => {
                failures = 0;
                pair
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                let pause = ACCEPT_BACKOFF_BASE * (1u32 << failures.min(ACCEPT_BACKOFF_MAX_SHIFT));
                tracing::warn!("accept failed: {e}; retrying in {pause:?}");
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(pause) => {}
                }
                continue;
            }
        };
        let Ok(global) = slots.clone().try_acquire_owned() else {
            tracing::debug!(peer = %peer, "connection refused: server at its connection cap");
            drop(stream);
            continue;
        };
        let ip = peer.ip().to_canonical();
        let ip_slot = if server.trusted_proxies().contains(ip) {
            None
        } else {
            match per_ip.take(ip) {
                Some(slot) => Some(slot),
                None => {
                    tracing::debug!(peer = %peer, "connection refused: address at its connection cap");
                    drop(stream);
                    continue;
                }
            }
        };
        let server = server.clone();
        let tls = tls.clone();
        tasks.spawn(async move {
            match tls {
                None => {
                    let _ = connection(&server, stream, Some(peer), limits.read_timeout).await;
                }
                Some(acceptor) => {
                    // the handshake has its own, shorter deadline; the request read starts after it
                    if let Ok(Ok(tls_stream)) =
                        tokio::time::timeout(limits.handshake_timeout, acceptor.accept(stream))
                            .await
                    {
                        let _ =
                            connection(&server, tls_stream, Some(peer), limits.read_timeout).await;
                    }
                }
            }
            drop(ip_slot);
            drop(global);
        });
    }
    drop(listener);
    let drained = tokio::time::timeout(SHUTDOWN_GRACE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!(
            open = tasks.len(),
            "shutdown: connections still open after {SHUTDOWN_GRACE:?}, closing them"
        );
        tasks.shutdown().await;
    }
    Ok(())
}

async fn connection<S>(
    server: &Server,
    stream: S,
    peer: Option<SocketAddr>,
    read_timeout: Duration,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    // a client that stalls (or trickles bytes) is cut off; nothing is answered to a silent peer
    let read = tokio::time::timeout(read_timeout, read_request(&mut reader, server)).await;
    let Ok(read) = read else {
        return Ok(());
    };
    let request = match read? {
        Ok(r) => r,
        Err(status) => return write_timed(reader.get_mut(), refused(status)).await,
    };
    let response = server.handle(request, peer).await;
    write_timed(reader.get_mut(), response).await
}

async fn write_timed<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response: Response<Vec<u8>>,
) -> io::Result<()> {
    match tokio::time::timeout(WRITE_TIMEOUT, write_response(stream, response)).await {
        Ok(r) => r,
        Err(_) => Ok(()), // the peer stopped reading: dropped
    }
}

fn refused(status: StatusCode) -> Response<Vec<u8>> {
    let msg = match status {
        StatusCode::NOT_IMPLEMENTED => "Transfer-Encoding is not supported",
        _ => "bad request",
    };
    crate::router::error_response(&ApiError::new(status, msg))
}

async fn read_line<S: AsyncRead + Unpin>(
    r: &mut BufReader<S>,
    budget: &mut usize,
) -> io::Result<Option<String>> {
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

/// A header name: an RFC 9110 token (no whitespace before the colon, no control characters).
fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// A `Host` value made of authority characters only (reg-name / IP literal and port): no `/ ? # @`, no
/// whitespace, no control or non-ASCII byte, so it cannot change the URI it is spliced into.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:[]%".contains(&b))
}

/// Read and check one request head and its body. `Err(status)` refuses it: 400 for a malformed head (bad
/// request line, bad header line, duplicate or non-numeric `Content-Length`, several or bad `Host`), 501 for
/// `Transfer-Encoding` (no chunked bodies: one framing only, no smuggling).
async fn read_request<S: AsyncRead + Unpin>(
    r: &mut BufReader<S>,
    server: &Server,
) -> io::Result<Result<Request<Vec<u8>>, StatusCode>> {
    let bad = Err(StatusCode::BAD_REQUEST);
    let mut budget = MAX_HEAD;
    let Some(line) = read_line(r, &mut budget).await? else {
        return Ok(bad);
    };
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Ok(bad);
    };
    // origin-form only: the authority comes from Host, never from the target
    if !target.starts_with('/') {
        return Ok(bad);
    }
    let Ok(method) = method.parse::<Method>() else {
        return Ok(bad);
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let Some(h) = read_line(r, &mut budget).await? else {
            return Ok(bad);
        };
        if h.is_empty() {
            break;
        }
        // no obs-fold continuation lines, no line without a colon, no space before the colon
        let Some((k, v)) = h.split_once(':') else {
            return Ok(bad);
        };
        if !valid_header_name(k) {
            return Ok(bad);
        }
        headers.push((k.to_owned(), v.trim().to_owned()));
    }
    fn named<'h>(headers: &'h [(String, String)], name: &'static str) -> Vec<&'h str> {
        headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
    if !named(&headers, "transfer-encoding").is_empty() {
        return Ok(Err(StatusCode::NOT_IMPLEMENTED));
    }
    let lengths = named(&headers, "content-length");
    let declared: usize = match lengths[..] {
        [] => 0,
        [v] if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => match v.parse() {
            Ok(n) => n,
            Err(_) => return Ok(bad),
        },
        _ => return Ok(bad),
    };
    let hosts = named(&headers, "host");
    let host = match hosts[..] {
        [] => None,
        [h] if valid_host(h) => Some(h),
        _ => return Ok(bad),
    };
    // the authority comes from Host, so a request without one has none and is refused by the router (421)
    let uri = match host {
        Some(h) => format!("http://{h}{target}"),
        None => target.to_owned(),
    };
    let Ok(uri) = uri.parse::<Uri>() else {
        return Ok(bad);
    };
    // never read more than the limit of the path the router will see (the API's 64 KiB, a mount's 4 MiB, the
    // token's 4 KiB): a larger declared length is answered 413 from the header by whoever owns the path. The
    // buffer grows with the bytes that really arrive, a liar declaring megabytes costs nothing.
    let want = declared.min(server.body_limit(uri.path()) + 1);
    let mut body = Vec::new();
    r.take(want as u64).read_to_end(&mut body).await?;
    if body.len() < want {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in &headers {
        b = b.header(k.as_str(), v.as_str());
    }
    Ok(b.body(body).map_err(|_| StatusCode::BAD_REQUEST))
}

async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response: Response<Vec<u8>>,
) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {}\r\nConnection: close\r\n", response.status());
    for (k, v) in response.headers() {
        head.push_str(&format!("{}: {}\r\n", k, v.to_str().unwrap_or("")));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(response.body()).await?;
    stream.shutdown().await
}
