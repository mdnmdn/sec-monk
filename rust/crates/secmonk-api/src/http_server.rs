//! HTTP/1.1 binding of the [`Server`] (and so of the router): one request per connection, `Connection: close`,
//! over plain TCP (the Linux headless build, tests, the optional dev binding `[ui] http_listen`) or TLS (server
//! mode). It builds the request URI from the `Host` header, so the router's Host rules apply exactly as on the
//! Python server.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::{ApiError, Router, Server};
use http::{Method, Request, Response};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;

const MAX_HEAD: usize = 64 * 1024;

/// How long a client may take to send its request (head and body together); a slow or silent one is dropped.
/// With TLS the handshake counts too.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a client may take to receive the response; a peer that stops reading is dropped.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Connections served at once; further ones wait in the accept backlog (a loopback server has no use for more).
pub const MAX_CONNECTIONS: usize = 64;

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
    pub max_connections: usize,
}

impl ServerOptions {
    /// The defaults ([`READ_TIMEOUT`], [`MAX_CONNECTIONS`]) for `listen`, plain HTTP.
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            tls: None,
            read_timeout: READ_TIMEOUT,
            max_connections: MAX_CONNECTIONS,
        }
    }
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

/// Listen as `opts` say and answer every connection with `server`. `on_bound` gets the real address (port 0
/// works). Certificate problems are reported before anything is bound.
pub async fn serve(
    server: Arc<Server>,
    opts: ServerOptions,
    on_bound: impl FnOnce(SocketAddr),
) -> io::Result<()> {
    let acceptor = opts.tls.as_ref().map(tls_acceptor).transpose()?;
    let listener = bind(opts.listen, on_bound).await?;
    accept_loop(
        server,
        listener,
        acceptor,
        opts.read_timeout,
        opts.max_connections,
    )
    .await
}

/// Listen on `addr` and answer every connection with `router` (no authentication, plain HTTP, loopback use).
/// `on_bound` gets the real address (port 0 works).
pub async fn serve_http(
    router: Arc<Router>,
    addr: SocketAddr,
    on_bound: impl FnOnce(SocketAddr),
) -> io::Result<()> {
    serve_http_with(router, addr, READ_TIMEOUT, on_bound).await
}

/// [`serve_http`] with another request read timeout (tests).
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

/// The accept loop over an existing listener, router only, plain HTTP.
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

/// The accept loop: an accept error (out of file descriptors, a connection reset before accept) is logged and the
/// loop goes on after a short pause; it never ends the server. At most `max_connections` are served at once.
/// A failed TLS handshake only drops that connection.
pub async fn accept_loop(
    server: Arc<Server>,
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    read_timeout: Duration,
    max_connections: usize,
) -> io::Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(max_connections));
    let mut failures = 0u32;
    loop {
        // take the slot before accepting: past the limit the kernel queues new connections
        let Ok(permit) = slots.clone().acquire_owned().await else {
            return Ok(());
        };
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => {
                failures = 0;
                pair
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                let pause = Duration::from_millis(50u64 << failures.min(6));
                tracing::warn!("accept failed: {e}; retrying in {pause:?}");
                tokio::time::sleep(pause).await;
                continue;
            }
        };
        let server = server.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            match tls {
                None => {
                    let _ = connection(&server, stream, Some(peer), read_timeout).await;
                }
                Some(acceptor) => {
                    // the handshake shares the read deadline: a client that stalls in it is dropped
                    if let Ok(Ok(tls_stream)) =
                        tokio::time::timeout(read_timeout, acceptor.accept(stream)).await
                    {
                        let _ = connection(&server, tls_stream, Some(peer), read_timeout).await;
                    }
                }
            }
            drop(permit);
        });
    }
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
    let Some(request) = read? else {
        let r = bad_request();
        return write_timed(reader.get_mut(), r).await;
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

fn bad_request() -> Response<Vec<u8>> {
    crate::router::error_response(&ApiError::bad_request("bad request"))
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

async fn read_request<S: AsyncRead + Unpin>(
    r: &mut BufReader<S>,
    server: &Server,
) -> io::Result<Option<Request<Vec<u8>>>> {
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
    // never read more than the path's limit (the API's 64 KiB, a mount's 4 MiB, the token's 4 KiB): a larger
    // declared length is answered 413 from the header by whoever owns the path. The buffer grows with the bytes
    // that really arrive, a liar declaring megabytes costs nothing.
    let path = target.split(['?', '#']).next().unwrap_or("");
    let want = declared.min(server.body_limit(path) + 1);
    let mut body = Vec::new();
    r.take(want as u64).read_to_end(&mut body).await?;
    if body.len() < want {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(b.body(body).ok())
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
