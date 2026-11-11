//! A `secmonk-wire/1` session over any byte stream (host side).
//!
//! One reader task (frames in, dispatch by id), one writer task (frames out). Unary calls wait on a oneshot;
//! stream calls read a bounded channel, so a slow consumer stops the reader and, through the pipe, the
//! module (backpressure end to end). Dropping an unfinished call sends `cancel`. A deadline sends `cancel`,
//! then, after the grace period without an answer, calls the session's kill hook (Python threads cannot be
//! interrupted) and fails the call with `timeout`. EOF or a broken frame fails every pending call
//! (`module-crashed` / `protocol-error`) and closes the session.

use std::collections::HashMap;
use std::fmt;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_core::Stream;
use futures_util::{SinkExt, StreamExt};
use secmonk_proto::codec::MessageCodec;
use secmonk_proto::{
    Cancel, ErrorCode, ErrorMsg, Hello, LogParams, Message, Progress, Provides, Request, WireError,
    methods,
};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;

use crate::ModuleResult;

/// Items buffered per stream call before the reader waits (backpressure).
pub const STREAM_BUFFER: usize = 8;

/// Progress callback of a call.
pub type ProgressFn = Arc<dyn Fn(&Progress) + Send + Sync>;
/// Kill hook: stop the peer process (timeouts, protocol errors).
pub type KillFn = Arc<dyn Fn() + Send + Sync>;

/// One message of a stream call.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamEvent {
    /// `event.data`.
    Item(Value),
    /// `end.result`.
    End(Option<Value>),
}

enum Pending {
    Unary(oneshot::Sender<ModuleResult<Value>>),
    Stream(mpsc::Sender<ModuleResult<StreamEvent>>),
    /// The caller dropped the call and `cancel` was sent: the entry (and its permit) stays until the module's
    /// final frame arrives, the session ends or the watchdog kills the module; nobody receives the answer.
    Cancelled,
}

struct Entry {
    pending: Pending,
    progress: Option<ProgressFn>,
    /// The `max_inflight` slot of this request: freed when the entry is removed, never earlier (a module still
    /// busy with a cancelled request is still busy).
    _permit: OwnedSemaphorePermit,
}

/// Per-session settings.
#[derive(Clone)]
pub struct SessionConfig {
    /// Module name (logs, errors).
    pub name: String,
    /// Frame limit in force (after negotiation).
    pub max_frame: usize,
    /// Concurrent requests.
    pub max_inflight: u32,
    /// Default deadline of a call.
    pub request_timeout: Duration,
    /// Wait after `cancel` before the kill.
    pub cancel_grace: Duration,
    /// Called to stop the peer (child kill); `None` for transports without a process.
    pub kill: Option<KillFn>,
}

impl fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionConfig")
            .field("name", &self.name)
            .field("max_frame", &self.max_frame)
            .field("max_inflight", &self.max_inflight)
            .field("request_timeout", &self.request_timeout)
            .field("cancel_grace", &self.cancel_grace)
            .finish()
    }
}

/// Options of one call.
#[derive(Clone, Default)]
pub struct CallOptions {
    /// Deadline (default: the session's request timeout).
    pub deadline: Option<Duration>,
    /// Progress callback.
    pub progress: Option<ProgressFn>,
}

impl fmt::Debug for CallOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallOptions")
            .field("deadline", &self.deadline)
            .finish()
    }
}

struct Inner {
    cfg: SessionConfig,
    peer: Hello,
    out: mpsc::UnboundedSender<Message>,
    pending: Mutex<HashMap<u64, Entry>>,
    next_id: AtomicU64,
    closed: AtomicBool,
    close_reason: Mutex<Option<WireError>>,
    inflight: Arc<Semaphore>,
    /// When a request last started or finished (the supervisor's idle timer).
    last_activity: Mutex<Instant>,
    /// Stops the writer task (which drops the peer's input) when the session ends.
    stop: CancellationToken,
}

/// A connected session. Cheap to clone; the tasks stop when the stream ends or [`Session::close`] is called.
#[derive(Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("module", &self.inner.cfg.name)
            .field("closed", &self.is_closed())
            .finish()
    }
}

/// What the handshake checks the module's `hello` against.
#[derive(Debug, Clone)]
pub struct HandshakeOptions {
    /// Expected module name.
    pub name: String,
    /// What the manifest allows (a module may not claim more).
    pub allowed: Provides,
    /// The host's `hello` (session grants and settings).
    pub host_hello: Hello,
    /// Time to wait for the module's `hello`.
    pub hello_timeout: Duration,
}

impl Session {
    /// Run the handshake (module speaks first, the host answers) and start the tasks.
    pub async fn connect<R, W>(
        reader: R,
        writer: W,
        hs: HandshakeOptions,
        mut cfg: SessionConfig,
    ) -> ModuleResult<Session>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let our_max = cfg.max_frame;
        let mut frames_in = FramedRead::new(reader, MessageCodec::new(our_max));
        let mut frames_out = FramedWrite::new(writer, MessageCodec::new(our_max));
        let unavailable =
            |m: String| WireError::new(ErrorCode::ModuleUnavailable, format!("{}: {m}", hs.name));
        let first = tokio::time::timeout(hs.hello_timeout, frames_in.next())
            .await
            .map_err(|_| unavailable(format!("no hello within {:?}", hs.hello_timeout)))?;
        let peer = match first {
            Some(Ok(Message::Hello(h))) => *h,
            Some(Ok(other)) => {
                return Err(unavailable(format!("expected hello, got {}", other.kind())));
            }
            Some(Err(e)) => return Err(unavailable(e.to_string())),
            None => return Err(unavailable("exited before hello".into())),
        };
        if !secmonk_proto::protocol_compatible(&peer.protocol) {
            return Err(unavailable(format!(
                "unsupported protocol {:?}",
                peer.protocol
            )));
        }
        if peer.name != hs.name {
            return Err(unavailable(format!("hello names module {:?}", peer.name)));
        }
        if !peer.codecs.iter().any(|c| c == "json") {
            return Err(unavailable("no common codec".into()));
        }
        if let Some(p) = &peer.provides
            && let Some(extra) = p.first_excess(&hs.allowed)
        {
            return Err(unavailable(format!(
                "claims {extra}, which its manifest does not provide"
            )));
        }
        let max = secmonk_proto::negotiated_max_frame(our_max, peer.limits.max_frame as usize);
        cfg.max_frame = max;
        frames_in.decoder_mut().set_max_frame(max);
        frames_out.encoder_mut().set_max_frame(max);
        let mut host = hs.host_hello.clone();
        host.limits.max_frame = max as u64;
        frames_out
            .send(Message::Hello(Box::new(host)))
            .await
            .map_err(|e| unavailable(format!("cannot send hello: {e}")))?;

        let inflight = cfg
            .max_inflight
            .min(peer.limits.max_inflight.unwrap_or(cfg.max_inflight))
            .max(1);
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let inner = Arc::new(Inner {
            cfg,
            peer,
            out: tx,
            pending: Mutex::new(HashMap::new()),
            last_activity: Mutex::new(Instant::now()),
            next_id: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            close_reason: Mutex::new(None),
            inflight: Arc::new(Semaphore::new(inflight as usize)),
            stop: CancellationToken::new(),
        });
        // writer task
        let w_inner = Arc::downgrade(&inner);
        let stop = inner.stop.clone();
        tokio::spawn(async move {
            loop {
                let m = tokio::select! {
                    biased;
                    () = stop.cancelled() => {
                        // flush what was queued before the session ended (a protocol `err` frame), best effort
                        while let Ok(m) = rx.try_recv() {
                            if tokio::time::timeout(Duration::from_millis(200), frames_out.send(&m)).await.is_err() {
                                break;
                            }
                        }
                        break;
                    }
                    m = rx.recv() => match m {
                        Some(m) => m,
                        None => break,
                    },
                };
                if let Err(e) = frames_out.send(&m).await {
                    if let Some(i) = w_inner.upgrade() {
                        i.fail_all(WireError::new(
                            ErrorCode::ModuleCrashed,
                            format!("{}: write failed: {e}", i.cfg.name),
                        ));
                    }
                    break;
                }
            }
            // dropping frames_out closes the peer's stdin: a module exits on EOF
        });
        // reader task
        let r_inner = inner.clone();
        tokio::spawn(async move {
            let reason = loop {
                match frames_in.next().await {
                    Some(Ok(m)) => {
                        if let Some(err) = r_inner.dispatch(m).await {
                            break err;
                        }
                    }
                    Some(Err(e)) => {
                        let w = e.to_wire();
                        let _ = r_inner
                            .out
                            .send(Message::Err(ErrorMsg::from_error(None, &w)));
                        break WireError::new(
                            ErrorCode::ProtocolError,
                            format!("{}: {}", r_inner.cfg.name, w.error),
                        );
                    }
                    None => {
                        break WireError::new(
                            ErrorCode::ModuleCrashed,
                            format!("{} exited", r_inner.cfg.name),
                        );
                    }
                }
            };
            if reason.code == ErrorCode::ProtocolError
                && let Some(k) = &r_inner.cfg.kill
            {
                k();
            }
            r_inner.fail_all(reason);
        });
        Ok(Session { inner })
    }

    /// The module's `hello`.
    pub fn peer(&self) -> &Hello {
        &self.inner.peer
    }

    /// Module name.
    pub fn name(&self) -> &str {
        &self.inner.cfg.name
    }

    /// Whether the session ended (peer exited, protocol error, closed).
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// Why it closed.
    pub fn close_reason(&self) -> Option<WireError> {
        self.inner.close_reason.lock().unwrap().clone()
    }

    /// Number of calls waiting for an answer.
    pub fn pending(&self) -> usize {
        self.inner.pending.lock().unwrap().len()
    }

    /// When a request last started or finished.
    pub fn last_activity(&self) -> Instant {
        *self.inner.last_activity.lock().unwrap()
    }

    /// Close: fail pending calls with `cancelled`; the writer ends, which closes the peer's input.
    pub fn close(&self) {
        self.inner.fail_all(WireError::cancelled(format!(
            "{}: session closed",
            self.inner.cfg.name
        )));
    }

    /// Send a `notify`.
    pub fn notify(&self, method: &str, params: Option<Value>) -> ModuleResult<()> {
        self.inner.send(Message::Notify(secmonk_proto::Notify {
            method: method.into(),
            params,
        }))
    }

    async fn start(
        &self,
        method: &str,
        params: Value,
        opts: &CallOptions,
        pending: Pending,
    ) -> ModuleResult<u64> {
        if self.is_closed() {
            return Err(self.closed_error());
        }
        if !methods::is_valid_method(method) {
            return Err(WireError::invalid_params(format!(
                "invalid method name {method:?}"
            )));
        }
        if !params.is_object() {
            return Err(WireError::invalid_params("params must be a JSON object"));
        }
        let permit = self
            .inner
            .inflight
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| self.closed_error())?;
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        let deadline = opts.deadline.unwrap_or(self.inner.cfg.request_timeout);
        self.inner.pending.lock().unwrap().insert(
            id,
            Entry {
                pending,
                progress: opts.progress.clone(),
                _permit: permit,
            },
        );
        self.inner.touch();
        let req = Request {
            id,
            method: method.into(),
            params: Some(params),
            deadline_ms: Some(deadline.as_millis().min(u64::MAX as u128) as u64),
        };
        if let Err(e) = self.inner.send(Message::Req(req)) {
            self.inner.pending.lock().unwrap().remove(&id);
            return Err(e);
        }
        self.spawn_watchdog(id, deadline);
        Ok(id)
    }

    /// After `deadline`: `cancel`; after the grace without an answer: kill and fail with `timeout`.
    fn spawn_watchdog(&self, id: u64, deadline: Duration) {
        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            tokio::time::sleep(deadline).await;
            let Some(inner) = weak.upgrade() else { return };
            if !inner.pending.lock().unwrap().contains_key(&id) {
                return;
            }
            let _ = inner.send(Message::Cancel(Cancel {
                id,
                reason: Some("deadline passed".into()),
            }));
            drop(inner);
            Inner::kill_if_unanswered(weak, id).await;
        });
    }

    /// A unary call. Dropping the future sends `cancel`.
    pub async fn call(
        &self,
        method: &str,
        params: Value,
        opts: CallOptions,
    ) -> ModuleResult<Value> {
        let (tx, rx) = oneshot::channel();
        let id = self
            .start(method, params, &opts, Pending::Unary(tx))
            .await?;
        let guard = CancelGuard {
            inner: Some(self.inner.clone()),
            id,
        };
        let deadline = opts.deadline.unwrap_or(self.inner.cfg.request_timeout);
        let res = rx.await.unwrap_or_else(|_| Err(self.closed_error()));
        guard.disarm();
        // a `cancelled` answer to our deadline cancel is a timeout for the caller
        res.map_err(|e| {
            if e.code == ErrorCode::Cancelled && !self.is_closed() {
                WireError::new(
                    ErrorCode::Timeout,
                    format!("{}: {method} exceeded {deadline:?}", self.name()),
                )
            } else {
                e
            }
        })
    }

    /// A stream call: `Item`s then one `End`. Dropping the stream before `End` sends `cancel`.
    pub async fn call_stream(
        &self,
        method: &str,
        params: Value,
        opts: CallOptions,
    ) -> ModuleResult<CallStream> {
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        let id = self
            .start(method, params, &opts, Pending::Stream(tx))
            .await?;
        Ok(CallStream {
            rx,
            guard: Some(CancelGuard {
                inner: Some(self.inner.clone()),
                id,
            }),
            done: false,
        })
    }

    fn closed_error(&self) -> WireError {
        self.close_reason().unwrap_or_else(|| {
            WireError::new(
                ErrorCode::ModuleCrashed,
                format!("{}: session closed", self.name()),
            )
        })
    }
}

impl Inner {
    fn send(&self, m: Message) -> ModuleResult<()> {
        self.out.send(m).map_err(|_| {
            self.close_reason
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| {
                    WireError::new(
                        ErrorCode::ModuleCrashed,
                        format!("{}: session closed", self.cfg.name),
                    )
                })
        })
    }

    fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    /// Remove the entry of a finished request: its slot is freed here, before the answer is delivered (a caller
    /// that reacts to the answer with the next call must find the slot free).
    fn finish(&self, id: u64) -> Option<Pending> {
        let e = self.pending.lock().unwrap().remove(&id)?;
        self.touch();
        Some(e.pending) // the entry's permit drops here
    }

    /// After the cancel grace: when the module still has not answered request `id`, kill it and fail the session.
    async fn kill_if_unanswered(weak: std::sync::Weak<Inner>, id: u64) {
        let Some(grace) = weak.upgrade().map(|i| i.cfg.cancel_grace) else {
            return;
        };
        tokio::time::sleep(grace).await;
        let Some(inner) = weak.upgrade() else { return };
        let entry = inner.pending.lock().unwrap().remove(&id);
        if let Some(e) = entry {
            tracing::warn!(module = %inner.cfg.name, id, "no answer after cancel: killing the module");
            let err = WireError::new(
                ErrorCode::Timeout,
                format!("{}: request {id} timed out", inner.cfg.name),
            );
            // kill and close first: delivering into a full stream channel must never delay the kill
            if let Some(k) = &inner.cfg.kill {
                k();
            }
            inner.fail_all(WireError::new(
                ErrorCode::Timeout,
                format!("{}: killed after a timeout", inner.cfg.name),
            ));
            Inner::deliver_now(e.pending, Err(err));
        }
    }

    /// Non-blocking delivery (a full stream buffer drops the error: the stream then ends with `module-crashed`).
    fn deliver_now(p: Pending, r: ModuleResult<Value>) {
        match p {
            Pending::Unary(tx) => {
                let _ = tx.send(r);
            }
            Pending::Stream(tx) => {
                let _ = tx.try_send(r.map(|v| StreamEvent::End(Some(v))));
            }
            Pending::Cancelled => {}
        }
    }

    async fn deliver(p: Pending, r: ModuleResult<Value>) {
        match p {
            Pending::Unary(tx) => {
                let _ = tx.send(r);
            }
            Pending::Stream(tx) => {
                let _ = tx.send(r.map(|v| StreamEvent::End(Some(v)))).await;
            }
            Pending::Cancelled => {}
        }
    }

    /// Handle one incoming message; `Some(reason)` ends the session.
    async fn dispatch(&self, m: Message) -> Option<WireError> {
        match m {
            Message::Res(r) => {
                let e = self.finish(r.id);
                if let Some(p) = e {
                    match p {
                        Pending::Unary(tx) => {
                            let _ = tx.send(Ok(r.result));
                        }
                        Pending::Stream(tx) => {
                            let _ = tx.send(Ok(StreamEvent::End(Some(r.result)))).await;
                        }
                        Pending::Cancelled => {}
                    }
                }
            }
            Message::Err(er) => {
                let Some(id) = er.id else {
                    return Some(WireError::new(
                        ErrorCode::ProtocolError,
                        format!("{} reported a protocol error: {}", self.cfg.name, er.error),
                    ));
                };
                let e = self.finish(id);
                if let Some(p) = e {
                    Inner::deliver(p, Err(er.to_error())).await;
                }
            }
            Message::Event(ev) => {
                let tx = match self.pending.lock().unwrap().get(&ev.id) {
                    Some(Entry {
                        pending: Pending::Stream(tx),
                        ..
                    }) => Some(tx.clone()),
                    Some(Entry {
                        pending: Pending::Cancelled,
                        ..
                    }) => None, // late events of a cancelled request are dropped
                    Some(_) => {
                        return Some(WireError::protocol(format!(
                            "{}: event for a unary request",
                            self.cfg.name
                        )));
                    }
                    None => None,
                };
                if let Some(tx) = tx {
                    // bounded: waits when the consumer is slow (backpressure)
                    let _ = tx.send(Ok(StreamEvent::Item(ev.data))).await;
                }
            }
            Message::End(end) => {
                let e = self.finish(end.id);
                if let Some(pending) = e {
                    match pending {
                        Pending::Stream(tx) => {
                            let _ = tx.send(Ok(StreamEvent::End(end.result))).await;
                        }
                        Pending::Unary(tx) => {
                            let _ = tx.send(Ok(end.result.unwrap_or(Value::Null)));
                        }
                        Pending::Cancelled => {}
                    }
                }
            }
            Message::Progress(p) => {
                let cb = self
                    .pending
                    .lock()
                    .unwrap()
                    .get(&p.id)
                    .and_then(|e| e.progress.clone());
                if let Some(cb) = cb {
                    cb(&p);
                }
            }
            Message::Notify(n) => {
                if n.method == methods::NOTIFY_LOG
                    && let Some(params) = n.params
                    && let Ok(log) = serde_json::from_value::<LogParams>(params)
                {
                    log_line(&self.cfg.name, &log);
                }
            }
            Message::Req(r) => {
                // The host serves no methods in the prototype.
                let _ = self.send(Message::err(
                    Some(r.id),
                    ErrorCode::UnknownMethod,
                    format!("the host serves no method {:?}", r.method),
                ));
            }
            Message::Cancel(_) => {}
            Message::Hello(_) => {
                return Some(WireError::protocol(format!(
                    "{}: second hello",
                    self.cfg.name
                )));
            }
        }
        None
    }

    fn fail_all(&self, reason: WireError) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        *self.close_reason.lock().unwrap() = Some(reason.clone());
        self.stop.cancel();
        self.inflight.close();
        let all: Vec<Entry> = self
            .pending
            .lock()
            .unwrap()
            .drain()
            .map(|(_, e)| e)
            .collect();
        for e in all {
            match e.pending {
                Pending::Unary(tx) => {
                    let _ = tx.send(Err(reason.clone()));
                }
                Pending::Stream(tx) => {
                    let _ = tx.try_send(Err(reason.clone()));
                }
                Pending::Cancelled => {}
            }
        }
    }
}

/// A module log line to `tracing` (target `module`), scrubbed.
fn log_line(module: &str, log: &LogParams) {
    let msg = secmonk_safeio::scrub_text(&log.message);
    let logger = log.logger.as_deref().unwrap_or("");
    match log.level.as_str() {
        "error" => {
            tracing::error!(target: "module", module, logger, request = log.request, "{msg}")
        }
        "warning" => {
            tracing::warn!(target: "module", module, logger, request = log.request, "{msg}")
        }
        "debug" => {
            tracing::debug!(target: "module", module, logger, request = log.request, "{msg}")
        }
        _ => tracing::info!(target: "module", module, logger, request = log.request, "{msg}"),
    }
}

/// Sends `cancel` when a call is dropped before its answer.
struct CancelGuard {
    inner: Option<Arc<Inner>>,
    id: u64,
}

impl CancelGuard {
    fn disarm(mut self) {
        self.inner = None;
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        if inner.closed.load(Ordering::SeqCst) {
            return;
        }
        // Keep the entry, and with it the permit, until the module's final frame: a module still busy with the
        // cancelled request cannot take another one beyond `max_inflight`, and the watchdog can still kill it.
        let marked = {
            let mut map = inner.pending.lock().unwrap();
            match map.get_mut(&self.id) {
                Some(e) if !matches!(e.pending, Pending::Cancelled) => {
                    e.pending = Pending::Cancelled;
                    e.progress = None;
                    true
                }
                _ => false,
            }
        };
        if marked {
            let _ = inner.out.send(Message::Cancel(Cancel {
                id: self.id,
                reason: Some("caller dropped the call".into()),
            }));
            if tokio::runtime::Handle::try_current().is_ok() {
                let weak = Arc::downgrade(&inner);
                let id = self.id;
                tokio::spawn(Inner::kill_if_unanswered(weak, id));
            }
        }
    }
}

/// The stream of a [`Session::call_stream`]. Ends after `End` or an error.
pub struct CallStream {
    rx: mpsc::Receiver<ModuleResult<StreamEvent>>,
    guard: Option<CancelGuard>,
    done: bool,
}

impl fmt::Debug for CallStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallStream")
            .field("done", &self.done)
            .finish()
    }
}

impl Stream for CallStream {
    type Item = ModuleResult<StreamEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(item)) => {
                if matches!(item, Ok(StreamEvent::End(_)) | Err(_)) {
                    self.done = true;
                    if let Some(g) = self.guard.take() {
                        g.disarm();
                    }
                }
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(Some(Err(WireError::new(
                    ErrorCode::ModuleCrashed,
                    "stream ended without end",
                ))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
