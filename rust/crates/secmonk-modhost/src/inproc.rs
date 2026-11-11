//! In-process serialized transport: a Rust [`RustModule`] served over `tokio::io::duplex` with the same
//! framing and session code as a child process. Used by conformance tests (every method through both
//! bindings, JSON compared) and as the binding of Rust ports that should still look like modules.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use secmonk_proto::codec::MessageCodec;
use secmonk_proto::{
    ErrorCode, ErrorMsg, Event, Hello, Limits, Manifest, Message, Response, Role, WireError,
    methods,
};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::ModuleResult;
use crate::hello::HostSettings;
use crate::registry::ModuleEntry;
use crate::session::Session;
use crate::supervisor::{ModuleHandle, Running, Starter, session_params};

/// Sends `event` frames of one request.
#[derive(Debug, Clone)]
pub struct EventSink {
    id: u64,
    seq: Arc<std::sync::atomic::AtomicU64>,
    out: mpsc::UnboundedSender<Message>,
}

impl EventSink {
    /// Emit one stream item.
    pub fn emit(&self, data: Value) -> ModuleResult<()> {
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.out
            .send(Message::Event(Event {
                id: self.id,
                seq,
                data,
            }))
            .map_err(|_| WireError::new(ErrorCode::Cancelled, "connection closed"))
    }
}

/// A module implemented in Rust.
#[async_trait]
pub trait RustModule: Send + Sync + 'static {
    /// Its manifest (`runtime = "rust"`).
    fn manifest(&self) -> &Manifest;

    /// Serve one request. Stream methods emit items through `sink` and return the `end` result; unary
    /// methods return the `res` result. Cancellation aborts the task.
    async fn handle(&self, method: &str, params: Value, sink: EventSink) -> ModuleResult<Value>;
}

/// Serve `module` on a byte stream until EOF.
pub async fn serve<R, W>(module: Arc<dyn RustModule>, reader: R, writer: W)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let m = module.manifest().clone();
    let mut rd = FramedRead::new(reader, MessageCodec::default());
    let mut wr = FramedWrite::new(writer, MessageCodec::default());
    let hello = Hello {
        protocol: secmonk_proto::PROTOCOL.into(),
        role: Role::Module,
        name: m.name.clone(),
        version: m.version.clone(),
        runtime: Some("rust".into()),
        runtime_version: None,
        pid: Some(u64::from(std::process::id())),
        codecs: vec!["json".into()],
        codec: None,
        limits: Limits {
            max_frame: secmonk_proto::DEFAULT_MAX_FRAME as u64,
            max_inflight: Some(16),
            chunk_items: None,
        },
        provides: Some(m.provides.clone()),
        capabilities: Some(
            m.capabilities
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
        ),
        session: None,
    };
    if wr.send(Message::Hello(Box::new(hello))).await.is_err() {
        return;
    }
    match rd.next().await {
        Some(Ok(Message::Hello(_))) => {}
        _ => return,
    }
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if wr.send(&msg).await.is_err() {
                break;
            }
        }
    });
    let tasks: Arc<Mutex<HashMap<u64, tokio::task::AbortHandle>>> = Default::default();
    while let Some(frame) = rd.next().await {
        let Ok(msg) = frame else {
            let _ = tx.send(Message::err(None, ErrorCode::ProtocolError, "bad frame"));
            break;
        };
        match msg {
            Message::Req(r) => {
                let module = module.clone();
                let out = tx.clone();
                let tasks2 = tasks.clone();
                let id = r.id;
                let stream = methods::STREAM_METHODS.contains(&r.method.as_str());
                let served = module.manifest().provides.methods().contains(&r.method);
                let h = tokio::spawn(async move {
                    let reply = if !served {
                        Message::err(
                            Some(id),
                            ErrorCode::UnknownMethod,
                            format!("unknown method {:?}", r.method),
                        )
                    } else {
                        let sink = EventSink {
                            id,
                            seq: Default::default(),
                            out: out.clone(),
                        };
                        match module
                            .handle(&r.method, r.params.unwrap_or(Value::Null), sink)
                            .await
                        {
                            Ok(v) if stream => Message::End(secmonk_proto::End {
                                id,
                                result: Some(v),
                            }),
                            Ok(v) => Message::Res(Response { id, result: v }),
                            Err(e) => Message::Err(ErrorMsg::from_error(Some(id), &e)),
                        }
                    };
                    let _ = out.send(reply);
                    tasks2.lock().unwrap().remove(&id);
                });
                tasks.lock().unwrap().insert(id, h.abort_handle());
            }
            Message::Cancel(c) => {
                if let Some(h) = tasks.lock().unwrap().remove(&c.id) {
                    h.abort();
                    let _ = tx.send(Message::err(
                        Some(c.id),
                        ErrorCode::Cancelled,
                        format!("request {} cancelled", c.id),
                    ));
                }
            }
            _ => {}
        }
    }
    for (_, h) in tasks.lock().unwrap().drain() {
        h.abort();
    }
    drop(tx);
    let _ = writer_task.await;
}

/// Connect a session to `module` over an in-memory duplex stream.
pub async fn connect(
    module: Arc<dyn RustModule>,
    entry: &ModuleEntry,
    settings: &HostSettings,
) -> ModuleResult<Session> {
    let (host_side, module_side) = tokio::io::duplex(256 * 1024);
    let (mr, mw) = tokio::io::split(module_side);
    tokio::spawn(serve(module, mr, mw));
    let (hr, hw) = tokio::io::split(host_side);
    let (hs, cfg) = session_params(entry, settings);
    Session::connect(hr, hw, hs, cfg).await
}

/// A supervised handle serving `module` in process.
pub fn handle(
    module: Arc<dyn RustModule>,
    entry: &ModuleEntry,
    settings: HostSettings,
) -> ModuleHandle {
    let entry2 = entry.clone();
    let starter: Starter = Arc::new(move || {
        let module = module.clone();
        let entry = entry2.clone();
        let settings = settings.clone();
        Box::pin(async move {
            Ok(Running {
                session: connect(module, &entry, &settings).await?,
                child: None,
            })
        })
    });
    ModuleHandle::new(entry, starter)
}
