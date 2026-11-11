//! The `secmonk-wire/1` envelope: one JSON object per frame, discriminated by `type`.
//! Unknown fields are ignored (minors are additive); see `rust/contracts/schemas/wire/envelope.schema.json`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{ErrorCode, WireError};

/// One message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Message {
    /// First message of each side.
    Hello(Box<Hello>),
    /// A call.
    Req(Request),
    /// A unary result.
    Res(Response),
    /// A failure.
    Err(ErrorMsg),
    /// One stream item.
    Event(Event),
    /// End of a stream.
    End(End),
    /// Advisory progress.
    Progress(Progress),
    /// Abort a request.
    Cancel(Cancel),
    /// No reply expected.
    Notify(Notify),
}

impl Message {
    /// The request id the message refers to, if any (`hello` and `notify` have none; `err` may have `null`).
    pub fn id(&self) -> Option<u64> {
        match self {
            Message::Req(m) => Some(m.id),
            Message::Res(m) => Some(m.id),
            Message::Err(m) => m.id,
            Message::Event(m) => Some(m.id),
            Message::End(m) => Some(m.id),
            Message::Progress(m) => Some(m.id),
            Message::Cancel(m) => Some(m.id),
            Message::Hello(_) | Message::Notify(_) => None,
        }
    }

    /// The `type` string.
    pub fn kind(&self) -> &'static str {
        match self {
            Message::Hello(_) => "hello",
            Message::Req(_) => "req",
            Message::Res(_) => "res",
            Message::Err(_) => "err",
            Message::Event(_) => "event",
            Message::End(_) => "end",
            Message::Progress(_) => "progress",
            Message::Cancel(_) => "cancel",
            Message::Notify(_) => "notify",
        }
    }

    /// Serialize to the frame payload.
    pub fn to_vec(&self) -> Vec<u8> {
        // A Message only holds JSON-representable data: serialization cannot fail.
        serde_json::to_vec(self).unwrap_or_else(|_| b"{}".to_vec())
    }

    /// Parse a frame payload (UTF-8 JSON object with a known `type`).
    pub fn from_slice(payload: &[u8]) -> Result<Message, WireError> {
        let text = std::str::from_utf8(payload)
            .map_err(|e| WireError::protocol(format!("invalid UTF-8: {e}")))?;
        let value: Value = serde_json::from_str(text)
            .map_err(|e| WireError::protocol(format!("invalid JSON: {e}")))?;
        let Value::Object(obj) = &value else {
            return Err(WireError::protocol("frame is not a JSON object"));
        };
        match obj.get("type").and_then(Value::as_str) {
            Some(
                "hello" | "req" | "res" | "err" | "event" | "end" | "progress" | "cancel"
                | "notify",
            ) => {}
            Some(other) => {
                return Err(WireError::protocol(format!(
                    "unknown message type {other:?}"
                )));
            }
            None => return Err(WireError::protocol("message without a type")),
        }
        for field in unknown_fields(&value) {
            tracing::debug!(field = %field, "ignoring an unknown field of a newer protocol minor");
        }
        let msg: Message = serde_json::from_value(value)
            .map_err(|e| WireError::protocol(format!("invalid message: {e}")))?;
        msg.validate()?;
        Ok(msg)
    }

    /// Checks serde cannot express: id ranges, method syntax.
    pub fn validate(&self) -> Result<(), WireError> {
        if let Some(id) = self.id()
            && !(1..=crate::MAX_ID).contains(&id)
        {
            return Err(WireError::protocol(format!("request id {id} out of range")));
        }
        match self {
            Message::Req(r) if !crate::methods::is_valid_method(&r.method) => {
                Err(WireError::protocol("invalid method name"))
            }
            Message::Req(r) if r.params.as_ref().is_some_and(|p| !p.is_object()) => {
                Err(WireError::protocol("params must be an object"))
            }
            _ => Ok(()),
        }
    }
}

/// Keys of `hello` that this version knows.
const HELLO_FIELDS: [&str; 14] = [
    "type",
    "protocol",
    "role",
    "name",
    "version",
    "runtime",
    "runtime_version",
    "pid",
    "codecs",
    "codec",
    "limits",
    "provides",
    "capabilities",
    "session",
];

/// Keys of `hello.provides` that this version knows.
const PROVIDES_FIELDS: [&str; 4] = ["collectors", "sources", "sync_all_order", "methods"];

/// The fields of a `hello` frame (top level and `provides`) this version does not know, as dotted paths
/// (`provides.tools`). They are ignored, never an error: minor versions are additive (contracts.md (a)).
/// Empty for other message types.
pub fn unknown_fields(frame: &Value) -> Vec<String> {
    let Some(obj) = frame.as_object() else {
        return Vec::new();
    };
    if obj.get("type").and_then(Value::as_str) != Some("hello") {
        return Vec::new();
    }
    let mut out: Vec<String> = obj
        .keys()
        .filter(|k| !HELLO_FIELDS.contains(&k.as_str()))
        .cloned()
        .collect();
    if let Some(p) = obj.get("provides").and_then(Value::as_object) {
        out.extend(
            p.keys()
                .filter(|k| !PROVIDES_FIELDS.contains(&k.as_str()))
                .map(|k| format!("provides.{k}")),
        );
    }
    out
}

/// Peer role in `hello`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// A module (Python or Rust).
    Module,
    /// The host (desktop app).
    Host,
    /// A remote probe (later).
    Probe,
    /// A remote engine (later).
    Engine,
    /// A UI client (later).
    Ui,
}

/// `hello.limits`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    /// Largest frame this side accepts.
    pub max_frame: u64,
    /// Concurrent requests this side serves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inflight: Option<u32>,
    /// Items per stream event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_items: Option<u32>,
}

/// A collector in `provides`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectorInfo {
    /// Name (slug).
    pub name: String,
    /// One-line description.
    pub description: String,
    /// Where it can run (absent = everywhere).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platforms: Option<Vec<String>>,
}

/// A source in `provides`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceInfo {
    /// Name (slug).
    pub name: String,
    /// One-line description.
    pub description: String,
    /// Part of `sync all`.
    pub in_all: bool,
}

/// What a module serves (`hello.provides`, `manifest.provides`). Unknown fields are ignored on the wire (minor
/// versions are additive; [`Message::from_slice`] logs them); a manifest stays strict
/// ([`crate::manifest::Manifest`] refuses unknown `provides` keys).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Provides {
    /// Collectors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collectors: Option<Vec<CollectorInfo>>,
    /// Sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<SourceInfo>>,
    /// Order of `sync all`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_all_order: Option<Vec<String>>,
    /// Methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
}

impl Provides {
    /// Methods (empty when absent).
    pub fn methods(&self) -> &[String] {
        self.methods.as_deref().unwrap_or(&[])
    }

    /// Collectors (empty when absent).
    pub fn collectors(&self) -> &[CollectorInfo] {
        self.collectors.as_deref().unwrap_or(&[])
    }

    /// Sources (empty when absent).
    pub fn sources(&self) -> &[SourceInfo] {
        self.sources.as_deref().unwrap_or(&[])
    }

    /// The first claim of `self` that `allowed` does not cover (a module may not claim more than its manifest).
    pub fn first_excess(&self, allowed: &Provides) -> Option<String> {
        for m in self.methods() {
            if !allowed.methods().contains(m) {
                return Some(format!("method {m}"));
            }
        }
        for c in self.collectors() {
            if !allowed.collectors().iter().any(|a| a.name == c.name) {
                return Some(format!("collector {}", c.name));
            }
        }
        for s in self.sources() {
            if !allowed.sources().iter().any(|a| a.name == s.name) {
                return Some(format!("source {}", s.name));
            }
        }
        None
    }
}

/// `db_read` grant: paths of the databases a module may open read-only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbReadGrant {
    /// State database file.
    pub state: String,
    /// Mirror database file.
    pub mirror: String,
    /// URI flags (`mode=ro`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_flags: Option<String>,
}

/// Grants of the host's `hello` (only `db_read` exists).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grants {
    /// Read-only database access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_read: Option<DbReadGrant>,
}

/// `hello.session` (host side).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Module name the host started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<Grants>,
    /// Settings (`min_confidence`, process monitor target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Map<String, Value>>,
}

/// `hello`. The module speaks first, the host answers; no `req` before both.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    /// `secmonk-wire/1.0`.
    pub protocol: String,
    /// Role.
    pub role: Role,
    /// Name (module name, or the host's).
    pub name: String,
    /// Version.
    pub version: String,
    /// Runtime (`python`, `rust`), modules only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Runtime version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_version: Option<String>,
    /// Process id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u64>,
    /// Codecs offered (`json`).
    pub codecs: Vec<String>,
    /// Codec chosen (host).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
    /// Limits.
    pub limits: Limits,
    /// What a module serves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provides: Option<Provides>,
    /// Declared capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    /// Host: module name, grants, settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionInfo>,
}

/// `req`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// Positive id, unique per sender and connection.
    pub id: u64,
    /// Method name.
    pub method: String,
    /// Params object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Relative deadline in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
}

/// `res`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    /// Request id.
    pub id: u64,
    /// Result (any JSON, `null` allowed).
    pub result: Value,
}

/// `err`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorMsg {
    /// Request id; `null` for connection-level errors.
    pub id: Option<u64>,
    /// Code.
    pub code: ErrorCode,
    /// Message.
    pub error: String,
    /// Hint.
    #[serde(default)]
    pub hint: Option<String>,
    /// Details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ErrorMsg {
    /// An `err` frame for `id` from a [`WireError`].
    pub fn from_error(id: Option<u64>, e: &WireError) -> ErrorMsg {
        ErrorMsg {
            id,
            code: e.code.clone(),
            error: e.error.clone(),
            hint: e.hint.clone(),
            data: e.data.as_deref().cloned(),
        }
    }

    /// The error as a [`WireError`].
    pub fn to_error(&self) -> WireError {
        let mut e = WireError::new(self.code.clone(), self.error.clone());
        e.hint = self.hint.clone();
        e.data = self.data.clone().map(Box::new);
        e
    }
}

/// `event`: one stream item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Request id.
    pub id: u64,
    /// Sequence number within the stream.
    #[serde(default)]
    pub seq: u64,
    /// The item.
    pub data: Value,
}

/// `end`: the stream finished.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct End {
    /// Request id.
    pub id: u64,
    /// Summary result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}

/// `progress`: advisory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Progress {
    /// Request id.
    pub id: u64,
    /// Line for the job log (at most 500 chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Units done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done: Option<u64>,
    /// Units in total.
    #[serde(default)]
    pub total: Option<u64>,
    /// Unit name.
    #[serde(default)]
    pub unit: Option<String>,
}

/// `cancel`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cancel {
    /// Request id to abort.
    pub id: u64,
    /// Why.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `notify`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Notify {
    /// Method (`log`).
    pub method: String,
    /// Params.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// Params of `notify log` (`wire/notify-log.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogParams {
    /// `debug`, `info`, `warning`, `error`.
    pub level: String,
    /// Message (at most 2000 chars).
    pub message: String,
    /// Logger name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logger: Option<String>,
    /// The request it belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<u64>,
}

impl Message {
    /// `err` for `id`.
    pub fn err(id: Option<u64>, code: ErrorCode, error: impl Into<String>) -> Message {
        Message::Err(ErrorMsg::from_error(id, &WireError::new(code, error)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_from_a_newer_minor_with_unknown_fields_is_accepted() {
        // regression: `Provides` was deny_unknown_fields, so an additive minor broke the hello
        let frame = serde_json::json!({
            "type": "hello", "protocol": "secmonk-wire/1.3", "role": "module", "name": "py-probe",
            "version": "0.2.0", "codecs": ["json"], "limits": {"max_frame": 65536},
            "provides": {"methods": ["collector.collect"], "tools": [{"name": "x"}]},
            "features": ["zstd"]
        });
        assert_eq!(
            unknown_fields(&frame),
            vec!["features".to_string(), "provides.tools".to_string()]
        );
        let msg = Message::from_slice(frame.to_string().as_bytes()).unwrap();
        let Message::Hello(h) = msg else {
            panic!("not a hello")
        };
        assert_eq!(h.provides.unwrap().methods(), ["collector.collect"]);
        assert!(unknown_fields(&serde_json::json!({"type": "req", "id": 1, "x": 1})).is_empty());
    }
}
