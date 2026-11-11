//! The host's `hello`: chosen codec, limits, and the session block (module name, grants, settings).
//!
//! Settings every module receives (agreed with the Python modules, W2.2): `min_confidence`, `module_dir`
//! (`<data_dir>/modules/<name>`, e.g. the py-sources staging directory) and `process = {target, options}`
//! (py-procmon). The `db_read` grant goes only to modules whose manifest declares `db-read`.

use std::path::{Path, PathBuf};

use secmonk_proto::manifest::{Capability, Manifest};
use secmonk_proto::{DbReadGrant, Grants, Hello, Limits, Role, SessionInfo};
use serde_json::{Map, Value, json};

/// Host-side inputs of the session block.
#[derive(Debug, Clone, Default)]
pub struct HostSettings {
    /// `engine.min_confidence`.
    pub min_confidence: f64,
    /// State database file (for `db_read`).
    pub state_db: Option<PathBuf>,
    /// Mirror database file (for `db_read`).
    pub mirror_db: Option<PathBuf>,
    /// Whether the config allows `db_read` grants at all.
    pub allow_db_read: bool,
    /// Process monitor target (a snapshot file or `None` for this machine).
    pub process_target: Option<String>,
    /// Process monitor options.
    pub process_options: Vec<String>,
    /// `<data_dir>/modules` (each module gets `<modules_root>/<name>`).
    pub modules_root: Option<PathBuf>,
}

/// Host name and version in `hello`.
pub const HOST_NAME: &str = "secmonk-desktop";

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// The host's `hello` for `manifest`.
pub fn host_hello(manifest: &Manifest, s: &HostSettings, max_frame: usize) -> Hello {
    let mut settings = Map::new();
    settings.insert("min_confidence".into(), json!(s.min_confidence));
    if let Some(root) = &s.modules_root {
        settings.insert(
            "module_dir".into(),
            Value::String(path_str(&root.join(&manifest.name))),
        );
    }
    settings.insert(
        "process".into(),
        json!({"target": s.process_target, "options": s.process_options}),
    );
    let db_read = match (&s.state_db, &s.mirror_db) {
        (Some(state), Some(mirror)) if s.allow_db_read && manifest.has(Capability::DbRead) => {
            Some(DbReadGrant {
                state: path_str(state),
                mirror: path_str(mirror),
                uri_flags: Some("mode=ro".into()),
            })
        }
        _ => None,
    };
    Hello {
        protocol: secmonk_proto::PROTOCOL.into(),
        role: Role::Host,
        name: HOST_NAME.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        runtime: None,
        runtime_version: None,
        pid: None,
        codecs: vec!["json".into()],
        codec: Some("json".into()),
        limits: Limits {
            max_frame: max_frame as u64,
            max_inflight: None,
            chunk_items: None,
        },
        provides: None,
        capabilities: None,
        session: Some(SessionInfo {
            module: Some(manifest.name.clone()),
            grants: Some(Grants { db_read }),
            settings: Some(settings),
        }),
    }
}
