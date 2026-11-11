//! The module manifest (`secmonk-module/1`): JSON in `rust/contracts/examples/module/`, TOML on disk in
//! `rust/python/modules/<name>.toml`, compiled in for Rust modules. Schema: `module/manifest.schema.json`.

use serde::{Deserialize, Serialize};

use crate::message::Provides;

/// Value of `manifest.schema`.
pub const MANIFEST_SCHEMA: &str = "secmonk-module/1";

/// Module kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleKind {
    /// Reads targets.
    Probe,
    /// Vulnerability feed.
    Source,
    /// classify / match / reports.
    Engine,
    /// Anything else.
    Tool,
}

/// Where the module runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleRuntime {
    /// Child process over stdio.
    Python,
    /// In-process.
    Rust,
}

/// Declared capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// Reads scanned targets.
    ReadTarget,
    /// Runs fixed commands.
    RunCommands,
    /// Uses the network.
    Network,
    /// May get the read-only database grant.
    DbRead,
    /// Reads this machine.
    LocalSystem,
    /// Keeps state between calls.
    Stateful,
    /// Writes its staging database.
    WritesStaging,
}

impl Capability {
    /// Wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::ReadTarget => "read-target",
            Capability::RunCommands => "run-commands",
            Capability::Network => "network",
            Capability::DbRead => "db-read",
            Capability::LocalSystem => "local-system",
            Capability::Stateful => "stateful",
            Capability::WritesStaging => "writes-staging",
        }
    }
}

/// Platform name in manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// macOS.
    Macos,
    /// Linux.
    Linux,
    /// Windows.
    Windows,
}

impl Platform {
    /// The platform this binary runs on, if it is one of the three.
    pub fn current() -> Option<Platform> {
        match std::env::consts::OS {
            "macos" => Some(Platform::Macos),
            "linux" => Some(Platform::Linux),
            "windows" => Some(Platform::Windows),
            _ => None,
        }
    }
}

/// `python` section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonSpec {
    /// uv project directory (relative to the config file, `python`).
    pub project: String,
    /// venv name under `venvs/`.
    pub env: String,
    /// Interpreter arguments (`-I -m secmonk_modules serve --stdio --module <name>`).
    pub entry: Vec<String>,
    /// PEP 440 specifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_python: Option<String>,
}

/// `rust` section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RustSpec {
    /// Crate implementing it.
    #[serde(rename = "crate")]
    pub krate: String,
    /// Factory function name.
    pub factory: String,
}

/// Start policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StartPolicy {
    /// On first use.
    #[default]
    Lazy,
    /// At app start.
    Eager,
}

/// `lifecycle` section (all optional; defaults in [`Lifecycle::resolved`]).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    /// Start policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<StartPolicy>,
    /// Stop after this idle time (0 = never).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_s: Option<u64>,
    /// Restarts allowed per window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_restarts: Option<u32>,
    /// Restart window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_window_s: Option<u64>,
}

/// `limits` section (all optional; defaults in [`ModuleLimits::resolved`]).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLimits {
    /// `hello` timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hello_timeout_s: Option<u64>,
    /// Default request deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_s: Option<u64>,
    /// Grace after `cancel` before the kill.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_grace_s: Option<u64>,
    /// Frame limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_frame: Option<u64>,
    /// Concurrent requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inflight: Option<u32>,
    /// Memory limit (advisory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u64>,
}

/// Effective limits after defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveLimits {
    /// `hello` timeout (default 20 s).
    pub hello_timeout_s: u64,
    /// Request deadline (default 600 s).
    pub request_timeout_s: u64,
    /// Cancel grace (default 5 s).
    pub cancel_grace_s: u64,
    /// Frame limit (default 16 MiB, at most 64 MiB).
    pub max_frame: usize,
    /// Concurrent requests (default 4).
    pub max_inflight: u32,
}

impl ModuleLimits {
    /// Fill defaults and clamp.
    pub fn resolved(&self) -> EffectiveLimits {
        EffectiveLimits {
            hello_timeout_s: self.hello_timeout_s.unwrap_or(20).max(1),
            request_timeout_s: self.request_timeout_s.unwrap_or(600).max(1),
            cancel_grace_s: self.cancel_grace_s.unwrap_or(5),
            max_frame: self
                .max_frame
                .map(|v| v as usize)
                .unwrap_or(crate::DEFAULT_MAX_FRAME)
                .clamp(crate::MIN_MAX_FRAME, crate::HARD_MAX_FRAME),
            max_inflight: self.max_inflight.unwrap_or(4).clamp(1, 64),
        }
    }

    /// Overlay `over` (config `[modules.<name>]`) on `self`.
    pub fn overlay(&self, over: &ModuleLimits) -> ModuleLimits {
        ModuleLimits {
            hello_timeout_s: over.hello_timeout_s.or(self.hello_timeout_s),
            request_timeout_s: over.request_timeout_s.or(self.request_timeout_s),
            cancel_grace_s: over.cancel_grace_s.or(self.cancel_grace_s),
            max_frame: over.max_frame.or(self.max_frame),
            max_inflight: over.max_inflight.or(self.max_inflight),
            memory_mb: over.memory_mb.or(self.memory_mb),
        }
    }
}

/// Effective lifecycle after defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveLifecycle {
    /// Start policy (default lazy).
    pub start: StartPolicy,
    /// Idle timeout, 0 = never (default 0).
    pub idle_timeout_s: u64,
    /// Restarts per window (default 3).
    pub max_restarts: u32,
    /// Window (default 60 s).
    pub restart_window_s: u64,
}

impl Lifecycle {
    /// Fill defaults.
    pub fn resolved(&self) -> EffectiveLifecycle {
        EffectiveLifecycle {
            start: self.start.unwrap_or_default(),
            idle_timeout_s: self.idle_timeout_s.unwrap_or(0),
            max_restarts: self.max_restarts.unwrap_or(3),
            restart_window_s: self.restart_window_s.unwrap_or(60).max(1),
        }
    }

    /// Overlay `over` (config `[modules.<name>]`) on `self`.
    pub fn overlay(&self, over: &Lifecycle) -> Lifecycle {
        Lifecycle {
            start: over.start.or(self.start),
            idle_timeout_s: over.idle_timeout_s.or(self.idle_timeout_s),
            max_restarts: over.max_restarts.or(self.max_restarts),
            restart_window_s: over.restart_window_s.or(self.restart_window_s),
        }
    }
}

/// `integrity` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Integrity {
    /// sha256 of the project's `uv.lock`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_sha256: Option<String>,
    /// sha256 of the module sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_sha256: Option<String>,
}

/// A module manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// `secmonk-module/1`.
    pub schema: String,
    /// Slug, unique in the registry.
    pub name: String,
    /// Version.
    pub version: String,
    /// Description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Kind.
    pub kind: ModuleKind,
    /// Runtime.
    pub runtime: ModuleRuntime,
    /// `secmonk-wire/1`.
    pub protocol: String,
    /// What it serves (unknown keys refused, unlike `hello.provides`).
    #[serde(deserialize_with = "strict_provides")]
    pub provides: Provides,
    /// Declared capabilities.
    pub capabilities: Vec<Capability>,
    /// Where it may run.
    pub platforms: Vec<Platform>,
    /// Python launch (runtime = python).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python: Option<PythonSpec>,
    /// Rust factory (runtime = rust).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rust: Option<RustSpec>,
    /// Lifecycle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<Lifecycle>,
    /// Limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<ModuleLimits>,
    /// Integrity pins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<Integrity>,
}

/// `provides` of a manifest: the wire type is lenient (additive minors), a manifest file is not (a typo in a
/// local file is an error).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictProvides {
    #[serde(default)]
    collectors: Option<Vec<crate::message::CollectorInfo>>,
    #[serde(default)]
    sources: Option<Vec<crate::message::SourceInfo>>,
    #[serde(default)]
    sync_all_order: Option<Vec<String>>,
    #[serde(default)]
    methods: Option<Vec<String>>,
}

fn strict_provides<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Provides, D::Error> {
    let s = StrictProvides::deserialize(d)?;
    Ok(Provides {
        collectors: s.collectors,
        sources: s.sources,
        sync_all_order: s.sync_all_order,
        methods: s.methods,
    })
}

impl Manifest {
    /// Checks the schema expresses with patterns and conditionals.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(format!("unsupported manifest schema {:?}", self.schema));
        }
        if !crate::methods::is_valid_slug(&self.name) {
            return Err(format!("invalid module name {:?}", self.name));
        }
        if self.protocol != crate::PROTOCOL_FAMILY {
            return Err(format!(
                "{}: unsupported protocol {:?}",
                self.name, self.protocol
            ));
        }
        if self.platforms.is_empty() {
            return Err(format!("{}: no platforms", self.name));
        }
        for m in self.provides.methods() {
            if !crate::methods::is_valid_method(m) {
                return Err(format!("{}: invalid method {m:?}", self.name));
            }
        }
        match self.runtime {
            ModuleRuntime::Python => {
                let py = self
                    .python
                    .as_ref()
                    .ok_or_else(|| format!("{}: python section missing", self.name))?;
                if !crate::methods::is_valid_slug(&py.env) || py.entry.is_empty() {
                    return Err(format!("{}: invalid python section", self.name));
                }
            }
            ModuleRuntime::Rust => {
                if self.rust.is_none() {
                    return Err(format!("{}: rust section missing", self.name));
                }
            }
        }
        if let Some(i) = &self.integrity {
            for h in [&i.lock_sha256, &i.tree_sha256].into_iter().flatten() {
                if h.len() != 64 || !h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                    return Err(format!(
                        "{}: integrity hashes must be lowercase sha256 hex",
                        self.name
                    ));
                }
            }
        }
        Ok(())
    }

    /// Whether it declares `cap`.
    pub fn has(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Whether it may run on `platform`.
    pub fn runs_on(&self, platform: Platform) -> bool {
        self.platforms.contains(&platform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_provides_stays_strict() {
        let base = serde_json::json!({
            "schema": "secmonk-module/1", "name": "py-x", "version": "0.1.0", "kind": "probe",
            "runtime": "python", "protocol": "secmonk-wire/1", "capabilities": [], "platforms": ["linux"],
            "python": {"project": "python", "env": "secmonk-modules", "entry": ["-I"]},
            "provides": {"methods": ["collector.collect"]}
        });
        assert!(serde_json::from_value::<Manifest>(base.clone()).is_ok());
        let mut typo = base;
        typo["provides"]["method"] = serde_json::json!(["x.y"]);
        assert!(serde_json::from_value::<Manifest>(typo).is_err());
    }
}
