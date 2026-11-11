//! Module registry: manifests from a directory (`*.toml`, `*.json`) or compiled in, filtered by the config.
//!
//! A module runs only when the config lists it in `[modules] enabled`; on another platform it is kept as
//! unavailable (its methods answer `unsupported-platform`). `trust = "pinned"` needs a `[modules.pins]` entry per
//! enabled module and the fixed `python.entry` ([`fixed_entry`]); the runtime verifies the real `uv.lock` and module
//! tree against the pins (a manifest's self-declared `integrity` is not proof). Config `[modules.<name>]` overrides limits and lifecycle, never
//! capabilities.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use secmonk_config::{Config, ModuleOverride, TrustMode};
use secmonk_proto::Manifest;
use secmonk_proto::manifest::{
    EffectiveLifecycle, EffectiveLimits, Lifecycle, ModuleLimits, ModuleRuntime, Platform,
    StartPolicy,
};

/// Registry errors.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// A manifest cannot be read or parsed.
    #[error("{path}: {message}")]
    Manifest {
        /// File.
        path: PathBuf,
        /// Message.
        message: String,
    },
    /// Two manifests with one name.
    #[error("duplicate module {0}")]
    Duplicate(String),
    /// Pinned mode and the pins do not match.
    #[error("module {name}: integrity does not match the config pins ({what})")]
    Pins {
        /// Module.
        name: String,
        /// What differs.
        what: String,
    },
}

/// One registered module.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleEntry {
    /// The manifest.
    pub manifest: Manifest,
    /// Limits after config overrides and defaults.
    pub limits: EffectiveLimits,
    /// Lifecycle after config overrides and defaults.
    pub lifecycle: EffectiveLifecycle,
    /// Runs on this platform.
    pub available: bool,
    /// Where the manifest came from (`None` = compiled in).
    pub source: Option<PathBuf>,
}

/// The registry.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    modules: BTreeMap<String, ModuleEntry>,
}

/// Largest manifest file read.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Parse a manifest file (`.toml` or `.json`) and validate it.
pub fn read_manifest(path: &Path) -> Result<Manifest, RegistryError> {
    let err = |m: String| RegistryError::Manifest {
        path: path.to_path_buf(),
        message: m,
    };
    let md = std::fs::metadata(path).map_err(|e| err(e.to_string()))?;
    if md.len() > MAX_MANIFEST_BYTES {
        return Err(err("manifest too large".into()));
    }
    let text = std::fs::read_to_string(path).map_err(|e| err(e.to_string()))?;
    let m: Manifest = match path.extension().and_then(|e| e.to_str()) {
        Some("toml") => toml::from_str(&text).map_err(|e| err(e.to_string()))?,
        Some("json") => serde_json::from_str(&text).map_err(|e| err(e.to_string()))?,
        _ => return Err(err("not a .toml or .json manifest".into())),
    };
    m.validate().map_err(err)?;
    Ok(m)
}

fn overrides(o: &ModuleOverride) -> (ModuleLimits, Lifecycle) {
    let start = match o.start.as_deref() {
        Some("eager") => Some(StartPolicy::Eager),
        Some("lazy") => Some(StartPolicy::Lazy),
        _ => None,
    };
    (
        ModuleLimits {
            hello_timeout_s: o.hello_timeout_s,
            request_timeout_s: o.request_timeout_s,
            cancel_grace_s: o.cancel_grace_s,
            max_frame: o.max_frame,
            max_inflight: o.max_inflight,
            memory_mb: o.memory_mb,
        },
        Lifecycle {
            start,
            idle_timeout_s: o.idle_timeout_s,
            max_restarts: o.max_restarts,
            restart_window_s: o.restart_window_s,
        },
    )
}

/// The only launch arguments a pinned Python module may declare: the module package's serve command.
pub fn fixed_entry(name: &str) -> Vec<String> {
    [
        "-I",
        "-m",
        "secmonk_modules",
        "serve",
        "--stdio",
        "--module",
        name,
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

impl Registry {
    /// Build from manifests: keep the enabled ones, apply overrides, check pins.
    pub fn from_manifests(
        manifests: Vec<(Manifest, Option<PathBuf>)>,
        enabled: &[String],
        module_overrides: &BTreeMap<String, ModuleOverride>,
        trust: TrustMode,
        pins: &BTreeMap<String, secmonk_config::ModulePin>,
    ) -> Result<Registry, RegistryError> {
        let here = Platform::current();
        let mut modules = BTreeMap::new();
        for (m, source) in manifests {
            if !enabled.contains(&m.name) {
                continue;
            }
            if modules.contains_key(&m.name) {
                return Err(RegistryError::Duplicate(m.name));
            }
            if trust == TrustMode::Pinned {
                // The manifest's own `integrity` strings prove nothing (whoever edits the manifest edits them);
                // the runtime hashes the real `uv.lock` and module tree against `[modules.pins]` at `ensure_env`
                // and again at every module start. Here: the module must have a pin, and, since manifests are
                // outside the tree hash, a Python module's `entry` must be the fixed form.
                if !pins.contains_key(&m.name) {
                    return Err(RegistryError::Pins {
                        name: m.name,
                        what: "no [modules.pins] entry".into(),
                    });
                }
                if let Some(py) = &m.python
                    && m.runtime == ModuleRuntime::Python
                {
                    let want = fixed_entry(&m.name);
                    if py.entry != want {
                        return Err(RegistryError::Pins {
                            name: m.name,
                            what: format!(
                                "python.entry must be {want:?} in pinned mode (manifests are outside the tree hash), got {:?}",
                                py.entry
                            ),
                        });
                    }
                }
            }
            let (lo, lc) = module_overrides
                .get(&m.name)
                .map(overrides)
                .unwrap_or_default();
            let limits = m.limits.clone().unwrap_or_default().overlay(&lo).resolved();
            let lifecycle = m
                .lifecycle
                .clone()
                .unwrap_or_default()
                .overlay(&lc)
                .resolved();
            let available = here.is_some_and(|p| m.runs_on(p));
            modules.insert(
                m.name.clone(),
                ModuleEntry {
                    manifest: m,
                    limits,
                    lifecycle,
                    available,
                    source,
                },
            );
        }
        Ok(Registry { modules })
    }

    /// Load every `*.toml` / `*.json` manifest of `dir` and filter with the config.
    pub fn load_dir(dir: &Path, config: &Config) -> Result<Registry, RegistryError> {
        let mut manifests = Vec::new();
        let rd = std::fs::read_dir(dir).map_err(|e| RegistryError::Manifest {
            path: dir.to_path_buf(),
            message: e.to_string(),
        })?;
        let mut paths: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            if matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("toml" | "json")
            ) {
                manifests.push((read_manifest(&p)?, Some(p)));
            }
        }
        Registry::from_manifests(
            manifests,
            &config.modules_enabled,
            &config.module_overrides,
            config.trust,
            &config.module_pins,
        )
    }

    /// One module.
    pub fn get(&self, name: &str) -> Option<&ModuleEntry> {
        self.modules.get(name)
    }

    /// Every module, by name.
    pub fn iter(&self) -> impl Iterator<Item = &ModuleEntry> {
        self.modules.values()
    }

    /// The module serving `method` (first by name).
    pub fn serving(&self, method: &str) -> Option<&ModuleEntry> {
        self.modules
            .values()
            .find(|e| e.manifest.provides.methods().iter().any(|m| m == method))
    }

    /// Modules to start at app start.
    pub fn eager(&self) -> Vec<&ModuleEntry> {
        self.modules
            .values()
            .filter(|e| e.available && e.lifecycle.start == StartPolicy::Eager)
            .collect()
    }
}
