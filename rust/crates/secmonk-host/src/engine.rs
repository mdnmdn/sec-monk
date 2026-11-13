//! Construction of the engine from the composed parts: the one place that names both the engine crate and the module
//! adapters' trait objects (architecture.md "Engine construction (W3.1)").

use std::sync::Arc;

use async_trait::async_trait;
use secmonk_config::Config;
use secmonk_engine::{
    EngineConfig, EngineDeps, ModuleInfo, ModuleStatus, SecmonkEngine, StoreMirrorView,
};
use secmonk_modhost::adapters::PyEngine;
use secmonk_modhost::supervisor::{ModuleHandle, ModuleState};
use secmonk_probe::ProbeService;
use secmonk_store::SqliteStore;
use secmonk_traits::Source;

use crate::host::HostError;

/// `/api/meta` `engine.modules`: the module host's states.
pub(crate) struct ModuleStates {
    /// Handle and whether the module runs on this platform.
    pub(crate) modules: Vec<(ModuleHandle, bool)>,
}

#[async_trait]
impl ModuleStatus for ModuleStates {
    async fn modules(&self) -> Vec<ModuleInfo> {
        let mut out = Vec::new();
        for (h, available) in &self.modules {
            let state = if !available {
                "unavailable"
            } else {
                match h.state().await {
                    ModuleState::Running => "ready",
                    ModuleState::Idle => "stopped",
                    ModuleState::Failed => "failed",
                    ModuleState::Starting => "starting",
                    ModuleState::Closed => "stopped",
                }
            };
            out.push(ModuleInfo {
                name: h.name().to_owned(),
                runtime: "python".into(),
                state: state.into(),
            });
        }
        out
    }
}

/// The native sources `[sources.implementation]` selects (rust ADR-0011), each over a read-only view of the mirror.
/// `python_served`: the sources of the enabled Python source modules (their manifests' `provides.sources`). Every
/// name in `[sources.implementation]` must be servable as configured, else the start is refused (as an unknown config
/// key is): `rust` needs a Rust implementation, `python` an enabled module serving the name; a misspelled name
/// (`kve`) matches neither.
pub(crate) fn native_sources(
    config: &Config,
    store: &SqliteStore,
    python_served: &[String],
) -> Result<Vec<Arc<dyn Source>>, HostError> {
    use secmonk_config::{ConfigError, SourceImpl};
    for (name, imp) in &config.source_impls {
        let problem = match imp {
            SourceImpl::Rust if secmonk_sources::importer(name).is_none() => Some(format!(
                "sources.implementation.{name} = \"rust\": there is no Rust implementation of {name} (Rust: {})",
                secmonk_sources::native_names().join(", ")
            )),
            SourceImpl::Python if !python_served.contains(name) => Some(format!(
                "sources.implementation.{name} = \"python\": no enabled module serves {name} (Python: {})",
                if python_served.is_empty() {
                    "none enabled".to_owned()
                } else {
                    python_served.join(", ")
                }
            )),
            _ => None,
        };
        if let Some(p) = problem {
            return Err(HostError::Config(ConfigError::Invalid(p)));
        }
    }
    let view: Arc<dyn secmonk_traits::MirrorView> =
        Arc::new(StoreMirrorView::new(Arc::new(store.clone())));
    let mut out = Vec::new();
    for imp in secmonk_sources::IMPORTERS {
        let default = if imp.default_rust {
            SourceImpl::Rust
        } else {
            SourceImpl::Python
        };
        if config.source_impl(imp.name, default) == SourceImpl::Rust {
            tracing::info!(source = imp.name, "source implementation: rust (native)");
            out.push((imp.new)(view.clone()));
        }
    }
    Ok(out)
}

pub(crate) struct Parts<'a> {
    pub(crate) config: &'a Config,
    pub(crate) store: &'a SqliteStore,
    pub(crate) probe: &'a Arc<ProbeService>,
    pub(crate) sources: &'a [Arc<dyn Source>],
    pub(crate) steps: Option<&'a Arc<PyEngine>>,
    pub(crate) procmon: Option<&'a Arc<PyEngine>>,
    /// The binding's actions setting (`EngineConfig::allow_actions`).
    pub(crate) allow_actions: bool,
    pub(crate) modules: Vec<(ModuleHandle, bool)>,
}

/// The engine's settings from the host configuration and the binding's actions setting.
pub(crate) fn engine_config(
    config: &Config,
    state_path: std::path::PathBuf,
    allow_actions: bool,
) -> EngineConfig {
    let mut c = EngineConfig::new(env!("CARGO_PKG_VERSION"), state_path);
    c.data_dir = config.data_dir.clone();
    c.min_confidence = config.min_confidence;
    c.allow_actions = allow_actions;
    c.snapshot_mode = config.ui_snapshot.is_some();
    c.nvd_api_key_env = Some(config.nvd_api_key_env.clone()).filter(|n| !n.is_empty());
    c
}

pub(crate) fn build(p: Parts<'_>) -> Result<Arc<SecmonkEngine>, HostError> {
    let steps = p.steps.ok_or_else(|| {
        HostError::Unsupported(
            "py-engine is not enabled: list it in [modules] enabled (classify, match and the reports run there)"
                .into(),
        )
    })?;
    let config = engine_config(
        p.config,
        p.store.state_path().to_path_buf(),
        p.allow_actions,
    );
    Ok(SecmonkEngine::new(EngineDeps {
        config,
        state: Arc::new(p.store.clone()),
        mirror: Arc::new(p.store.clone()),
        steps: steps.clone(),
        procmon: p
            .procmon
            .map(|m| m.clone() as Arc<dyn secmonk_traits::Reporter>),
        sources: p.sources.to_vec(),
        probe: p.probe.clone(),
        modules: Some(Arc::new(ModuleStates { modules: p.modules })),
        node_store: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bindings_actions_setting_reaches_the_engine() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("cwd")).unwrap();
        let config = secmonk_config::load(&secmonk_config::LoadOptions {
            cwd: r.join("cwd"),
            home: Some(r.join("home")),
            user_config_root: Some(r.join("cfgroot")),
            user_data_root: Some(r.join("dataroot")),
            ..Default::default()
        })
        .unwrap();
        let on = engine_config(&config, r.join("s.sqlite3"), true);
        let off = engine_config(&config, r.join("s.sqlite3"), false);
        assert!(on.allow_actions);
        assert!(!off.allow_actions);
        assert_eq!(off.data_dir, config.data_dir);
    }

    async fn store_in(dir: &std::path::Path) -> SqliteStore {
        SqliteStore::open(
            &dir.join("state.sqlite3"),
            &dir.join("mirror.sqlite3"),
            &secmonk_store::StoreOptions::default(),
        )
        .await
        .unwrap()
    }

    fn config_with(dir: &std::path::Path, sources: &str) -> Config {
        std::fs::create_dir_all(dir.join("cwd")).unwrap();
        let raw = secmonk_config::parse(sources, std::path::Path::new("x.toml")).unwrap();
        secmonk_config::resolve(
            raw,
            secmonk_config::ConfigOrigin::Flag,
            None,
            &secmonk_config::LoadOptions {
                cwd: dir.join("cwd"),
                home: Some(dir.join("home")),
                user_config_root: Some(dir.join("cfgroot")),
                user_data_root: Some(dir.join("dataroot")),
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn the_configuration_selects_the_native_sources() {
        let d = tempfile::tempdir().unwrap();
        let store = store_in(d.path()).await;
        let names = |v: &[Arc<dyn Source>]| -> Vec<String> {
            v.iter().flat_map(|s| s.sources()).map(|i| i.name).collect()
        };
        // default: the importers with `default_rust` (secmonk_sources::IMPORTERS), in that order
        let mut served: Vec<String> = secmonk_sources::native_names()
            .iter()
            .map(|n| (*n).to_owned())
            .collect();
        served.push("osv".into());
        let defaults: Vec<&str> = secmonk_sources::IMPORTERS
            .iter()
            .filter(|i| i.default_rust)
            .map(|i| i.name)
            .collect();
        assert!(defaults.contains(&"kev") && defaults.contains(&"epss"));
        let native = native_sources(&config_with(d.path(), ""), &store, &served).unwrap();
        assert_eq!(names(&native), defaults);
        assert!(native.iter().all(|s| s.native()));
        // python for every importer: nothing native (py-sources serves them)
        let all_python: String = secmonk_sources::native_names()
            .iter()
            .map(|n| format!("\"{n}\" = \"python\"\n"))
            .collect();
        let c = config_with(d.path(), &format!("[sources.implementation]\n{all_python}"));
        assert!(native_sources(&c, &store, &served).unwrap().is_empty());
        // one of them only
        let only_kev: String = secmonk_sources::native_names()
            .iter()
            .filter(|n| **n != "kev")
            .map(|n| format!("\"{n}\" = \"python\"\n"))
            .collect();
        let only_kev = config_with(
            d.path(),
            &format!("[sources.implementation]\nkev = \"rust\"\n{only_kev}"),
        );
        assert_eq!(
            names(&native_sources(&only_kev, &store, &served).unwrap()),
            vec!["kev"]
        );
        // ... but not when no enabled module serves it
        let c = config_with(d.path(), "[sources.implementation]\nkev = \"python\"\n");
        let e = native_sources(&c, &store, &[]).err().unwrap();
        assert!(
            e.to_string().contains("no enabled module serves kev"),
            "{e}"
        );
        // a misspelled name is refused (review W6.5 L7), whatever its value
        for v in ["python", "rust"] {
            let c = config_with(
                d.path(),
                &format!("[sources.implementation]\nkve = \"{v}\"\n"),
            );
            let e = native_sources(&c, &store, &served).err().unwrap();
            assert!(e.to_string().contains("sources.implementation.kve"), "{e}");
        }
        // every shipped source has a native importer since osv and cvelist were ported (3cd17ca), so
        // `osv = "rust"` is now accepted; the "no Rust implementation" refusal is covered by the misspelled
        // names above (an unknown name has neither implementation)
        let c = config_with(d.path(), "[sources.implementation]\nosv = \"rust\"\n");
        assert!(native_sources(&c, &store, &served).is_ok());
        store.close().await;
    }
}
