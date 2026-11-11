//! Construction of the engine from the composed parts: the one place that names both the engine crate and the module
//! adapters' trait objects (architecture.md "Engine construction (W3.1)").

use std::sync::Arc;

use async_trait::async_trait;
use secmonk_config::Config;
use secmonk_engine::{EngineConfig, EngineDeps, ModuleInfo, ModuleStatus, SecmonkEngine};
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
}
