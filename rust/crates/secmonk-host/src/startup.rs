//! Startup phases and their progress reports.

use std::fmt;
use std::sync::{Arc, Mutex};

/// A step of [`crate::Host::start`], in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Pinned uv: download, verify, extract (skipped when present).
    Uv,
    /// The managed Python interpreter.
    Python,
    /// The module venv (`uv sync --frozen`).
    ModuleEnv,
    /// State and mirror databases, migrations.
    Databases,
    /// Module registry, probe, sources, engine.
    Modules,
}

impl Phase {
    /// Every phase, in order.
    pub const ALL: [Phase; 5] = [
        Phase::Uv,
        Phase::Python,
        Phase::ModuleEnv,
        Phase::Databases,
        Phase::Modules,
    ];

    /// 1-based position and the total, for "step 2 of 5".
    pub fn step(self) -> (usize, usize) {
        (self as usize + 1, Self::ALL.len())
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Phase::Uv => "downloading uv",
            Phase::Python => "installing Python",
            Phase::ModuleEnv => "installing the module environment",
            Phase::Databases => "opening the databases",
            Phase::Modules => "starting the modules",
        })
    }
}

/// Progress callback of [`crate::Host::start`]: called when a phase begins.
pub type Progress = Arc<dyn Fn(Phase) + Send + Sync>;

/// A progress callback that ignores everything.
pub fn no_progress() -> Progress {
    Arc::new(|_| {})
}

/// Where startup stands, shared between the starter and whoever answers requests meanwhile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupState {
    /// Running the given phase.
    Preparing(Phase),
    /// Everything is up.
    Ready,
    /// Startup failed; the message is already scrubbed.
    Failed(String),
    /// The app is closing.
    Stopping,
}

/// A shared [`StartupState`].
#[derive(Debug, Clone)]
pub struct StartupCell(Arc<Mutex<StartupState>>);

impl StartupCell {
    /// Starts as `Preparing(Uv)`.
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(StartupState::Preparing(Phase::Uv))))
    }

    /// Current state.
    pub fn get(&self) -> StartupState {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Replace the state. `Stopping` is final: nothing replaces it (a startup that ends after the shutdown began
    /// must not report `Ready`).
    pub fn set(&self, s: StartupState) {
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if *g != StartupState::Stopping {
            *g = s;
        }
    }

    /// A [`Progress`] that records the phase here while the state is still `Preparing`.
    pub fn progress(&self) -> Progress {
        let cell = self.clone();
        Arc::new(move |phase| {
            let mut g = cell.0.lock().unwrap_or_else(|p| p.into_inner());
            if matches!(*g, StartupState::Preparing(_)) {
                *g = StartupState::Preparing(phase);
            }
        })
    }
}

impl Default for StartupCell {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_are_ordered_and_numbered() {
        assert_eq!(Phase::Uv.step(), (1, 5));
        assert_eq!(Phase::Modules.step(), (5, 5));
        assert!(Phase::Python < Phase::ModuleEnv);
        assert_eq!(Phase::Python.to_string(), "installing Python");
    }

    #[test]
    fn progress_updates_only_while_preparing() {
        let c = StartupCell::new();
        let p = c.progress();
        p(Phase::ModuleEnv);
        assert_eq!(c.get(), StartupState::Preparing(Phase::ModuleEnv));
        c.set(StartupState::Ready);
        p(Phase::Uv);
        assert_eq!(c.get(), StartupState::Ready);
    }

    #[test]
    fn stopping_is_final() {
        let c = StartupCell::new();
        c.set(StartupState::Stopping);
        c.set(StartupState::Ready);
        c.set(StartupState::Failed("x".into()));
        assert_eq!(c.get(), StartupState::Stopping);
    }
}
