//! [`ModuleHandle`]: one module, started lazily (or eagerly by the caller), restarted after a crash with
//! exponential backoff, at most `max_restarts` restarts per `restart_window_s`, then `failed`
//! (`module-unavailable`). Dropping the last handle kills the process.

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secmonk_proto::manifest::{EffectiveLifecycle, EffectiveLimits, Manifest};
use secmonk_proto::{ErrorCode, Provides, WireError};
use secmonk_runtime::PythonRuntime;

use crate::ModuleResult;
use crate::child::ChildModule;
use crate::hello::{HostSettings, host_hello};
use crate::registry::ModuleEntry;
use crate::session::{HandshakeOptions, Session, SessionConfig};

/// A started module: its session and, for child processes, the process.
#[derive(Debug)]
pub struct Running {
    /// The session.
    pub session: Session,
    /// The child process (none for in-process modules).
    pub child: Option<ChildModule>,
}

/// Starts the module once.
pub type Starter =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ModuleResult<Running>> + Send>> + Send + Sync>;

/// Lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleState {
    /// Not started.
    Idle,
    /// Running.
    Running,
    /// Gave up (restarts exhausted).
    Failed,
    /// A start (or the backoff before a restart) is in progress.
    Starting,
    /// Stopped for good by [`ModuleHandle::shutdown`].
    Closed,
}

struct State {
    current: Option<Running>,
    starts: VecDeque<Instant>,
    started_once: bool,
    failed: Option<WireError>,
    /// When the module was given up on (the failure lasts one restart window, then a new start is allowed).
    failed_at: Option<Instant>,
    /// Stopped by the idle timeout: the next start is a normal start, not a restart after a crash.
    idle_stopped: bool,
    /// Last time a caller asked for the session.
    last_used: Instant,
    /// Set by [`ModuleHandle::shutdown`]: nothing starts the module again.
    closed: bool,
}

struct Sup {
    manifest: Manifest,
    lifecycle: EffectiveLifecycle,
    limits: EffectiveLimits,
    available: bool,
    starter: Starter,
    state: tokio::sync::Mutex<State>,
    provides: Mutex<Option<Provides>>,
}

/// A supervised module. Cheap to clone.
#[derive(Clone)]
pub struct ModuleHandle {
    sup: Arc<Sup>,
}

impl fmt::Debug for ModuleHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModuleHandle")
            .field("module", &self.sup.manifest.name)
            .finish()
    }
}

/// Delay before restart number `n` (1-based): 100 ms doubling, at most 5 s.
pub fn backoff(n: usize) -> Duration {
    Duration::from_millis(100u64.saturating_mul(1u64 << n.saturating_sub(1).min(6)))
        .min(Duration::from_secs(5))
}

impl ModuleHandle {
    /// A handle with a custom starter (tests, in-process modules).
    pub fn new(entry: &ModuleEntry, starter: Starter) -> ModuleHandle {
        ModuleHandle {
            sup: Arc::new(Sup {
                manifest: entry.manifest.clone(),
                lifecycle: entry.lifecycle,
                limits: entry.limits,
                available: entry.available,
                starter,
                state: tokio::sync::Mutex::new(State {
                    current: None,
                    starts: VecDeque::new(),
                    started_once: false,
                    failed: None,
                    failed_at: None,
                    idle_stopped: false,
                    last_used: Instant::now(),
                    closed: false,
                }),
                provides: Mutex::new(None),
            }),
        }
    }

    /// A Python module: launched through `runtime` (the venv must be ensured by the caller), with the host
    /// `hello` built from `settings`.
    pub fn python(
        entry: &ModuleEntry,
        runtime: Arc<dyn PythonRuntime>,
        settings: HostSettings,
    ) -> ModuleHandle {
        let entry2 = entry.clone();
        let starter: Starter = Arc::new(move || {
            let entry = entry2.clone();
            let runtime = runtime.clone();
            let settings = settings.clone();
            Box::pin(async move {
                let m = &entry.manifest;
                let py = m.python.as_ref().ok_or_else(|| {
                    WireError::new(
                        ErrorCode::ModuleUnavailable,
                        format!("{}: not a python module", m.name),
                    )
                })?;
                let caps: Vec<&str> = m.capabilities.iter().map(|c| c.as_str()).collect();
                let spec = runtime
                    .command_for(&py.env, &py.entry, &caps)
                    .map_err(|e| {
                        WireError::new(ErrorCode::ModuleUnavailable, format!("{}: {e}", m.name))
                    })?;
                if let Some(root) = &settings.modules_root {
                    let _ = secmonk_config::layout::ensure_private_dir(&root.join(&m.name));
                }
                let (hs, cfg) = session_params(&entry, &settings);
                let child = ChildModule::spawn(&spec, hs, cfg).await?;
                Ok(Running {
                    session: child.session.clone(),
                    child: Some(child),
                })
            })
        });
        ModuleHandle::new(entry, starter)
    }

    /// Module name.
    pub fn name(&self) -> &str {
        &self.sup.manifest.name
    }

    /// The manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.sup.manifest
    }

    /// What the module serves: the last `hello.provides`, else the manifest's.
    pub fn provides(&self) -> Provides {
        self.sup
            .provides
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| self.sup.manifest.provides.clone())
    }

    /// Default deadline of calls.
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.sup.limits.request_timeout_s)
    }

    /// Current state.
    ///
    /// Never waits for a start in progress (that holds the state lock, possibly for the whole handshake): `/api/meta`
    /// must answer meanwhile.
    pub async fn state(&self) -> ModuleState {
        let Ok(st) = self.sup.state.try_lock() else {
            return ModuleState::Starting;
        };
        if st.closed {
            ModuleState::Closed
        } else if st.failed.is_some() {
            ModuleState::Failed
        } else if st.current.as_ref().is_some_and(|r| !r.session.is_closed()) {
            ModuleState::Running
        } else {
            ModuleState::Idle
        }
    }

    /// The process id of the running module, if any.
    pub async fn pid(&self) -> Option<u32> {
        self.sup
            .state
            .lock()
            .await
            .current
            .as_ref()
            .and_then(|r| r.child.as_ref())
            .and_then(|c| c.pid())
    }

    /// A live session: the current one, or a (re)started module.
    pub async fn session(&self) -> ModuleResult<Session> {
        let sup = &self.sup;
        if !sup.available {
            return Err(WireError::new(
                ErrorCode::UnsupportedPlatform,
                format!(
                    "{} is not available on {}",
                    sup.manifest.name,
                    std::env::consts::OS
                ),
            ));
        }
        let mut st = sup.state.lock().await;
        if st.closed {
            return Err(WireError::new(
                ErrorCode::ModuleUnavailable,
                format!("{}: stopped (the app is shutting down)", sup.manifest.name),
            ));
        }
        st.last_used = Instant::now();
        if let Some(r) = &st.current {
            if !r.session.is_closed() {
                return Ok(r.session.clone());
            }
            let why = r
                .session
                .close_reason()
                .map(|e| e.error)
                .unwrap_or_default();
            tracing::warn!(module = %sup.manifest.name, "module ended: {why}");
            st.current = None; // drops the child: killed if still alive
        }
        // `Failed` lasts one restart window: after it the module may be tried again from a clean slate
        if let (Some(_), Some(at)) = (&st.failed, st.failed_at)
            && at.elapsed() >= Duration::from_secs(sup.lifecycle.restart_window_s)
        {
            st.failed = None;
            st.failed_at = None;
            st.starts.clear();
        }
        if let Some(f) = &st.failed {
            return Err(f.clone());
        }
        if st.started_once && !st.idle_stopped {
            let window = Duration::from_secs(sup.lifecycle.restart_window_s);
            let now = Instant::now();
            while st
                .starts
                .front()
                .is_some_and(|t| now.duration_since(*t) > window)
            {
                st.starts.pop_front();
            }
            if st.starts.len() >= sup.lifecycle.max_restarts as usize {
                let e = WireError::new(
                    ErrorCode::ModuleUnavailable,
                    format!(
                        "{} failed: {} restarts within {}s",
                        sup.manifest.name,
                        sup.lifecycle.max_restarts,
                        sup.lifecycle.restart_window_s
                    ),
                );
                st.failed = Some(e.clone());
                st.failed_at = Some(Instant::now());
                return Err(e);
            }
            st.starts.push_back(now);
            tokio::time::sleep(backoff(st.starts.len())).await;
        }
        st.started_once = true;
        st.idle_stopped = false;
        let running = (sup.starter)().await?;
        if let Some(p) = &running.session.peer().provides {
            *sup.provides.lock().unwrap() = Some(p.clone());
        }
        let s = running.session.clone();
        st.current = Some(running);
        drop(st);
        self.spawn_idle_reaper();
        Ok(s)
    }

    /// With `idle_timeout_s > 0`: stop the module after that long without a session request and without a call in
    /// flight; the next call starts it again (not counted as a restart). One reaper per start, ends with the module.
    fn spawn_idle_reaper(&self) {
        let idle = Duration::from_secs(self.sup.lifecycle.idle_timeout_s);
        if idle.is_zero() {
            return;
        }
        let weak = Arc::downgrade(&self.sup);
        tokio::spawn(async move {
            let tick = (idle / 4).max(Duration::from_millis(50));
            loop {
                tokio::time::sleep(tick).await;
                let Some(sup) = weak.upgrade() else { return };
                let mut st = sup.state.lock().await;
                let Some(r) = st.current.as_ref().filter(|r| !r.session.is_closed()) else {
                    return; // stopped, crashed or replaced: a new start spawns a new reaper
                };
                if r.session.pending() == 0
                    && st.last_used.max(r.session.last_activity()).elapsed() >= idle
                {
                    let running = st.current.take();
                    st.idle_stopped = true;
                    drop(st);
                    tracing::info!(module = %sup.manifest.name, "idle: stopping the module");
                    if let Some(r) = running {
                        match r.child {
                            Some(c) => {
                                c.shutdown(Duration::from_secs(sup.limits.cancel_grace_s))
                                    .await
                            }
                            None => r.session.close(),
                        }
                    }
                    return;
                }
            }
        });
    }

    /// Stop the module for good: close its input, wait the cancel grace, kill. Later [`ModuleHandle::session`]
    /// calls fail with `module-unavailable` (an app that is shutting down must not restart its modules).
    pub async fn shutdown(&self) {
        let running = {
            let mut st = self.sup.state.lock().await;
            st.closed = true; // `session()` refuses from now on, also for a caller already waiting on the lock
            st.current.take()
        };
        if let Some(r) = running {
            match r.child {
                Some(c) => {
                    c.shutdown(Duration::from_secs(self.sup.limits.cancel_grace_s))
                        .await
                }
                None => r.session.close(),
            }
        }
    }
}

/// Handshake and session parameters of a registry entry.
pub fn session_params(
    entry: &ModuleEntry,
    settings: &HostSettings,
) -> (HandshakeOptions, SessionConfig) {
    let m = &entry.manifest;
    let l = entry.limits;
    let hs = HandshakeOptions {
        name: m.name.clone(),
        allowed: m.provides.clone(),
        host_hello: host_hello(m, settings, l.max_frame),
        hello_timeout: Duration::from_secs(l.hello_timeout_s),
    };
    let cfg = SessionConfig {
        name: m.name.clone(),
        max_frame: l.max_frame,
        max_inflight: l.max_inflight,
        request_timeout: Duration::from_secs(l.request_timeout_s),
        cancel_grace: Duration::from_secs(l.cancel_grace_s),
        kill: None,
    };
    (hs, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use async_trait::async_trait;
    use secmonk_config::layout::Layout;
    use secmonk_proto::manifest::{Lifecycle, ModuleLimits};
    use secmonk_runtime::env::module_env_for;
    use secmonk_runtime::{EnvInfo, LaunchSpec, RuntimeInfo, RuntimeResult};

    use crate::registry::read_manifest;

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff(1), Duration::from_millis(100));
        assert_eq!(backoff(2), Duration::from_millis(200));
        assert_eq!(backoff(4), Duration::from_millis(800));
        assert_eq!(backoff(50), Duration::from_secs(5));
    }

    /// A runtime that scopes the environment like `UvRuntime` (host variables come from a fixed map) and
    /// records the environment of the last launch; the program does not exist, so the start itself fails.
    struct Recording {
        layout: Layout,
        seen: Arc<Mutex<Option<BTreeMap<String, OsString>>>>,
    }

    #[async_trait]
    impl PythonRuntime for Recording {
        async fn ensure(&self) -> RuntimeResult<RuntimeInfo> {
            unreachable!("not used")
        }
        async fn ensure_env(&self, _p: &Path, _e: &str) -> RuntimeResult<EnvInfo> {
            unreachable!("not used")
        }
        fn command(&self, _env: &str, _entry: &[String]) -> RuntimeResult<LaunchSpec> {
            panic!("a module must start with command_for (capability-scoped environment)")
        }
        fn command_for(
            &self,
            _env: &str,
            _entry: &[String],
            capabilities: &[&str],
        ) -> RuntimeResult<LaunchSpec> {
            let host = |k: &str| -> Option<OsString> {
                matches!(
                    k,
                    "PATH"
                        | "HOME"
                        | "SSH_AUTH_SOCK"
                        | "DOCKER_HOST"
                        | "KUBECONFIG"
                        | "HTTPS_PROXY"
                )
                .then(|| format!("host-{k}").into())
            };
            let env = module_env_for(&self.layout, capabilities, &host);
            *self.seen.lock().unwrap() = Some(env.clone());
            Ok(LaunchSpec {
                program: PathBuf::from("/nonexistent/secmonk-test-python"),
                args: vec![],
                env,
                cwd: std::env::temp_dir(),
            })
        }
    }

    async fn launch_env(manifest: &str) -> BTreeMap<String, OsString> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../python/modules")
            .join(manifest);
        let m = read_manifest(&path).unwrap();
        let entry = ModuleEntry {
            limits: ModuleLimits::default().resolved(),
            lifecycle: Lifecycle::default().resolved(),
            manifest: m,
            available: true,
            source: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let seen = Arc::new(Mutex::new(None));
        let rt = Recording {
            layout: Layout::new(tmp.path()),
            seen: seen.clone(),
        };
        let h = ModuleHandle::python(&entry, Arc::new(rt), HostSettings::default());
        let _ = h.session().await; // spawn fails: the program does not exist
        seen.lock()
            .unwrap()
            .clone()
            .expect("the module was launched")
    }

    #[tokio::test]
    async fn module_env_is_scoped_by_manifest_capabilities() {
        let engine = launch_env("py-engine.toml").await;
        for k in ["SSH_AUTH_SOCK", "DOCKER_HOST", "KUBECONFIG", "HTTPS_PROXY"] {
            assert!(!engine.contains_key(k), "py-engine must not receive {k}");
        }
        assert!(engine.contains_key("PATH"), "base variables stay");

        let probe = launch_env("py-probe.toml").await;
        for k in ["SSH_AUTH_SOCK", "DOCKER_HOST", "KUBECONFIG", "HTTPS_PROXY"] {
            assert!(
                probe.contains_key(k),
                "py-probe (read-target, network) receives {k}"
            );
        }

        let sources = launch_env("py-sources.toml").await;
        assert!(sources.contains_key("HTTPS_PROXY"));
        assert!(!sources.contains_key("SSH_AUTH_SOCK"));
    }
}
