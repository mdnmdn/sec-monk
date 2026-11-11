//! Child-process stdio transport: stdin = frames to the module, stdout = frames from it, stderr = log lines
//! (forwarded to `tracing`, target `module`, scrubbed, at most 8 KiB per line). The child is killed when the
//! [`ChildModule`] is dropped (`kill_on_drop`), runs in its own process group on Unix (a terminal Ctrl-C does
//! not reach it; the host decides) and gets `CREATE_NO_WINDOW` on Windows (`LaunchSpec::to_command`).

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secmonk_proto::{ErrorCode, WireError};
use secmonk_runtime::LaunchSpec;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Child;

use crate::ModuleResult;
use crate::session::{HandshakeOptions, Session, SessionConfig};

/// SIGKILL to the whole process group of a module (`process_group(0)` made the child's pid the group id), so what
/// the module started (ssh, docker, kubectl, git) dies with it. A no-op where the group is already gone.
///
/// Windows: the equivalent is a Job object with `KILL_ON_JOB_CLOSE`, which needs a safe wrapper crate; not done
/// (the host forbids `unsafe`), see `_docs/plans/on-windows.md`. There only the module process is killed.
#[cfg(unix)]
pub fn kill_group(pid: u32) {
    if let Some(p) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(p, rustix::process::Signal::KILL);
    }
}

/// See the Unix version.
#[cfg(not(unix))]
pub fn kill_group(_pid: u32) {}

/// Longest stderr line forwarded (longer lines are cut).
pub const MAX_LOG_LINE: u64 = 8 * 1024;

/// A running module process and its session.
#[derive(Debug)]
pub struct ChildModule {
    /// The session.
    pub session: Session,
    child: Arc<Mutex<Option<Child>>>,
    pid: Option<u32>,
}

impl ChildModule {
    /// Spawn `spec`, forward stderr, run the handshake. On failure the process is killed.
    pub async fn spawn(
        spec: &LaunchSpec,
        hs: HandshakeOptions,
        mut cfg: SessionConfig,
    ) -> ModuleResult<ChildModule> {
        let name = hs.name.clone();
        let unavailable =
            |m: String| WireError::new(ErrorCode::ModuleUnavailable, format!("{name}: {m}"));
        let mut cmd = spec.to_command();
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd
            .spawn()
            .map_err(|e| unavailable(format!("cannot start {}: {e}", spec.program.display())))?;
        let pid = child.id();
        let (Some(stdin), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            return Err(unavailable("stdio not captured".into()));
        };
        let module = name.clone();
        tokio::spawn(async move {
            let mut r = BufReader::new(stderr);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match (&mut r)
                    .take(MAX_LOG_LINE)
                    .read_until(b'\n', &mut buf)
                    .await
                {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let line = String::from_utf8_lossy(&buf);
                        let line = secmonk_safeio::scrub_text(line.trim_end());
                        if !line.is_empty() {
                            tracing::info!(target: "module", module = %module, "{line}");
                        }
                        if !buf.ends_with(b"\n") {
                            // cut line: skip to the next newline
                            let mut skip = Vec::new();
                            if r.read_until(b'\n', &mut skip).await.unwrap_or(0) == 0 {
                                break;
                            }
                        }
                    }
                }
            }
        });
        let slot = Arc::new(Mutex::new(Some(child)));
        let weak = Arc::downgrade(&slot);
        cfg.kill = Some(Arc::new(move || {
            // take the child out, kill it and reap it, so no zombie is left behind
            let taken = weak.upgrade().and_then(|s| s.lock().unwrap().take());
            if let Some(mut c) = taken {
                if let Some(p) = c.id() {
                    kill_group(p);
                }
                let _ = c.start_kill();
                if let Ok(rt) = tokio::runtime::Handle::try_current() {
                    rt.spawn(async move {
                        let _ = c.wait().await;
                    });
                }
            }
        }));
        match Session::connect(stdout, stdin, hs, cfg).await {
            Ok(session) => Ok(ChildModule {
                session,
                child: slot,
                pid,
            }),
            Err(e) => {
                // failed handshake: kill the group while the leader is still ours, then reap (no zombie)
                let taken = slot.lock().unwrap().take();
                if let Some(mut c) = taken {
                    if let Some(p) = c.id() {
                        kill_group(p);
                    }
                    let _ = c.start_kill();
                    let _ = tokio::time::timeout(Duration::from_secs(5), c.wait()).await;
                }
                Err(e)
            }
        }
    }

    /// The process id.
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// Close the input (a module exits on EOF), wait up to `grace`, then kill. Waits for the exit.
    pub async fn shutdown(self, grace: Duration) {
        self.session.close();
        let child = self.child.lock().unwrap().take();
        if let Some(mut c) = child {
            if tokio::time::timeout(grace, c.wait()).await.is_err() {
                // still running after the grace: the whole group first (while the leader is not reaped, its
                // pid is certainly still the group id), then the leader, then reap
                if let Some(p) = self.pid {
                    kill_group(p);
                }
                let _ = c.start_kill();
                let _ = c.wait().await;
            }
            // the module exited on its own: whatever it left running in its group goes too (the group id stays
            // reserved while a member lives, so this cannot hit an unrelated process)
            if let Some(p) = self.pid {
                kill_group(p);
            }
        }
    }

    /// Whether the process has exited (reaps it if so).
    pub fn has_exited(&self) -> bool {
        match self.child.lock().unwrap().as_mut() {
            Some(c) => !matches!(c.try_wait(), Ok(None)),
            None => true,
        }
    }
}

impl Drop for ChildModule {
    /// A handle dropped with the process still ours: kill its group (`kill_on_drop` alone signals the leader only).
    fn drop(&mut self) {
        if let Ok(g) = self.child.lock()
            && g.is_some()
            && let Some(p) = self.pid
        {
            kill_group(p);
        }
    }
}
