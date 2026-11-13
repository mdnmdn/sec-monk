//! `UvRuntime`: the pinned-uv implementation of [`PythonRuntime`].

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::env::{UvEnvOptions, UvStep, module_env, module_env_for, sentinel_dirs, uv_env};
use crate::extract::extract_uv;
use crate::fetch::{asset_url, fetch_to, part_path, sha256_file};
use crate::platform::{UvAsset, host_asset};
use crate::tree::{TreeDigest, verify_project_pins};
use crate::{EnvInfo, LaunchSpec, PythonRuntime, RuntimeError, RuntimeInfo, RuntimeResult, pins};
use secmonk_config::{Config, Layout, ModulePin, TrustMode, UvPath};

/// Longest a uv step may run.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Everything `UvRuntime` needs; [`UvSettings::from_config`] builds it from `sec-monk.toml`.
#[derive(Debug, Clone)]
pub struct UvSettings {
    /// The data directory layout (absolute root).
    pub layout: Layout,
    /// uv version.
    pub uv_version: String,
    /// URL template.
    pub uv_url: String,
    /// Local archive instead of a download.
    pub uv_archive: Option<PathBuf>,
    /// Config checksum overrides (target -> sha256).
    pub uv_sha256: BTreeMap<String, String>,
    /// Python version.
    pub python_version: String,
    /// Offline mode.
    pub offline: bool,
    /// Package index.
    pub index_url: Option<String>,
    /// Wheel directory.
    pub find_links: Option<PathBuf>,
    /// Trust mode (`pinned` installs non-editable and verifies `module_pins` before `uv sync` and every start).
    pub trust: TrustMode,
    /// `[modules.pins]` of the enabled modules (they share the project; each pin must match it).
    pub module_pins: BTreeMap<String, ModulePin>,
    /// The asset of this host (overridable in tests).
    pub asset: Option<UvAsset>,
    /// `[uv] path`: a uv binary to use instead of the managed download (`Auto`: `uv` on `PATH`).
    pub uv_path: Option<UvPath>,
    /// `[uv] any_version`: accept any version of `uv_path`.
    pub uv_any_version: bool,
}

/// Where the uv in use came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvSource {
    /// `tools/uv-<version>/`: downloaded and verified (sha256 pin).
    Managed,
    /// `[uv] path` named a file.
    Configured,
    /// `[uv] path = "auto"` found `uv` on `PATH`.
    Path,
}

/// The uv binary [`UvRuntime::ensure_uv`] settled on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UvInUse {
    /// The binary.
    pub path: PathBuf,
    /// Its version (the pinned one for a managed copy).
    pub version: String,
    /// Where it came from.
    pub source: UvSource,
}

impl UvSettings {
    /// From the resolved config.
    pub fn from_config(c: &Config) -> UvSettings {
        UvSettings {
            layout: c.layout(),
            uv_version: c
                .uv_version
                .clone()
                .unwrap_or_else(|| pins::UV_VERSION.into()),
            uv_url: c.uv_url.clone().unwrap_or_else(|| pins::UV_URL.into()),
            uv_archive: c.uv_archive.clone(),
            uv_sha256: c.uv_sha256.clone(),
            python_version: c.python_version.clone(),
            offline: c.offline,
            index_url: c.index_url.clone(),
            find_links: c.find_links.clone(),
            trust: c.trust,
            module_pins: c
                .module_pins
                .iter()
                .filter(|(name, _)| c.modules_enabled.contains(name))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            asset: host_asset(),
            uv_path: c.uv_path.clone(),
            uv_any_version: c.uv_any_version,
        }
    }

    /// The expected sha256 of the archive of `triple`: config override, else the compiled-in pin when the
    /// version is the pinned one; otherwise none (fail closed).
    pub fn expected_sha256(&self, triple: &str) -> Option<String> {
        if let Some(s) = self.uv_sha256.get(triple) {
            return Some(s.to_ascii_lowercase());
        }
        (self.uv_version == pins::UV_VERSION)
            .then(|| pins::builtin_sha256(triple).map(str::to_string))
            .flatten()
    }
}

/// `tools/uv-<v>/VERIFIED`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Verified {
    version: String,
    asset: String,
    archive_sha256: String,
    binary_sha256: String,
    date: String,
}

/// `venvs/<env>/.secmonk-install.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct InstallMarker {
    uv_version: String,
    python_version: String,
    lock_sha256: String,
    /// Absent in markers written before W3.4: a mismatch, so the env is synced again.
    #[serde(default)]
    tree_sha256: String,
    project: String,
    editable: bool,
    date: String,
}

/// The pinned-uv runtime.
#[derive(Debug, Clone)]
pub struct UvRuntime {
    settings: UvSettings,
    host_env: fn(&str) -> Option<OsString>,
    /// env -> project, recorded by `ensure_env` (pinned mode re-verifies the project before every start).
    projects: Arc<Mutex<BTreeMap<String, PathBuf>>>,
    /// The uv chosen by `ensure_uv`.
    in_use: Arc<Mutex<Option<UvInUse>>>,
}

fn real_env(k: &str) -> Option<OsString> {
    std::env::var_os(k)
}

impl UvRuntime {
    /// A runtime reading pass-through variables from the process environment.
    pub fn new(settings: UvSettings) -> UvRuntime {
        UvRuntime::with_host_env(settings, real_env)
    }

    /// With another source of host variables (tests).
    pub fn with_host_env(
        settings: UvSettings,
        host_env: fn(&str) -> Option<OsString>,
    ) -> UvRuntime {
        UvRuntime {
            settings,
            host_env,
            projects: Arc::default(),
            in_use: Arc::default(),
        }
    }

    /// Settings.
    pub fn settings(&self) -> &UvSettings {
        &self.settings
    }

    fn layout(&self) -> &Layout {
        &self.settings.layout
    }

    /// The managed uv path (`<tools>/uv-<v>/uv[.exe]`).
    fn managed_uv_path(&self) -> PathBuf {
        self.layout()
            .uv_dir(&self.settings.uv_version)
            .join(exe_name("uv"))
    }

    /// The uv binary: the one [`UvRuntime::ensure_uv`] settled on, else the managed path.
    pub fn uv_path(&self) -> PathBuf {
        match self.uv_in_use() {
            Some(u) => u.path,
            None => self.managed_uv_path(),
        }
    }

    /// Which uv `ensure_uv` settled on (`None` before it ran).
    pub fn uv_in_use(&self) -> Option<UvInUse> {
        self.in_use
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn record(&self, path: &Path, version: &str, source: UvSource) {
        tracing::info!(uv = %path.display(), version, source = ?source, "uv in use");
        *self.in_use.lock().unwrap_or_else(|p| p.into_inner()) = Some(UvInUse {
            path: path.to_path_buf(),
            version: version.to_string(),
            source,
        });
    }

    /// `<uv> --version` must report the configured version (unless `any_version`). Returns the version.
    async fn check_external(&self, uv: &Path) -> RuntimeResult<String> {
        if !uv.is_file() {
            return Err(RuntimeError::io(
                uv,
                std::io::Error::new(std::io::ErrorKind::NotFound, "no such uv binary"),
            ));
        }
        let out = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::process::Command::new(uv)
                .arg("--version")
                .env_clear()
                .env("UV_NO_CONFIG", "1")
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| RuntimeError::Step {
            step: "uv --version".into(),
            code: None,
            stderr: "timed out".into(),
        })?
        .map_err(|e| RuntimeError::io(uv, e))?;
        if !out.status.success() {
            return Err(RuntimeError::Step {
                step: "uv --version".into(),
                code: out.status.code(),
                stderr: secmonk_safeio::scrub_text(&String::from_utf8_lossy(&out.stderr)),
            });
        }
        let found = parse_uv_version(&String::from_utf8_lossy(&out.stdout));
        let expected = &self.settings.uv_version;
        if !self.settings.uv_any_version && found.as_deref() != Some(expected.as_str()) {
            return Err(RuntimeError::UvVersion {
                path: uv.to_path_buf(),
                found: found.unwrap_or_else(|| "unknown".into()),
                expected: expected.clone(),
            });
        }
        Ok(found.unwrap_or_else(|| "unknown".into()))
    }

    /// `[uv] path`: the configured binary, or `uv` on `PATH` (`auto`, falling back to the managed download when
    /// absent or of another version). `Ok(None)`: use the managed download.
    async fn external_uv(&self) -> RuntimeResult<Option<PathBuf>> {
        match &self.settings.uv_path {
            None => Ok(None),
            Some(UvPath::File(f)) => {
                let v = self.check_external(f).await?;
                self.record(f, &v, UvSource::Configured);
                Ok(Some(f.clone()))
            }
            Some(UvPath::Auto) => {
                let path = (self.host_env)("PATH");
                let Some(f) = path
                    .as_deref()
                    .and_then(|p| find_on_path(&exe_name("uv"), p))
                else {
                    tracing::info!("uv.path = auto: no uv on PATH, using the managed download");
                    return Ok(None);
                };
                match self.check_external(&f).await {
                    Ok(v) => {
                        self.record(&f, &v, UvSource::Path);
                        Ok(Some(f))
                    }
                    Err(e) => {
                        tracing::info!(uv = %f.display(), error = %e, "uv on PATH not usable, using the managed download");
                        Ok(None)
                    }
                }
            }
        }
    }

    /// The interpreter of venv `env`.
    pub fn venv_python(&self, env: &str) -> PathBuf {
        let v = self.layout().venv(env);
        if cfg!(windows) {
            v.join("Scripts").join("python.exe")
        } else {
            v.join("bin").join("python")
        }
    }

    fn env_options(&self) -> UvEnvOptions {
        UvEnvOptions {
            python_version: self.settings.python_version.clone(),
            offline: self.settings.offline,
            index_url: self.settings.index_url.clone(),
            find_links: self.settings.find_links.clone(),
        }
    }

    /// The environment of a uv step (exposed for audits and tests).
    pub fn uv_environment(&self, step: UvStep, venv: Option<&Path>) -> BTreeMap<String, OsString> {
        uv_env(
            self.layout(),
            &self.env_options(),
            step,
            venv,
            &self.host_env,
        )
    }

    /// Download (or copy), verify and install uv unless an intact verified copy exists. Returns the binary.
    pub async fn ensure_uv(&self) -> RuntimeResult<PathBuf> {
        if let Some(uv) = self.external_uv().await? {
            return Ok(uv);
        }
        let s = &self.settings;
        let dir = self.layout().uv_dir(&s.uv_version);
        let exe = self.managed_uv_path();
        let asset = s.asset.clone().ok_or_else(|| {
            RuntimeError::UnsupportedPlatform(format!(
                "{}/{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            ))
        })?;
        let expected = s
            .expected_sha256(asset.triple)
            .ok_or_else(|| RuntimeError::NoChecksum(asset.triple.into()))?;
        // Fast path: the installed copy was verified against the *current* pin (version, asset, archive sha256)
        // and the binary is unchanged. A changed pin re-fetches.
        if let Ok(text) = std::fs::read_to_string(dir.join("VERIFIED"))
            && let Ok(v) = serde_json::from_str::<Verified>(&text)
            && v.version == s.uv_version
            && v.asset == asset.name
            && v.archive_sha256 == expected
            && exe.is_file()
            && sha256_file(&exe)? == v.binary_sha256
        {
            self.record(&exe, &s.uv_version, UvSource::Managed);
            return Ok(exe);
        }
        let downloads = self.layout().downloads();
        mkdir(&downloads)?;
        let part = part_path(&downloads, &asset.name);
        let url = asset_url(&s.uv_url, &s.uv_version, &asset.name);
        tracing::info!(asset = %asset.name, local = s.uv_archive.is_some(), "fetching uv");
        let actual = fetch_to(&url, s.uv_archive.as_deref(), &part, s.offline).await;
        let actual = match actual {
            Ok(a) => a,
            Err(e) => {
                let _ = std::fs::remove_file(&part);
                return Err(e);
            }
        };
        if actual != expected {
            let _ = std::fs::remove_file(&part);
            return Err(RuntimeError::ChecksumMismatch {
                asset: asset.name.clone(),
                expected,
                actual,
            });
        }
        let staging = self
            .layout()
            .tools()
            .join(format!("uv-{}.partial", s.uv_version));
        let _ = std::fs::remove_dir_all(&staging);
        mkdir(&staging)?;
        let res = extract_uv(&part, asset.kind, &staging);
        let _ = std::fs::remove_file(&part);
        if let Err(e) = res {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
        let main = staging.join(exe.file_name().unwrap_or_default());
        let verified = Verified {
            version: s.uv_version.clone(),
            asset: asset.name.clone(),
            archive_sha256: actual,
            binary_sha256: sha256_file(&main)?,
            date: secmonk_model::time::now_iso(),
        };
        write_private(
            &staging.join("VERIFIED"),
            &serde_json::to_vec_pretty(&verified).unwrap_or_default(),
        )?;
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::rename(&staging, &dir).map_err(|e| RuntimeError::io(&dir, e))?;
        tracing::info!(version = %s.uv_version, "uv installed and verified");
        self.record(&exe, &s.uv_version, UvSource::Managed);
        Ok(exe)
    }

    /// Run a uv step with the contained environment; captures output; errors carry the scrubbed stderr tail.
    pub async fn run_uv(
        &self,
        step_name: &str,
        step: UvStep,
        venv: Option<&Path>,
        args: &[OsString],
    ) -> RuntimeResult<String> {
        let uv = self.uv_path();
        for (_, d) in sentinel_dirs(self.layout()) {
            mkdir(&d)?;
        }
        mkdir(&self.layout().tmp())?;
        let spec = LaunchSpec {
            program: uv,
            args: args.to_vec(),
            env: self.uv_environment(step, venv),
            cwd: self.layout().root.clone(),
        };
        let mut cmd = spec.to_command();
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        tracing::info!(step = step_name, "running uv");
        let out = tokio::time::timeout(STEP_TIMEOUT, cmd.output())
            .await
            .map_err(|_| RuntimeError::Step {
                step: step_name.into(),
                code: None,
                stderr: "timed out".into(),
            })?
            .map_err(|e| RuntimeError::io(&spec.program, e))?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        for line in stderr.lines().take(200) {
            tracing::debug!(target: "uv", "{}", secmonk_safeio::scrub_text(line));
        }
        if !out.status.success() {
            let tail: Vec<&str> = stderr.lines().rev().take(20).collect();
            let tail: Vec<&str> = tail.into_iter().rev().collect();
            return Err(RuntimeError::Step {
                step: step_name.into(),
                code: out.status.code(),
                stderr: secmonk_safeio::scrub_text(&tail.join("\n")),
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

/// `uv 0.13.7 (abc123 2026-11-01)` -> `0.13.7`.
fn parse_uv_version(out: &str) -> Option<String> {
    let mut it = out.split_whitespace();
    (it.next()? == "uv").then(|| it.next().map(str::to_string))?
}

/// The first executable regular file called `name` in the directories of `path` (a `PATH` value). Relative
/// directories are skipped: a `PATH` entry that depends on the working directory is not trusted.
pub fn find_on_path(name: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|f| is_executable(f))
}

fn is_executable(f: &Path) -> bool {
    let Ok(md) = std::fs::metadata(f) else {
        return false;
    };
    if !md.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    true
}

/// Whether a module venv already records `python_version` with an interpreter that still exists: the interpreter
/// was installed by an earlier run, `uv python find` is not needed.
fn python_already_installed(layout: &Layout, python_version: &str) -> bool {
    let Ok(rd) = std::fs::read_dir(layout.venvs()) else {
        return false;
    };
    rd.flatten().any(|e| {
        let venv = e.path();
        let Ok(text) = std::fs::read_to_string(venv.join(".secmonk-install.json")) else {
            return false;
        };
        let Ok(m) = serde_json::from_str::<InstallMarker>(&text) else {
            return false;
        };
        let python = if cfg!(windows) {
            venv.join("Scripts").join("python.exe")
        } else {
            venv.join("bin").join("python")
        };
        m.python_version == python_version && python.exists()
    })
}

fn mkdir(p: &Path) -> RuntimeResult<()> {
    secmonk_config::layout::ensure_private_dir(p).map_err(|e| match e {
        secmonk_config::ConfigError::Io { path, source } => RuntimeError::Io { path, source },
        other => RuntimeError::io(p, std::io::Error::other(other.to_string())),
    })
}

fn write_private(path: &Path, data: &[u8]) -> RuntimeResult<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    use std::io::Write;
    o.open(path)
        .and_then(|mut f| f.write_all(data))
        .map_err(|e| RuntimeError::io(path, e))
}

#[async_trait]
impl PythonRuntime for UvRuntime {
    async fn ensure(&self) -> RuntimeResult<RuntimeInfo> {
        let uv = self.ensure_uv().await?;
        let v = &self.settings.python_version;
        if python_already_installed(self.layout(), v) {
            tracing::debug!(python = %v, "interpreter recorded by a module venv; skipping uv python find");
            return Ok(RuntimeInfo {
                uv_version: self
                    .uv_in_use()
                    .map_or_else(|| self.settings.uv_version.clone(), |u| u.version),
                uv,
                python_version: v.clone(),
            });
        }
        let find = self
            .run_uv(
                "uv python find",
                UvStep::Other,
                None,
                &["python".into(), "find".into(), v.into()],
            )
            .await;
        if find.is_err() {
            if self.settings.offline {
                return Err(RuntimeError::Offline(format!(
                    "Python {v} is not installed in data_dir"
                )));
            }
            self.run_uv(
                "uv python install",
                UvStep::PythonInstall,
                None,
                &["python".into(), "install".into(), v.into()],
            )
            .await?;
        }
        Ok(RuntimeInfo {
            uv_version: self
                .uv_in_use()
                .map_or_else(|| self.settings.uv_version.clone(), |u| u.version),
            uv,
            python_version: v.clone(),
        })
    }

    async fn ensure_env(&self, project: &Path, env: &str) -> RuntimeResult<EnvInfo> {
        let project = dunce::canonicalize(project).map_err(|e| RuntimeError::io(project, e))?;
        // Pinned: the real uv.lock and sources must match [modules.pins] before anything is installed.
        // Dev: nothing is compared, the hashes are recorded (a changed source re-syncs).
        let TreeDigest {
            lock_sha256,
            tree_sha256,
            ..
        } = self.verify_project(&project)?;
        self.projects
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(env.to_string(), project.clone());
        let venv = self.layout().venv(env);
        let python = self.venv_python(env);
        let editable = self.settings.trust == TrustMode::Dev;
        let marker = InstallMarker {
            uv_version: self.settings.uv_version.clone(),
            python_version: self.settings.python_version.clone(),
            lock_sha256: lock_sha256.clone(),
            tree_sha256: tree_sha256.clone(),
            project: project.to_string_lossy().into_owned(),
            editable,
            date: String::new(),
        };
        let marker_path = venv.join(".secmonk-install.json");
        if let Ok(text) = std::fs::read_to_string(&marker_path)
            && let Ok(old) = serde_json::from_str::<InstallMarker>(&text)
            && (InstallMarker {
                date: String::new(),
                ..old
            }) == marker
            && python.exists()
        {
            return Ok(EnvInfo {
                env: env.into(),
                venv,
                python,
                lock_sha256,
                tree_sha256,
                synced: false,
            });
        }
        mkdir(&self.layout().venvs())?;
        let mut args: Vec<OsString> = vec![
            "sync".into(),
            "--project".into(),
            project.clone().into(),
            "--frozen".into(),
            "--no-dev".into(),
        ];
        if self.settings.offline {
            args.push("--offline".into());
        }
        if !editable {
            args.push("--no-editable".into());
        }
        self.run_uv("uv sync", UvStep::Other, Some(&venv), &args)
            .await?;
        let marker = InstallMarker {
            date: secmonk_model::time::now_iso(),
            ..marker
        };
        write_private(
            &marker_path,
            &serde_json::to_vec_pretty(&marker).unwrap_or_default(),
        )?;
        Ok(EnvInfo {
            env: env.into(),
            venv,
            python,
            lock_sha256,
            tree_sha256,
            synced: true,
        })
    }

    fn command(&self, env: &str, entry: &[String]) -> RuntimeResult<LaunchSpec> {
        let spec = self.launch_spec(env, entry)?;
        Ok(LaunchSpec {
            env: module_env(self.layout(), &self.host_env),
            ..spec
        })
    }

    fn command_for(
        &self,
        env: &str,
        entry: &[String],
        capabilities: &[&str],
    ) -> RuntimeResult<LaunchSpec> {
        let spec = self.launch_spec(env, entry)?;
        Ok(LaunchSpec {
            env: module_env_for(self.layout(), capabilities, &self.host_env),
            ..spec
        })
    }
}

impl UvRuntime {
    /// [`verify_project_pins`] with this runtime's trust mode and pins.
    fn verify_project(&self, project: &Path) -> RuntimeResult<TreeDigest> {
        verify_project_pins(project, &self.settings.module_pins, self.settings.trust)
    }

    /// Program, args and cwd of a module start; in pinned mode the project of `env` is verified again first
    /// (sources changed after `ensure_env` refuse the start).
    fn launch_spec(&self, env: &str, entry: &[String]) -> RuntimeResult<LaunchSpec> {
        if self.settings.trust == TrustMode::Pinned {
            let project = self
                .projects
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(env)
                .cloned()
                .ok_or_else(|| {
                    RuntimeError::Integrity(format!(
                        "env {env} was not verified (ensure_env) before the module start"
                    ))
                })?;
            self.verify_project(&project)?;
        }
        let mut args: Vec<OsString> = vec!["-X".into()];
        let mut prefix = OsString::from("pycache_prefix=");
        prefix.push(self.layout().pycache());
        args.push(prefix);
        args.extend(entry.iter().map(OsString::from));
        Ok(LaunchSpec {
            program: self.venv_python(env),
            args,
            env: BTreeMap::new(),
            cwd: self.layout().tmp(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::asset_for;

    fn settings(root: &Path, archive: Option<PathBuf>, sha: Option<String>) -> UvSettings {
        let layout = Layout::new(root);
        layout.create().unwrap();
        let asset = asset_for("aarch64-apple-darwin");
        let mut uv_sha256 = BTreeMap::new();
        if let Some(s) = sha {
            uv_sha256.insert(asset.triple.to_string(), s);
        }
        UvSettings {
            layout,
            uv_version: "0.0.0-test".into(),
            uv_url: "https://invalid.invalid/{version}/{asset}".into(),
            uv_archive: archive,
            uv_sha256,
            python_version: "3.13".into(),
            offline: true,
            index_url: None,
            find_links: None,
            trust: TrustMode::Dev,
            module_pins: BTreeMap::new(),
            asset: Some(asset),
            uv_path: None,
            uv_any_version: false,
        }
    }

    fn fake_archive(dir: &Path) -> PathBuf {
        let a = dir.join("uv-aarch64-apple-darwin.tar.gz");
        std::fs::write(
            &a,
            crate::extract::tests::targz(&[
                (
                    "uv-aarch64-apple-darwin/uv",
                    b"fake-uv-binary",
                    tar::EntryType::Regular,
                ),
                (
                    "uv-aarch64-apple-darwin/uvx",
                    b"fake-uvx-binary",
                    tar::EntryType::Regular,
                ),
            ]),
        )
        .unwrap();
        a
    }

    #[tokio::test]
    async fn checksum_mismatch_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let root = d
            .path()
            .join("data")
            .canonicalize()
            .unwrap_or(d.path().join("data"));
        let a = fake_archive(d.path());
        let rt = UvRuntime::new(settings(&root, Some(a), Some("0".repeat(64))));
        let err = rt.ensure_uv().await.unwrap_err();
        assert!(
            matches!(err, RuntimeError::ChecksumMismatch { .. }),
            "{err}"
        );
        assert!(!rt.uv_path().exists());
        assert_eq!(
            std::fs::read_dir(rt.layout().downloads()).unwrap().count(),
            0,
            ".part removed"
        );
        assert!(!rt.layout().tools().join("uv-0.0.0-test.partial").exists());
    }

    #[tokio::test]
    async fn missing_checksum_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        let a = fake_archive(d.path());
        let rt = UvRuntime::new(settings(&d.path().join("data"), Some(a), None));
        assert!(matches!(
            rt.ensure_uv().await,
            Err(RuntimeError::NoChecksum(_))
        ));
    }

    #[tokio::test]
    async fn verified_install_from_local_archive() {
        let d = tempfile::tempdir().unwrap();
        let a = fake_archive(d.path());
        let sha = sha256_file(&a).unwrap();
        let rt = UvRuntime::new(settings(
            &d.path().join("data"),
            Some(a.clone()),
            Some(sha.clone()),
        ));
        let exe = rt.ensure_uv().await.unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"fake-uv-binary");
        let v: Verified = serde_json::from_str(
            &std::fs::read_to_string(exe.parent().unwrap().join("VERIFIED")).unwrap(),
        )
        .unwrap();
        assert_eq!(v.archive_sha256, sha);
        // second call: no fetch (archive gone), the verified copy is reused
        std::fs::remove_file(&a).unwrap();
        assert_eq!(rt.ensure_uv().await.unwrap(), exe);
        // a tampered binary is detected: the fast path is refused and uv is fetched again. With another
        // archive at the configured path the re-fetch fails with the checksum error ...
        std::fs::write(&exe, b"tampered").unwrap();
        std::fs::write(&a, b"not the pinned archive").unwrap();
        let err = rt.ensure_uv().await.unwrap_err();
        assert!(
            matches!(&err, RuntimeError::ChecksumMismatch { expected, .. } if *expected == sha),
            "{err}"
        );
        assert_eq!(
            std::fs::read(&exe).unwrap(),
            b"tampered",
            "nothing installed"
        );
        // ... and with the pinned archive back, the binary is restored
        std::fs::write(&a, std::fs::read(fake_archive(d.path())).unwrap()).unwrap();
        assert_eq!(rt.ensure_uv().await.unwrap(), exe);
        assert_eq!(std::fs::read(&exe).unwrap(), b"fake-uv-binary");
    }

    #[tokio::test]
    async fn changed_pin_is_not_served_by_the_fast_path() {
        // regression: a reused install ignored a changed [uv.sha256] pin
        let d = tempfile::tempdir().unwrap();
        let a = fake_archive(d.path());
        let sha = sha256_file(&a).unwrap();
        let root = d.path().join("data");
        let rt = UvRuntime::new(settings(&root, Some(a.clone()), Some(sha)));
        rt.ensure_uv().await.unwrap();
        let other = "ab".repeat(32);
        let rt2 = UvRuntime::new(settings(&root, Some(a), Some(other.clone())));
        let err = rt2.ensure_uv().await.unwrap_err();
        assert!(
            matches!(&err, RuntimeError::ChecksumMismatch { expected, .. } if *expected == other),
            "{err}"
        );
    }

    fn project(dir: &Path) -> PathBuf {
        let p = dir.join("project");
        crate::tree::tests::vector_tree(&p);
        p
    }

    fn pins_of(p: &Path) -> BTreeMap<String, ModulePin> {
        let d = crate::tree::module_digest(p).unwrap();
        BTreeMap::from([(
            "py-x".to_string(),
            ModulePin {
                lock_sha256: Some(d.lock_sha256),
                tree_sha256: Some(d.tree_sha256),
            },
        )])
    }

    #[tokio::test]
    async fn pinned_mode_refuses_a_changed_lock_before_uv_sync() {
        // regression: trust = "pinned" computed the lock hash but never compared it
        let d = tempfile::tempdir().unwrap();
        let p = project(d.path());
        let mut s = settings(&d.path().join("data"), None, None);
        s.trust = TrustMode::Pinned;
        s.module_pins = pins_of(&p);
        std::fs::write(p.join("uv.lock"), b"version = 1\n# changed\n").unwrap();
        let rt = UvRuntime::new(s.clone());
        let err = rt.ensure_env(&p, "secmonk-modules").await.unwrap_err();
        assert!(
            matches!(&err, RuntimeError::PinMismatch { what, .. } if what == "lock_sha256"),
            "{err}"
        );
        assert!(!rt.layout().venv("secmonk-modules").exists(), "no uv sync");
        // no pins at all in pinned mode: refused as well
        s.module_pins.clear();
        let err = UvRuntime::new(s)
            .ensure_env(&p, "secmonk-modules")
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeError::PinMismatch { .. }), "{err}");
    }

    /// A venv that looks installed (marker + interpreter), as `uv sync` would leave it.
    fn fake_install(rt: &UvRuntime, p: &Path, env: &str, trust: TrustMode) {
        let dig = crate::tree::module_digest(p).unwrap();
        let py = rt.venv_python(env);
        std::fs::create_dir_all(py.parent().unwrap()).unwrap();
        std::fs::write(&py, b"").unwrap();
        let m = InstallMarker {
            uv_version: rt.settings.uv_version.clone(),
            python_version: rt.settings.python_version.clone(),
            lock_sha256: dig.lock_sha256,
            tree_sha256: dig.tree_sha256,
            project: dunce::canonicalize(p)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            editable: trust == TrustMode::Dev,
            date: "x".into(),
        };
        write_private(
            &rt.layout().venv(env).join(".secmonk-install.json"),
            &serde_json::to_vec(&m).unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn pinned_mode_verifies_the_tree_before_every_start() {
        let d = tempfile::tempdir().unwrap();
        let p = project(d.path());
        let mut s = settings(&d.path().join("data"), None, None);
        s.trust = TrustMode::Pinned;
        s.module_pins = pins_of(&p);
        let rt = UvRuntime::new(s);
        let entry = vec!["-I".to_string()];
        // never ensured: refused
        assert!(matches!(
            rt.command("secmonk-modules", &entry),
            Err(RuntimeError::Integrity(_))
        ));
        fake_install(&rt, &p, "secmonk-modules", TrustMode::Pinned);
        let env = rt.ensure_env(&p, "secmonk-modules").await.unwrap();
        assert!(!env.synced);
        assert_eq!(
            env.tree_sha256,
            pins_of(&p)["py-x"].tree_sha256.clone().unwrap()
        );
        assert!(rt.command("secmonk-modules", &entry).is_ok());
        std::fs::write(p.join("src/pkg/mod.py"), b"print('changed')\n").unwrap();
        let err = rt
            .command_for("secmonk-modules", &entry, &["network"])
            .unwrap_err();
        assert!(
            matches!(&err, RuntimeError::PinMismatch { what, .. } if what == "tree_sha256"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn dev_mode_records_the_tree_and_resyncs_on_change() {
        let d = tempfile::tempdir().unwrap();
        let p = project(d.path());
        let rt = UvRuntime::new(settings(&d.path().join("data"), None, None));
        fake_install(&rt, &p, "secmonk-modules", TrustMode::Dev);
        let env = rt.ensure_env(&p, "secmonk-modules").await.unwrap();
        assert!(!env.synced, "marker with the same tree hash is reused");
        // a changed source no longer matches the marker: uv sync runs (and fails here: no uv binary)
        std::fs::write(p.join("src/pkg/mod.py"), b"print('changed')\n").unwrap();
        assert!(rt.ensure_env(&p, "secmonk-modules").await.is_err());
        // dev mode never refuses a start over hashes
        assert!(rt.command("secmonk-modules", &["-I".to_string()]).is_ok());
    }

    #[test]
    fn builtin_pins_apply_only_to_the_pinned_version() {
        let d = tempfile::tempdir().unwrap();
        let mut s = settings(d.path(), None, None);
        assert_eq!(s.expected_sha256("aarch64-apple-darwin"), None);
        s.uv_version = pins::UV_VERSION.into();
        assert_eq!(
            s.expected_sha256("aarch64-apple-darwin").as_deref(),
            pins::builtin_sha256("aarch64-apple-darwin")
        );
    }

    thread_local! {
        static TEST_PATH: std::cell::RefCell<Option<OsString>> = const { std::cell::RefCell::new(None) };
    }

    fn path_env(k: &str) -> Option<OsString> {
        (k == "PATH")
            .then(|| TEST_PATH.with(|p| p.borrow().clone()))
            .flatten()
    }

    /// An executable shell script at `dir/name` (written aside and renamed: no ETXTBSY with parallel tests).
    #[cfg(unix)]
    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).unwrap();
        let tmp = dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        let f = dir.join(name);
        std::fs::rename(&tmp, &f).unwrap();
        f
    }

    #[cfg(unix)]
    fn fake_uv(dir: &Path, version: &str) -> PathBuf {
        script(
            dir,
            "uv",
            &format!(
                "if [ \"$1\" = \"--version\" ]; then echo 'uv {version} (abc 2026-01-01)'; else exit 1; fi"
            ),
        )
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn configured_uv_path_is_used_without_download() {
        let d = tempfile::tempdir().unwrap();
        let uv = fake_uv(&d.path().join("bin"), "0.0.0-test");
        let mut s = settings(&d.path().join("data"), None, None);
        s.uv_path = Some(UvPath::File(uv.clone()));
        let rt = UvRuntime::new(s);
        assert_eq!(rt.uv_in_use(), None);
        assert_eq!(rt.ensure_uv().await.unwrap(), uv);
        assert_eq!(rt.uv_path(), uv);
        let u = rt.uv_in_use().unwrap();
        assert_eq!(
            (u.source, u.version.as_str()),
            (UvSource::Configured, "0.0.0-test")
        );
        // nothing managed: no uv-<version> directory, no VERIFIED, no checksum needed
        assert!(!rt.layout().uv_dir("0.0.0-test").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn configured_uv_of_another_version_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let uv = fake_uv(&d.path().join("bin"), "9.9.9");
        let mut s = settings(&d.path().join("data"), None, None);
        s.uv_path = Some(UvPath::File(uv.clone()));
        let rt = UvRuntime::new(s.clone());
        let err = rt.ensure_uv().await.unwrap_err();
        assert!(
            matches!(&err, RuntimeError::UvVersion { found, expected, .. }
                if found == "9.9.9" && expected == "0.0.0-test"),
            "{err}"
        );
        assert_eq!(rt.uv_in_use(), None);
        s.uv_any_version = true;
        let rt = UvRuntime::new(s);
        assert_eq!(rt.ensure_uv().await.unwrap(), uv);
        assert_eq!(rt.uv_in_use().unwrap().version, "9.9.9");
        // a missing file is an error, not a fallback
        let mut s = settings(&d.path().join("data2"), None, None);
        s.uv_path = Some(UvPath::File(d.path().join("nope")));
        assert!(matches!(
            UvRuntime::new(s).ensure_uv().await,
            Err(RuntimeError::Io { .. })
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn auto_uses_uv_on_path_when_the_version_matches() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("bin");
        let uv = fake_uv(&bin, "0.0.0-test");
        TEST_PATH.with(|p| *p.borrow_mut() = Some(bin.clone().into_os_string()));
        let mut s = settings(&d.path().join("data"), None, None);
        s.uv_path = Some(UvPath::Auto);
        let rt = UvRuntime::with_host_env(s, path_env);
        assert_eq!(rt.ensure_uv().await.unwrap(), uv);
        assert_eq!(rt.uv_in_use().unwrap().source, UvSource::Path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn auto_falls_back_to_the_managed_download() {
        let d = tempfile::tempdir().unwrap();
        let a = fake_archive(d.path());
        let sha = sha256_file(&a).unwrap();
        let bin = d.path().join("bin");
        // wrong version on PATH, then nothing on PATH: both end in the verified managed copy
        fake_uv(&bin, "9.9.9");
        for path in [bin.clone(), d.path().join("empty")] {
            TEST_PATH.with(|p| *p.borrow_mut() = Some(path.into_os_string()));
            let mut s = settings(&d.path().join("data"), Some(a.clone()), Some(sha.clone()));
            s.uv_path = Some(UvPath::Auto);
            let rt = UvRuntime::with_host_env(s, path_env);
            let exe = rt.ensure_uv().await.unwrap();
            assert_eq!(exe, rt.managed_uv_path());
            assert_eq!(rt.uv_in_use().unwrap().source, UvSource::Managed);
            assert!(exe.parent().unwrap().join("VERIFIED").is_file());
        }
    }

    #[cfg(unix)]
    #[test]
    fn path_lookup_skips_relative_and_non_executable_entries() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(a.join("uv"), b"#!/bin/sh\n").unwrap(); // not executable
        let good = fake_uv(&b, "1.0.0");
        let joined =
            std::env::join_paths([PathBuf::from("relative/dir"), a.clone(), b.clone()]).unwrap();
        assert_eq!(find_on_path("uv", &joined), Some(good));
        assert_eq!(find_on_path("uvx", &joined), None);
        assert_eq!(find_on_path("uv", std::ffi::OsStr::new("")), None);
    }

    #[test]
    fn uv_version_output_is_parsed() {
        assert_eq!(
            parse_uv_version("uv 0.13.7 (abc 2026-11-01)\n").as_deref(),
            Some("0.13.7")
        );
        assert_eq!(parse_uv_version("uv 0.13.7").as_deref(), Some("0.13.7"));
        assert_eq!(parse_uv_version("pip 24.0"), None);
        assert_eq!(parse_uv_version(""), None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ensure_skips_python_find_when_a_venv_records_the_interpreter() {
        let d = tempfile::tempdir().unwrap();
        let p = project(d.path());
        let log = d.path().join("calls.log");
        // every uv call is logged; `python find` and `python install` fail
        let uv = script(
            &d.path().join("bin"),
            "uv",
            &format!(
                "echo \"$@\" >> {}\nif [ \"$1\" = \"--version\" ]; then echo 'uv 0.0.0-test (x)'; else exit 1; fi",
                log.display()
            ),
        );
        let mut s = settings(&d.path().join("data"), None, None);
        s.uv_path = Some(UvPath::File(uv));
        let rt = UvRuntime::new(s);
        // no marker: `uv python find` runs and (offline) fails with the offline error
        assert!(matches!(rt.ensure().await, Err(RuntimeError::Offline(_))));
        assert!(
            std::fs::read_to_string(&log)
                .unwrap()
                .contains("python find")
        );
        std::fs::remove_file(&log).unwrap();
        // marker + interpreter: no uv python call at all
        fake_install(&rt, &p, "secmonk-modules", TrustMode::Dev);
        let info = rt.ensure().await.unwrap();
        assert_eq!(info.python_version, "3.13");
        assert!(!std::fs::read_to_string(&log).unwrap().contains("python"));
        // another python version in the marker does not count
        let mut s2 = rt.settings().clone();
        s2.python_version = "3.12".into();
        assert!(matches!(
            UvRuntime::new(s2).ensure().await,
            Err(RuntimeError::Offline(_))
        ));
    }

    #[test]
    fn uv_environment_follows_the_moved_directories() {
        let d = tempfile::tempdir().unwrap();
        let sh = d.path().join("shared");
        let mut s = settings(&d.path().join("data"), None, None);
        s.layout = Layout::with_moved(
            &d.path().join("data"),
            secmonk_config::MovedDirs {
                python: Some(sh.join("py")),
                uv_cache: Some(sh.join("uvc")),
                venvs: Some(sh.join("venvs")),
                cache: Some(sh.join("cache")),
                ..Default::default()
            },
        );
        let rt = UvRuntime::with_host_env(s, |_| None);
        let e = rt.uv_environment(UvStep::Other, Some(&sh.join("venvs/m")));
        assert_eq!(e["UV_PYTHON_INSTALL_DIR"], sh.join("py").into_os_string());
        assert_eq!(e["UV_CACHE_DIR"], sh.join("uvc").into_os_string());
        assert_eq!(e["UV_PYTHON_BIN_DIR"], sh.join("py/bin").into_os_string());
        assert_eq!(
            rt.venv_python("m").parent().unwrap().parent().unwrap(),
            sh.join("venvs/m")
        );
        let m = module_env(rt.layout(), &|_| None);
        assert_eq!(m["SECMONK_CACHE"], sh.join("cache").into_os_string());
    }

    #[test]
    fn launch_command_runs_the_venv_python() {
        let d = tempfile::tempdir().unwrap();
        let rt = UvRuntime::with_host_env(settings(d.path(), None, None), |k| {
            (k == "HOME").then(|| "/h".into())
        });
        let entry: Vec<String> = [
            "-I",
            "-m",
            "secmonk_modules",
            "serve",
            "py-probe",
            "--stdio",
        ]
        .map(String::from)
        .into();
        let spec = rt.command("secmonk-modules", &entry).unwrap();
        assert!(spec.program.ends_with(if cfg!(windows) {
            "Scripts/python.exe"
        } else {
            "bin/python"
        }));
        assert!(spec.program.starts_with(d.path()));
        assert_eq!(spec.args[0], "-X");
        assert!(
            spec.args[1]
                .to_string_lossy()
                .starts_with("pycache_prefix=")
        );
        assert_eq!(spec.args[2], "-I");
        assert_eq!(spec.env["HOME"], "/h");
        assert!(!spec.env.contains_key("UV_CACHE_DIR"));
    }
}
