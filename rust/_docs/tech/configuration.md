---
title: Configuration — sec-monk.toml, data_dir layout, pinned uv and its environment
summary: sec-monk.toml schema and lookup order, the real data_dir layout, start-up states, uv download/verify/install, the instance lock, the uv and module process environments, module integrity (pinned mode).
read_when: you change config loading, the data_dir layout, the uv download/verify/install steps or the environment of a module process, or set up a dev or offline machine
type: tech
context: tech
status: implemented
tags: [config, uv, python, data-dir, rust]
updated: 2026-11-11
verified: 2026-11-11
code: [rust/crates/secmonk-config/src/, rust/crates/secmonk-runtime/src/, rust/crates/secmonk-host/src/startup.rs]
fixtures: rust/crates/secmonk-runtime/tests/fixtures/
related: [decisions/0008-config-file-and-data-dir.md, decisions/0004-pinned-uv-in-data-dir.md, tech/architecture.md, tech/data-model.md]
---

# Configuration

The dev config is [`rust/sec-monk.toml`](../../sec-monk.toml). Decisions: config and data dir
[rust ADR-0008](../decisions/0008-config-file-and-data-dir.md), pinned uv [rust ADR-0004](../decisions/0004-pinned-uv-in-data-dir.md).

## Lookup order

1. `--config <file>` on the command line;
2. `SECMONK_CONFIG` (a file path);
3. `./sec-monk.toml` in the current directory, **in every build** (user decision 2026-11-11);
4. the per-user config file: macOS `~/Library/Application Support/sec-monk/sec-monk.toml`, Linux
   `$XDG_CONFIG_HOME/sec-monk/sec-monk.toml` (`~/.config/…`), Windows `%APPDATA%\sec-monk\sec-monk.toml`;
5. none: built-in defaults.

The first file found wins; files are not merged. The app logs which file it uses. A config file decides which code
runs (modules, uv URL) and where state goes, so a file found in steps 2–4 is opened **once**, without following a
final symlink and without blocking (`O_NOFOLLOW | O_NONBLOCK`), checked on that handle (`fstat`) and read from the
same handle (`secmonk_config::read_config`; no check-then-reopen window). It is refused when it is a symlink, not a
regular file, replaced between lookup and open, not owned by the current user, writable by group/others, larger
than 1 MiB, or when its directory is writable by group/others without the sticky bit (POSIX). `--config` is the
user's explicit choice: it must exist, may be a symlink and is not ownership-checked.

**Windows**: the check is "regular file, not a reparse point" (opened with `FILE_FLAG_OPEN_REPARSE_POINT`); owner
and ACLs are **not** checked. The per-user profile ACLs of `%APPDATA%` are the protection; `SECMONK_CONFIG` pointing
into a shared directory is not detected (documented limitation, **verify** on Windows).

**Step 3 runs in every build** (rust ADR-0008 amendment, 2026-11-11, user decision; it replaces the earlier dev-only
rule, and `SECMONK_DEV` no longer exists). It passes the same single-open checks as steps 2 and 4: no final symlink,
`fstat` on the same handle, owner and mode, and a group/other-writable directory is refused. Residual risk: a
`sec-monk.toml` in a cloned repository is owned by you and passes these checks, and it chooses the modules and the uv
URL, so **start sec-monk only from directories you trust** (or pass `--config`). `cd rust && cargo tauri dev` finds
`rust/sec-monk.toml`, whose `data_dir = "_data"` decides where everything goes. A well-known config for general
settings is on the [backlog](../plans/backlog.md).

**Unknown keys are refused** (every section is `deny_unknown_fields`; `[modules.<name>]` tables accept only the
override keys): the file decides which code runs, a silently ignored typo is worse than an error. New keys are added
in `secmonk-config`. `SECMONK_STATIC` overrides `ui.static_dir` in the loaded config; the window honours it in debug builds
only (a release build serves the bundled copy), the headless server always serves what `ui.static_dir` says. The API: `secmonk_config::load(&LoadOptions)`
(`LoadOptions::from_env(cli_config)` reads the process environment; tests build it by hand) returns a `Config` with
absolute paths; [architecture § Crate APIs](architecture.md#crate-apis).

**Relative paths** in the file (`data_dir`, `modules.python_project`, `ui.static_dir`, `uv.archive`) resolve
against the directory of the config file, never the current directory. `~` expands to the user's home. The resolved
`data_dir` is canonicalized to an absolute path before anything uses it (`secmonk_config::canonical`, `dunce`: on
Windows no `\\?\` prefix, which would break the `sqlite://` / `file:` URIs, the uv variables and working
directories; `strip_verbatim` removes it from strings built elsewhere, and the Python side strips it again before
building a `file:` URI, `secmonk_modules.db.plain_path`).
**Default `data_dir`** (unset): macOS `~/Library/Application Support/sec-monk`, Linux `$XDG_DATA_HOME/sec-monk`
(`~/.local/share/sec-monk`), Windows `%LOCALAPPDATA%\sec-monk`. All differ from the Python version's
`~/.local/share/secmonk` / `%LOCALAPPDATA%\secmonk` and its `secmonk.db`, so both run side by side.

**No config file at all** means the built-in defaults, and an absent `[modules] enabled` means the four shipped modules
(`DEFAULT_MODULES` in `secmonk-config`: `py-engine`, `py-procmon`, `py-probe`, `py-sources`). `enabled = []` means none:
the host then fails the start ("py-engine is not enabled").

## Schema

| Key | Type, default | Meaning |
|---|---|---|
| `config_version` | int, `1` | Format version of this file; an unknown major is refused. |
| `data_dir` | path, per-user | Everything the app and uv write (layout below). Created 0700. |
| `[database] backend` | `"sqlite"` | `postgres`, `mysql` later. |
| `[database] state`, `mirror` | URL, `sqlite://{data_dir}/db/state.sqlite3`, `…/mirror.sqlite3` | `{data_dir}` is substituted. Two URLs so the mirror can stay SQLite when state moves ([data-model](data-model.md) R1). |
| `[python] version` | string, `"3.13"` | Interpreter for module venvs (python-build-standalone via uv). `3.13` is a minor selector: uv picked `cpython-3.13.18` on 2026-11-11; whether a given uv version always resolves it to the same build is unverified **(verify)**. |
| `[python] offline` | bool, `false` | No download of any kind: uv from `uv.archive` or already in `tools/`, `UV_OFFLINE=1`, `UV_PYTHON_DOWNLOADS=never`, packages from `python.find_links`. |
| `[python] find_links` | path, unset | Wheel directory for offline installs. |
| `[python] index_url` | URL, unset | Package index (else uv's default, PyPI). |
| `[uv] version` | string, built-in pin | Pinned uv release; overrides the pin compiled into `secmonk-runtime` (0.13.7). |
| `[uv] url` | template | `https://github.com/astral-sh/uv/releases/download/{version}/{asset}` |
| `[uv] archive` | path, unset | A local copy of the release archive (offline machines); verified like a download. |
| `[uv.sha256]` | table target → hex, built-in pins | sha256 of each release archive; required whenever `[uv] version` differs from the built-in pin; a target without a checksum cannot download (fail closed). |
| `[modules] python_project` | path, `"python"` | The uv project of the Python modules (`rust/python`). |
| `[modules] enabled` | list of names, the four shipped modules when absent | Modules that may run; anything else is never installed or started. `enabled = []` enables none. `py-engine` is required by the engine. |
| `[modules] trust` | `"dev"` \| `"pinned"` | `dev`: the project is installed editable from the repo; hashes are recorded, not compared. `pinned`: the `uv.lock` and source tree on disk must match `[modules.pins]` (and the manifest `integrity`) before install and before every start ([Module integrity](#module-integrity)). Pinned mode does not refuse at startup by itself: it needs a pin per enabled module and each module's launch entry must be exactly `-I -m secmonk_modules serve --stdio --module <name>` (`registry::fixed_entry`); the runtime verifies the lock and tree hash. |
| `[modules.pins]` | table name → sha256 | `lock_sha256` / `tree_sha256` per module (pinned mode); print them with `uv run python scripts/pins.py` in `rust/python`. |
| `[modules.<name>]` | table | Overrides of manifest `limits` / `lifecycle` (never `capabilities`). |
| `[ui] static_dir` | path, `"../src/secmonk/web/static"` | The current UI, served in place (resolved against the config file's directory). Release windows ignore it and serve the bundled copy. |
| `[ui] scheme` | string, `"secmonk"` | Custom scheme name. |
| `[ui] snapshot` | path, unset | Process monitor on a snapshot file (`secmonk ui --snapshot`). |
| `[ui] http_listen` | `"host:port"`, unset | Optional dev HTTP binding of the same router (off by default; loopback; Host check, actions only on loopback). |
| `[ui] devtools` | bool, `false` | Webview developer tools; only honoured in debug builds. |
| `[engine] min_confidence` | float, `0.5` | As `secmonk ui`. |
| `[sources] nvd_api_key_env` | string, `"NVD_API_KEY"` | Environment variable the host reads; the key travels in `source.sync` `secrets`, never in a module's environment or a log. |
| `[log] level`, `keep_days` | `"info"`, `7` | `tracing` filter (`RUST_LOG` wins); log files older than `keep_days` are deleted at start. |

## Data directory layout

The directories below are created at start by `Layout::create()` (`secmonk-config/src/layout.rs`), 0700. `rust/_data/`
after a first run on macOS arm64 (2026-11-11) holds exactly: `cache db jobs logs modules pycache python python-home run
tmp tools uv-cache uv-home uv-tools venvs`.

| Path | Written by | Content |
|---|---|---|
| `db/state.sqlite3`, `db/mirror.sqlite3` (+ wal/shm) | host store | schema v3 ([data-model](data-model.md)) |
| `tools/downloads/` | host | partial downloads (`*.part`), deleted after verification |
| `tools/uv-<version>/` | host | `uv`, `uvx` (`.exe` on Windows), `VERIFIED` (JSON: version, asset, archive sha256, binary sha256, date; the binary hash is re-checked at every start, a mismatch re-fetches); `uv-<version>.partial/` while extracting |
| `python/`, `python/bin/` | uv | `UV_PYTHON_INSTALL_DIR`: python-build-standalone interpreters (`cpython-3.13...`); `UV_PYTHON_BIN_DIR` (stays empty with `UV_PYTHON_INSTALL_BIN=0`) |
| `pycache/` | Python | `-X pycache_prefix`: bytecode, mirrored under the absolute path of the source (`pycache/Users/...`) |
| `webview/` | webview | **not part of `Layout::create()`**: the window creates it (0700) on Windows and Linux for the WebView2 / WebKitGTK data directory; absent on macOS and in the headless build. On macOS WKWebView writes `~/Library/WebKit/<id>` and `~/Library/Caches/<id>` instead (known exception, [on-macos](../plans/on-macos.md)) |
| `uv-cache/` | uv | `UV_CACHE_DIR` |
| `uv-tools/`, `uv-tools/bin/` | uv | `UV_TOOL_DIR`, `UV_TOOL_BIN_DIR` (unused; set so nothing lands in `~/.local`) |
| `uv-home/` | uv (must stay empty of files) | `HOME` (`uv-home/home`), `XDG_CACHE_HOME`, `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_BIN_HOME`, `APPDATA`, `LOCALAPPDATA` of uv steps: one empty subdirectory each (`home`, `xdg-*`, `appdata`, `localappdata`); a sentinel, any file appearing here is a bug (`uv_audit` checks it) |
| `venvs/<env>/` | uv | `UV_PROJECT_ENVIRONMENT` of each module env (prototype: `venvs/secmonk-modules/`) + `.secmonk-install.json` (uv version, python version, lock sha256, tree sha256, project path, editable, date) |
| `modules/<name>/` | module | module-owned files (`py-sources/staging.sqlite3`); the host passes the path as `session.settings.module_dir` in its `hello` |
| `python-home/` | Python modules | `SECMONK_HOME` of modules: the `secmonk` package's own data dir (must hold no `secmonk.db`; empty after a first run) |
| `cache/secmonk/` | Python modules | `SECMONK_CACHE`: cvelist git clone, image blobs |
| `logs/` | host | `secmonk-desktop.log.<date>` (host and module lines). `logs/modules/` is created but unused: per-module files do not exist yet |
| `jobs/` | (host, later) | created, unused: planned per-job scratch |
| `tmp/` | host, uv, modules | `TMPDIR` / `TEMP` / `TMP` of child processes (uv leaves its lock file here) |
| `run/` | host | `run/instance.lock`: an exclusive, non-blocking lock (`File::try_lock`), mode 0600, holding the PID of the running instance. A second instance on the same `data_dir` gets `HostError::InstanceRunning`; the API then answers 503 "another sec-monk instance is already running on …" |

Directories are 0700 and files 0600 on POSIX, owned by the current user, symlinks refused (the rule of
`secmonk/paths.py` `ensure_private_dir`); on Windows the per-user profile ACLs apply and the app does not check them **(verify)**.

## uv: download, verify, install

Proven by the W1.2 spike on macOS arm64 (2026-11-11, uv 0.13.7, Python 3.13): uv download ~4 s, `uv python install`
6–8 s, first `uv sync` ~4 s, a warm run 27 ms; with the environment below a filesystem audit found **no write outside
`data_dir`** once `TMPDIR` pointed inside it (uv leaves a lock file in `TMPDIR`). Windows and Linux were not run. The first headless start
of 2026-11-11 (`rust/_data`, uv 0.13.7) took 38 s to ready: uv 5 s, `python find` + `python install` 6 s, `uv sync` 25 s (it builds
the `secmonk` path dependency); later starts re-run `uv python find` and are ready after about 2 s.

| Step | What the host does |
|---|---|
| 0 Paths | Canonicalize `data_dir` to an **absolute** path first. With a relative one, uv builds the path dependency with its working directory in the repo and a relative pycache prefix wrote into the repo (found by the spike). |
| 1 Pick the asset | Target triple from the running OS/arch and libc (Linux: musl when `/lib/ld-musl-*` exists and no *real* glibc loader / `libc.so.6` does, or when the host binary itself is musl; a glibc name that resolves to musl's loader or to `libgcompat`, as Alpine's `gcompat` installs it, does not count): `uv-<triple>.tar.gz` (macOS, Linux gnu or musl), `uv-<triple>.zip` on Windows (flat, `uv.exe` at the root) ([architecture § platform matrix](architecture.md#8-platform-matrix)). Each asset has a sibling `<asset>.sha256`; the release also has a combined `sha256.sum`. |
| 2 Download | Skip if `tools/uv-<v>/VERIFIED` exists, records the current pin (version, asset, archive sha256: a changed `[uv]` pin re-fetches) and the binary hash matches. Else fetch `url` (HTTPS only, rustls) or copy `archive` to `tools/downloads/<asset>.part`, hashing while writing, at most 512 MiB. Offline without `archive` fails with a clear message. |
| 3 Verify | sha256 of the archive must equal the pin. Pins (version + sha256 per target) are **compiled into `secmonk-runtime`** (`pins.rs`); `[uv.sha256]` in the config overrides them per target; with another `[uv] version` the compiled pins no longer apply and a missing config checksum fails closed. Mismatch → delete the `.part`, error, no retry loop (tested on a local fake archive). |
| 4 Extract | Only the expected entries (`uv`, `uvx` / `uv.exe`, `uvx.exe`) at depth ≤ 2, file names only (no directories from the archive), regular files (links skipped), 256 MiB per entry, at most 64 entries, written with `create_new` into a fresh `tools/uv-<v>.partial/`, then `VERIFIED`, then rename into place; mode 0700. An entry with `..` or an absolute path refuses the whole archive (tested: tar and zip). |
| 5 Python | `uv python find <version>` (downloads `never`); when it fails, `uv python install <version>` with `UV_PYTHON_DOWNLOADS=automatic` for this step only (offline: a clear error instead). |
| 6 Env | `uv sync --project <python_project> --frozen --no-dev` (+ `--offline` offline, `--no-editable` in pinned mode), `UV_PROJECT_ENVIRONMENT=venvs/<env>`. `uv.lock` is committed and `--frozen` is always used. Before it, the project is hashed and, in pinned mode, compared with the pins (a mismatch stops here, nothing is installed). Skipped when `.secmonk-install.json` matches (uv version, python version, lock sha256, tree sha256: in dev a changed source re-syncs). |
| 7 Launch | Not through uv: exec `venvs/<env>/bin/python` (Windows `Scripts\python.exe`) with `-X pycache_prefix=<data_dir>/pycache` followed by the manifest `entry` (`-I -m secmonk_modules serve --stdio --module <name>`); `-X` works under `-I`, unlike `PYTHONPYCACHEPREFIX`. Working directory `<data_dir>/tmp`. `uv run` would stay as a parent process, so killing the worker would leave Python running (found by the spike). `-I` ignores `PYTHON*` variables, the user site and the current directory. |

Every uv step runs with `env_clear()` and exactly these variables (the spike's proven set):

| Variable | Value | Purpose |
|---|---|---|
| `UV_CACHE_DIR` | `{data_dir}/uv-cache` | cache |
| `UV_PYTHON_INSTALL_DIR` | `{data_dir}/python` | interpreters |
| `UV_PYTHON_BIN_DIR` | `{data_dir}/python/bin` | interpreter executables |
| `UV_PYTHON_INSTALL_BIN` | `0` | no `python3.x` executables in a bin dir |
| `UV_PYTHON_INSTALL_REGISTRY` | `0` | Windows: no PEP 514 registration in `HKCU\Software\Python` (from the docs; Windows not run) |
| `UV_TOOL_DIR`, `UV_TOOL_BIN_DIR` | `{data_dir}/uv-tools`, `{data_dir}/uv-tools/bin` | tools (unused) |
| `UV_PROJECT_ENVIRONMENT` | `{data_dir}/venvs/<env>` | the module venv |
| `UV_NO_CONFIG` | `1` | ignore `uv.toml` from user or system dirs: **necessary**, the spike machine has a real `~/.config/uv` |
| `UV_NO_ENV_FILE` | `1` | ignore `.env` files |
| `UV_NO_PROGRESS` | `1` | plain output for the job log |
| `UV_PYTHON_PREFERENCE` | `only-managed` | never a system or user Python. Do **not** also set `UV_MANAGED_PYTHON`: it conflicts with this one. |
| `UV_PYTHON_DOWNLOADS` | `automatic` during step 5, then `never` | no implicit interpreter downloads |
| `UV_PYTHON` | `[python] version` | the pinned interpreter |
| `UV_LINK_MODE` | `copy` (optional) | venvs do not share inodes with the cache |
| `UV_OFFLINE` | `1` when offline | no network |
| `UV_INDEX_URL` / `UV_FIND_LINKS` | from `[python]` when set | package source |
| `PYTHONPYCACHEPREFIX` | `{data_dir}/pycache` (absolute) | bytecode never next to the sources (the repo) |
| `PIP_CONFIG_FILE` | `/dev/null` (`NUL` on Windows) | no pip config from the user |
| `HOME`, `USERPROFILE`, `XDG_CACHE_HOME`, `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_BIN_HOME` | dirs under `{data_dir}/uv-home/` | sentinel: catches any default path; must stay empty |
| `APPDATA`, `LOCALAPPDATA` | dirs under `{data_dir}\uv-home\` | same on Windows **(verify: uv starts with them redirected)** |
| `TMPDIR`, `TEMP`, `TMP` | `{data_dir}/tmp` | uv's lock file lands here (the one leak the spike found otherwise) |
| `PATH` (+ `SystemRoot` on Windows) | `/usr/bin:/bin:/usr/sbin:/sbin`; Windows `%SystemRoot%\System32;%SystemRoot%;%SystemRoot%\System32\Wbem` | nothing else is inherited |
| `SSL_CERT_FILE`, `SSL_CERT_DIR`, `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, `ALL_PROXY` (and lowercase forms) | passed through when set | corporate networks (not part of the spike's set) |

**Audit** (`secmonk-runtime/tests/uv_audit.rs`, ignored by default; run on 2026-11-11, macOS arm64, uv 0.13.7,
Python 3.13): download + verify + `uv python install` 12.7 s, `uv lock` + `uv sync --frozen` of a fixture project
(`uv_build`, editable) 34 ms, launch through `command()` ok; afterwards `uv-home/` held no file, the project directory
held only the expected `uv.lock`, `~/.cache/uv`, `~/.local/share/uv`, `~/.local/bin`, `~/.config/uv`,
`~/Library/Caches/uv`, `~/Library/Application Support/uv` had no file newer than the test start, and the real temp
directory had no new uv entry. `data_dir` use: tools 28 MB, python 64 MB.

Pitfalls: a `noexec` mount for `data_dir` breaks the managed Python (Linux, from the spike notes, not run; the app does not detect it yet);
Windows `MAX_PATH` limits deep venv paths, so keep `data_dir` short; SmartScreen may flag the unsigned `uv.exe`.

## Start-up states

What the first minutes look like (code: `secmonk-host/src/startup.rs`, `gate.rs`;
[architecture §3](architecture.md#3-composition-secmonk-host-and-the-desktop-app)). The host runs five phases, in
order: `Uv` (download, verify), `Python`, `ModuleEnv` (`uv sync --frozen`), `Databases`, `Modules`. While they run,
`/api/meta` answers with `engine.schema = "preparing"` and `engine.step`, and every other route answers 503 "sec-monk is
preparing its Python runtime (step N of 5: ...)". A failure (offline without `uv.archive`, a checksum or pin mismatch, a
missing `py-engine`) ends in `failed`: 503 "sec-monk could not start: <reason>" with a hint to the logs. The host does not
retry; restart the app. With `[python] offline = true` the phases that would download fail with a message instead.

## Module integrity

`trust = "pinned"` checks the module code on disk, not only the manifest (`secmonk-runtime/src/tree.rs`):

- `lock_sha256`: sha256 of `<python_project>/uv.lock`.
- `tree_sha256` (`secmonk-tree/1`): `pyproject.toml` plus every regular file below `src/`, skipping directories
  `__pycache__`, `.venv`, `.git`, `.pytest_cache`, `.ruff_cache`, `.mypy_cache`, `.tox`, `node_modules` and files
  `*.pyc`, `*.pyo`, `.DS_Store`, `Thumbs.db`; for each file, sorted by relative path (`/`, byte order), the line
  `<sha256 of content>  <path>\n` (`sha256sum` format); the hash of all lines. Manifests (`modules/`), tests and
  scripts are outside the tree (manifests carry the pins). A symlink or special file in the tree, more than 50 000
  files or a file above 64 MiB is an error. Line endings count: a Windows checkout with `autocrlf` hashes
  differently. `rust/python/scripts/pins.py` implements the same algorithm and prints a `[modules.pins]` block;
  a shared test vector keeps the two equal.
- When: `ensure_env` hashes before `uv sync` (pinned: every enabled module's pin must match, a missing pin is
  refused; nothing is installed on a mismatch); `command` / `command_for` hash the project of the env again before
  every module start (pinned: a source changed after install refuses the start; an env never ensured is refused).
  Dev: nothing is compared; both hashes go into `.secmonk-install.json`.
- Not covered: the `secmonk` package the project depends on by path (`../..`, installed non-editable in pinned
  mode) and the venv contents themselves (backlog). Manifests carry no integrity either: pinned mode needs the
  `[modules.pins]` block that `scripts/pins.py` prints (backlog).

Public API (`secmonk_runtime`), for the module registry:

```rust
pub struct TreeDigest { pub lock_sha256: String, pub tree_sha256: String, pub files: usize }
pub fn module_digest(project: &Path) -> RuntimeResult<TreeDigest>;
pub fn verify_module_tree(project: &Path, module: &str, pin: Option<&ModulePin>, trust: TrustMode)
    -> RuntimeResult<TreeDigest>;          // pinned: RuntimeError::PinMismatch { module, what, expected, actual }
pub fn verify_project_pins(project: &Path, pins: &BTreeMap<String, ModulePin>, trust: TrustMode)
    -> RuntimeResult<TreeDigest>;
```

`UvSettings::module_pins` holds the pins of the enabled modules (`from_config`); `EnvInfo` carries `tree_sha256`.

## Module process environment

Module processes are not uv processes: they need the real user context (collectors read `~/.ssh`, `~/.kube`,
Homebrew, `/Applications`). `env_clear()`, then, **scoped by the manifest capabilities**
(`PythonRuntime::command_for(env, entry, capabilities)`, `env::module_env_for`; `command` without capabilities
passes every group and is kept for compatibility):

| Variable | Value |
|---|---|
| `HOME` / `USERPROFILE`, `USER`, `LOGNAME`, `USERNAME`, `LANG`, `LC_*`, `PATH`, `XDG_RUNTIME_DIR`, Windows system variables | every module (`MODULE_BASE`) |
| `SSH_AUTH_SOCK`, `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`, `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`, `KUBECONFIG` | only with `read-target` (py-probe) (`MODULE_TARGET_VARS`) |
| `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, proxy variables (both cases) | only with `network` (py-sources, py-probe) (`MODULE_NETWORK_VARS`) |
| `SECMONK_HOME` | `{data_dir}/python-home` |
| `SECMONK_CACHE` | `{data_dir}/cache/secmonk` |
| `SECMONK_DB` | `{data_dir}/python-home/forbidden.db`: a conformance test asserts it never appears |
| `TMPDIR` / `TEMP` / `TMP` | `{data_dir}/tmp` |
| `PYTHONPYCACHEPREFIX` | `{data_dir}/pycache` (informational: `-I` ignores it; the effective setting is the `-X pycache_prefix=` argument of step 7) |
| `PYTHONUTF8` | `1` (informational under `-I`; the server sets UTF-8 itself) |
| unbuffered stderr, UTF-8 | set by the server at startup (`-I` ignores `PYTHONUNBUFFERED`, `PYTHONIOENCODING`) |
| secrets (`NVD_API_KEY`) | **never**: passed in `source.sync` `secrets` |

## Example

```toml
config_version = 1
data_dir = "_data"

[uv]
version = "0.13.7"
url = "https://github.com/astral-sh/uv/releases/download/{version}/{asset}"

[uv.sha256]
aarch64-apple-darwin = "81b811b5…"   # full values in rust/sec-monk.toml
```

The full dev file with all eight checksums is [`rust/sec-monk.toml`](../../sec-monk.toml); they repeat the pins
compiled into `secmonk-runtime` and were copied from the `.sha256` files of the uv 0.13.7 GitHub release on 2026-11-11.
Check them against the release's `sha256.sum` and GitHub attestations before the first release build **(verify)**.

## Rationale

Linking uv as Rust crates instead of shelling out is a later option behind the same `PythonRuntime` trait; not designed
for now ([rust ADR-0004](../decisions/0004-pinned-uv-in-data-dir.md)).
