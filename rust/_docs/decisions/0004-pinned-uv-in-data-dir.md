---
title: ADR-0004 — Python runtime = pinned uv downloaded into data_dir, everything uv writes stays there
summary: A pinned uv is downloaded into data_dir/tools, sha256-verified, and every uv step runs with variables that keep cache, interpreters, venvs and tools inside data_dir; uv crates are a later option.
read_when: you change how Python modules are installed or launched, upgrade uv or Python, or investigate files written outside data_dir
type: decision
context: decisions
status: accepted
tags: [uv, python, runtime, security, decision]
updated: 2026-11-11
verified: 2026-11-11
related: [tech/configuration.md, decisions/0008-config-file-and-data-dir.md]
---

# ADR-0004 — Pinned uv in data_dir

## Context

User direction 2026-11-11 (A2): the Python runtime is uv, pinned; downloaded at app start into
`<data_dir>/tools/uv-<version>/` with sha256 verification; everything uv writes stays inside `data_dir` (binary,
cache, python-build-standalone interpreters, venvs, tool dirs); nothing in `~/.cache/uv`, `~/.local/share/uv` or a
user/system uv config. The proposal (§9.2) recommended the pinned binary over linking uv's crates.

## Decision

- `PythonRuntime` trait (`ensure() -> RuntimeInfo`, `ensure_env(project, env)`, `command(env, entry) -> Command`);
  implementation `UvRuntime`.
- Version and per-target sha256 are **pinned in code** (`secmonk-runtime`: uv 0.13.7, 2026-11-11), the config `[uv]`
  may override them; download → verify → extract allowlisted file names into `.partial` → rename into place; fail
  closed on a missing or wrong checksum. Python 3.13 from python-build-standalone via `uv python install`.
- uv steps run with a cleared environment plus the variables of
  [configuration § uv](../tech/configuration.md#uv-download-verify-install) (`UV_CACHE_DIR`, `UV_PYTHON_INSTALL_DIR`,
  `UV_PYTHON_BIN_DIR`, `UV_TOOL_DIR`, `UV_TOOL_BIN_DIR`, `UV_PROJECT_ENVIRONMENT`, `UV_NO_CONFIG`,
  `UV_PYTHON_PREFERENCE=only-managed`, `UV_PYTHON_DOWNLOADS`, `UV_LINK_MODE`, …) and a sentinel HOME/XDG/APPDATA
  that must stay empty, `TMPDIR` inside `data_dir`, `PYTHONPYCACHEPREFIX`, `PIP_CONFIG_FILE` to the null device;
  `data_dir` canonicalized to an absolute path; `UV_MANAGED_PYTHON` never set (it conflicts with
  `UV_PYTHON_PREFERENCE`). The W1.2 spike's audit on macOS arm64 found no write outside `data_dir` with this set;
  Windows and Linux audits are plan items.
- `uv sync --frozen` once (lock committed), then modules run from the venv interpreter with `-I`, not through
  `uv run`: `uv run` stays as a parent process, so killing it would leave Python running (found by the spike).
- Later option, not designed for: link uv's crates (`uv-resolver`, `uv-installer`, …) behind the same trait; their API
  is not stable and the dependency tree is large.

## Consequences

- ~40 MB uv + ~60–100 MB interpreter + packages in `data_dir` **(verify)**; first start needs the network unless an
  offline archive and wheel directory are configured. Measured on macOS arm64: download ~4 s, Python install 6–8 s,
  first sync ~4 s, warm start 27 ms.
- Upgrading uv is a config change (version + 8 checksums), tested by the audit.
- The checksums trust GitHub release sidecars; release builds should also check GitHub attestations **(verify)**.

## Implementation notes (2026-11-11, W2.1)

- `secmonk-runtime`: `PythonRuntime { ensure, ensure_env(project, env), command(env, entry) -> LaunchSpec }`,
  `UvRuntime` with the pins of uv 0.13.7 compiled in (`pins.rs`); `LaunchSpec::to_command()` applies `env_clear`,
  `kill_on_drop` and `CREATE_NO_WINDOW` on Windows.
- Launch adds `-X pycache_prefix=<data_dir>/pycache` before the manifest entry: `-I` ignores
  `PYTHONPYCACHEPREFIX`, `-X` is honoured.
- `uv_audit` (ignored test, real network) passed on macOS arm64: no file outside `data_dir`, sentinel home empty
  ([configuration](../tech/configuration.md#uv-download-verify-install)). Linux and Windows audits remain plan items.

## Implementation notes (2026-11-11, W3.4: review fixes)

- `trust = "pinned"` now verifies the disk: before `uv sync` the real `uv.lock` sha256 and the `secmonk-tree/1`
  hash of the sources must equal `[modules.pins]` of every enabled module, and the project is hashed again before
  every module start (`command` / `command_for`). Public API: `secmonk_runtime::verify_module_tree`,
  `verify_project_pins`, `module_digest` ([configuration § Module integrity](../tech/configuration.md#module-integrity)).
  `dev` mode compares nothing but records both hashes in `.secmonk-install.json`, so a changed source re-syncs.
- The uv fast path also compares the recorded version, asset and archive sha256 with the current pin: a changed pin
  re-fetches.
- The module environment is scoped by manifest capabilities (`PythonRuntime::command_for`,
  `env::module_env_for`): ssh/Docker/Kubernetes variables only with `read-target`, proxy/CA variables only with
  `network`.
- Linux libc detection ignores glibc names that resolve to musl's loader or gcompat (Alpine + `gcompat` gets the
  musl uv build).

## Implementation notes (2026-11-11, W4.2)

- Sizes measured on macOS arm64 (uv 0.13.7, Python 3.13): `tools/` 28 MB, `python/` 64 MB
  ([configuration](../tech/configuration.md#uv-download-verify-install)). The first headless start took 38 s, 25 s of it
  `uv sync`.
- `Host::start` drives the runtime in two phases, `ensure_uv` then `ensure` and `ensure_env` per module env, and reports
  each as a startup phase while the API answers 503 "preparing" (`secmonk-host`).
- Not covered by pinned mode: the `secmonk` path-dependency package and the venv contents (backlog).
