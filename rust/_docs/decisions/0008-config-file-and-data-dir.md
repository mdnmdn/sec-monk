---
title: ADR-0008 — sec-monk.toml and data_dir
summary: One TOML config (--config, SECMONK_CONFIG, ./sec-monk.toml in every build, per-user file); data_dir holds everything written, separate from the Python version.
read_when: you change config lookup, data_dir defaults or the layout, or run both versions side by side
type: decision
context: decisions
status: accepted
tags: [config, data-dir, decision]
updated: 2026-11-11
verified: 2026-11-11
related: [tech/configuration.md, decisions/0004-pinned-uv-in-data-dir.md]
---

# ADR-0008 — sec-monk.toml and data_dir

## Context

User direction 2026-11-11: `sec-monk.toml` defines `data_dir`; in dev `_data/`, gitignored; lookup `--config`,
`SECMONK_CONFIG`, `./sec-monk.toml`, per-user config dir; per-user `data_dir` when unset. The Python version's rule
(Python ADR-0006) is "state is never CWD-relative".

## Decision

- Lookup order as above; first file wins, no merging; relative paths resolve against the config file's directory.
- `data_dir` default per user (`~/Library/Application Support/sec-monk`, `$XDG_DATA_HOME/sec-monk`,
  `%LOCALAPPDATA%\sec-monk`), different from the Python version's directories and file names.
- Layout and permissions of [configuration](../tech/configuration.md#data-directory-layout); dev config `rust/sec-monk.toml`
  with `data_dir = "_data"`.
- Because the config decides which code runs (modules, uv URL), a config file not owned by the user or writable by
  others is refused, and the chosen file is logged.

## Consequences

- `./sec-monk.toml` is a deliberate exception to "never CWD-relative": state is still not CWD-relative unless the
  config file says so, and the ownership check limits planted configs. Revisit if the app is ever started from
  untrusted directories (open question in the report).
- Both versions coexist without touching each other's data.

## Implementation notes (2026-11-11, W2.1)

- `secmonk-config`: lookup and ownership check as decided (`--config` must exist; `SECMONK_CONFIG` must exist and
  pass the check; `./sec-monk.toml` and the per-user file pass the check: regular file, owned by the current user,
  not group/other-writable). `data_dir` is created 0700 (symlinks and foreign owners refused), canonicalized, and
  `{data_dir}` substituted into the database URLs. Unknown keys are refused.

## Amendment (2026-11-11, W3.4: review fixes)

*(Superseded by the 2026-11-11 amendment below: step 3 now runs in every build.)* Decided by the coordinator after the W3.3 review: **lookup step 3 (`./sec-monk.toml`) runs only in debug builds or
with `SECMONK_DEV=1`**. A release build started in a directory someone else prepared must not run that directory's
config (it chooses the modules and the uv URL). Dev use stays as easy as before: `cd rust && cargo tauri dev` (a debug
build) finds `rust/sec-monk.toml`, and its `data_dir = "_data"` still decides where everything goes; for a release
build use `--config rust/sec-monk.toml`, `SECMONK_CONFIG=…` or `SECMONK_DEV=1`.

The ownership check is now done on the open handle: the file is opened once without following a final symlink
(`O_NOFOLLOW | O_NONBLOCK`), `fstat` checks it (regular file, same inode as looked up, owned by the current user, not
group/other-writable), its directory must not be group/other-writable unless sticky, and the text is read from that
handle. A symlinked config is therefore refused in steps 2–4 (dotfile managers: point `--config` at it instead).
Windows: only "regular file, not a reparse point" is checked; ownership and ACLs are not (documented limitation;
the per-user `%APPDATA%` ACLs are the protection). `data_dir` is canonicalized with `dunce`, so Windows paths carry
no `\\?\` prefix into database URLs, `file:` URIs, child environments or working directories.

## Implementation notes (2026-11-11, W4.2)

- Observed layout of `rust/_data` after a first run: `cache db jobs logs modules pycache python python-home run tmp
  tools uv-cache uv-home uv-tools venvs`; `webview/` is created by the window on Windows and Linux only. `jobs/`, `run/`
  and `logs/modules/` exist but are not used yet (no job scratch, no instance lock, no per-module log files:
  [backlog](../plans/backlog.md)).
- Without any config file `[modules] enabled` defaults to the empty list and the host cannot start; the per-user file
  must list the modules (code question raised in the docs pass, see [configuration](../tech/configuration.md)).

## Amendment (2026-11-11, user decision: CWD lookup, instance lock, default modules, single open)

Appended; the decision text above is unchanged except where this amendment supersedes it.

- **CWD lookup in all builds.** The user decided on 2026-11-11 that `./sec-monk.toml` is looked up in every build. This
  supersedes the W3.4 amendment (debug builds or `SECMONK_DEV=1` only); `SECMONK_DEV` and `LoadOptions::allow_cwd`
  are removed. Order: `--config`, `SECMONK_CONFIG`, `./sec-monk.toml`, per-user file. Residual risk: a config in a
  cloned repository is owned by the user and passes the checks, so start sec-monk only from trusted directories.
  Later there may be a well-known config for general settings ([backlog](../plans/backlog.md)).
- **Instance lock.** `run/instance.lock` is an exclusive, non-blocking advisory lock held by the host for its
  lifetime; a second instance on the same `data_dir` is refused (`HostError::InstanceRunning`).
- **`DEFAULT_MODULES`.** When `[modules] enabled` is absent the list is `py-engine`, `py-procmon`, `py-probe`,
  `py-sources` (`secmonk-config`). `enabled = []` still means none. This resolves the W4.2 note that the host could not
  start without a config file.
- **Single-open check.** A found config file is opened once without following a final symlink, checked with `fstat`
  on that handle (regular file, owner, not group/other-writable, directory not group/other-writable unless sticky)
  and read from the same handle: no check-then-reopen window. The checks stay in force with the CWD lookup.
