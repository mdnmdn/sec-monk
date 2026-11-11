---
title: Plan — Rust desktop app on Windows
summary: "Windows verification items: WebView2 origin, uv zip and data_dir containment, Job object kill, CREATE_NO_WINDOW, verbatim paths, reparse-point config check, APPDATA redirection, SmartScreen."
read_when: you are on a Windows machine and want to verify the Rust desktop app
type: plan
context: plans
status: open
platform: windows
tags: [plan, windows, rust]
updated: 2026-11-11
verified: 2026-11-11
related: [plans/README.md, decisions/0009-platform-targets.md]
---

# Plan — Rust desktop app on Windows

- [ ] WebView2: the custom scheme is served as `http://secmonk.localhost/`; relative `/api` fetches and the CSP work;
      decide `http` vs `https` (`useHttpsScheme`).
- [ ] uv zip (x86_64, aarch64): flat layout with `uv.exe` (per the release; not run), verification, extraction.
- [ ] Containment: `UV_PYTHON_INSTALL_REGISTRY=0` leaves `HKCU\Software\Python` untouched; nothing in
      `%APPDATA%\uv`, `%LOCALAPPDATA%\uv`, `%USERPROFILE%\.local\bin`; uv still starts with redirected
      `APPDATA`/`LOCALAPPDATA`.
- [ ] Module processes: no console window (`CREATE_NO_WINDOW`), killed with the app (Job Object), binary stdio (no CRLF
      translation of frames), `data_dir` with spaces and non-ASCII characters; `MAX_PATH` with the deepest venv path (keep `data_dir`
      short or enable long paths).
- [ ] `PIP_CONFIG_FILE=NUL` and redirected `APPDATA`/`LOCALAPPDATA`/`USERPROFILE` do not break uv; WebView2 user data
      folder inside `data_dir`.
- [ ] Per-user ACLs of `data_dir` (no other user can read the databases).
- [ ] Collectors that run here (fs, docker-engine over npipe, ssh with the OpenSSH client, k8s, sbom, windows live);
      the process view answers 503 `unsupported-platform` as today.
- [ ] Authenticode signing; Defender / SmartScreen behaviour with the downloaded uv and Python.

## Added by the W4.2 docs pass (2026-11-11): code written without a Windows machine

- [ ] **Job object kill (review M2, not implemented).** On Unix a module's whole process group is killed
      (`secmonk-modhost` `child.rs` `kill_group`); on Windows `kill_group` is a no-op and only the module process dies, so
      ssh, docker, kubectl or git started by a module can outlive it. Needs a Job object with
      `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (the workspace forbids `unsafe`: a safe wrapper crate or a scoped exception).
      Check afterwards: kill the app from Task Manager during a scan over ssh and find no `python.exe`, `ssh.exe` left.
- [ ] **`\\?\` paths and `dunce`.** `data_dir` is canonicalized with `dunce` (`secmonk-config`, `secmonk-runtime`), so no
      verbatim prefix reaches the `sqlite://` URLs, the `file:` URIs of the read-only grant, the uv variables or working
      directories; the Python side strips it again (`secmonk_modules.db.plain_path`). Check with a `data_dir` that has spaces,
      non-ASCII characters, a drive letter in another case and a UNC-looking path; `MAX_PATH` with the deepest venv path.
- [ ] **Reparse-point config check.** The config file is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and refused when it is a
      symlink or junction (`secmonk-config/src/lookup.rs`); owner and ACLs are not checked. Check: symlink and junction
      configs are refused for `SECMONK_CONFIG` and the `%APPDATA%` file, `--config` accepts a symlink; decide whether an ACL
      check is needed.
- [ ] **`CREATE_NO_WINDOW`.** Set in `LaunchSpec::to_command`: no console window flashes for modules or for the uv steps
      (download, `python install`, `sync`), and stdin/stdout stay binary.
- [ ] **`APPDATA` / `LOCALAPPDATA` redirection.** uv steps run with both pointing into `data_dir\uv-home\`
      (`appdata`, `localappdata`): uv still starts, and nothing appears under the real `%APPDATA%\uv` or `%LOCALAPPDATA%\uv`.
      Module processes get the real user environment (collectors read profiles): confirm the two sets stay separate.
- [ ] **SmartScreen / Defender.** The unsigned `uv.exe` extracted into `tools\uv-0.13.7\` and the downloaded Python may be
      flagged; record what the user sees and whether the extraction path or a Mark-of-the-Web matters.
- [ ] Headless server on Windows: `secmonk-headless` binds loopback, Ctrl-C stops the modules (SIGTERM does not exist there).
- [ ] Native importers: `feed::exists_like_python` maps Windows error codes 2, 3, 21, 123 and 1921 to "path not found" like
      Python's `Path.exists()`; check `--path` with a missing, invalid and looping path on a real Windows machine
      ([source-msrc](../tech/source-msrc.md)).
