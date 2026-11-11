---
title: Plan — Rust desktop app on a real Mac
summary: "What only a real macOS machine can confirm for the Rust prototype: WKWebView custom scheme and CSP, uv/Python install staying in data_dir, process monitor through py-procmon, signing and notarization."
read_when: you are on a Mac and want to verify the Rust desktop app
type: plan
context: plans
status: open
platform: macos
tags: [plan, macos, rust]
updated: 2026-11-11
verified: 2026-11-11
related: [plans/README.md, decisions/0009-platform-targets.md]
---

# Plan — Rust desktop app on a real Mac

- [ ] On a GUI session (the W1.2 spike's sandbox blocked WebKit): `secmonk://localhost/` loads `index.html`; relative `/api` fetches reach the handler; CSP `connect-src 'self'`
      accepts the custom scheme; Vue compiles templates with `'unsafe-eval'` (no console error).
- [ ] SBOM download (fetch + blob + `<a download>`) and advisory links (`target=_blank`) behave (system browser).
- [ ] First start: uv 0.13.7 aarch64 and x86_64 archives verify; `uv python install 3.13` and `uv sync` write only
      under `data_dir` (audit `~/.cache/uv`, `~/.local/share/uv`, `~/.local/bin`, `~/Library/Caches`).
  - 2026-11-11 W1.2 spike, arm64 only: passed once `TMPDIR` pointed inside `data_dir` (uv lock file). x86_64 open.
- [ ] `py-procmon` live snapshot as the user (ps, launchctl, codesign) equals `secmonk ui` on the same machine.
- [ ] Quitting the app (Cmd-Q, force quit) leaves no Python process (modules exit on stdin EOF).
  - Confirm with `pgrep` that no module process survives shutdown (it was blocked in the dev sandbox).
- [ ] Live process monitor: `ps` was blocked in the dev sandbox, so the macOS `py-procmon` snapshot and its watch through the
      composed host were never run live; verify them as the user.
- [ ] WKWebView writes `~/Library/WebKit/<id>` and `~/Library/Caches/<id>` (outside `data_dir`, found by the spike; the
      coordinator's open choice **Q4**, accepted as a documented exception for now): check what is stored there
      after a session (local storage, cache of `secmonk://` responses, any `/api` payload) and decide between accepting
      it and a non-persistent website data store.
- [ ] Asynchronous scheme handler (`register_asynchronous_uri_scheme_protocol`) answers while a slow module call
      runs; the window stays responsive.
- [ ] TEMP tables on a `mode=ro` connection (persisted and ephemeral `engine.match`); `mode=ro` when `-shm` cannot be
      created.
- [ ] Developer ID signing, hardened runtime and notarization with spawned Python children (entitlements needed?).
- [ ] W2.3 GUI checks of `sec-monk.app` (`cargo tauri build --debug --bundles app`, from a Mac session with a display).
      The sandbox run only showed the process starting and WebKit failing to create `~/Library/WebKit/dev.secmonk.desktop/...`
      (denied there), so nothing below was observed:
  - The window opens at `secmonk://localhost/`, shows the preparing panel on a first start and then the overview with "create the mirror first" (`no-db`), no console error.
  - Sidebar pages load (assets, findings, sources); theme switch persists (localStorage).
  - Menu/Cmd-Q quits; a `https://` advisory link opens in the default browser and the window does not navigate; `target=_blank` too.
  - Dragging a `file://` or typing a URL cannot navigate the window away from the app origin.
  - Safari Web Inspector (devtools = true): no CSP violation, no request leaves the `secmonk` scheme, no Tauri `ipc` call is possible (`window.__TAURI_INTERNALS__.invoke('plugin:...')` is denied).
  - The bundle contains `Contents/Resources/static` and the app serves it (release build uses only that directory).

## Added by the W4.2 docs pass (2026-11-11): GUI checks of the composed app

- [ ] **Webview render.** `cargo tauri dev` (debug build, finds `rust/sec-monk.toml`) and the release `.app`: every page of the
      UI renders against the real engine (overview, assets, findings, vulnerabilities, processes, sources, scans, runs).
- [ ] **CSP in a real webview.** The handler's CSP (`script-src 'self' 'unsafe-eval'`) is the only policy (Tauri's `csp` does
      not apply to custom schemes): no violation in the Safari Web Inspector; Vue compiles its templates; no request leaves
      the `secmonk` origin.
- [ ] **The preparing state in the UI.** Delete `rust/_data` and start: the window opens at once and each screen shows the error
      panel with "sec-monk is preparing its Python runtime (step N of 5: ...)" and the hint; after the install, reload shows the
      real data. Then break the start (offline, no `uv.archive`) and check the "could not start" message and the log hint.
- [ ] **WKWebView data under `~/Library`** (exception Q4): see the item above; also confirm `data_dir` holds no webview state on
      macOS and that the filesystem audit lists only `~/Library/WebKit/<id>` and `~/Library/Caches/<id>` outside `data_dir`.
- [ ] Quit paths with the composed host: Cmd-Q and the red button both stop the modules (`RunEvent::Exit` runs
      `Service::shutdown`, about 0.2 s observed headless); force quit leaves no Python process.
