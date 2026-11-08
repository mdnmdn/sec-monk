# Process collector fixtures (real)

**Provenance: real, trimmed and anonymized, captured 2026-11-08 on macOS 26.5 (build 25F71), Apple Silicon (arm64)**
with `secmonk procs --no-match --snapshot-out` as a **non-root** user with Full Disk Access. Used by
`tests/collectors/test_process.py` (`test_real_user_snapshot_launch_classification`, `test_real_root_snapshot_launch_classification`).

| File | What | Trimming |
|---|---|---|
| `snapshot-user.json` | `secmonk-process-snapshot/1`, 19 of 989 processes, 9 of 970 launch items: launchd, Apple daemons matched by program (logd, configd, syslogd), cfprefsd as root (daemon) and as `_locationd` (agent), a bundle without `Info.plist` (`liquiddetectiond.app`), GUI apps with `application.<id>.<n>.<n>` labels and the `.<UUID>` variant (Ollama, a second Claude instance), a `.appex` widget and an `.xpc` service started by launchd without a label, Little Snitch's daemon `.bundle`, Warp -> helper -> zsh -> uv -> Python. Launch items include two with missing programs: `com.docker.socket` (third-party, stale) and `com.apple.cvmsCompAgent_arm64` (`meta.os_owned`, dormant on this hardware) | processes outside the selection removed (orphans re-parented to 1), `args` reduced to argv[0], `executables` emptied, user name -> `alice`, home -> `/Users/alice`, host -> `mac`. pids, ppids, start times, labels and paths are otherwise as captured |

| `snapshot-root.json` | same Mac, same day, `sudo uv run secmonk procs --no-match --snapshot-out` (root; system domain + the user's domain via `launchctl asuser`): 27 of 979 processes, 13 launch items. Adds what only root sees: labels of system/service-account processes (WindowServer as `_windowserver`, adid as `_fpsd`), `lsd` and XProtect as both daemon (root) and agent (user), a login-item helper labelled from the user's domain (1Password Browser Helper), the root-only Teams plist (no warnings) | as above |

As a non-root user `launchctl list` returns only the user's domain, so in `snapshot-user.json` Apple daemons carry no
pid label and are attributed by program (`exe-match`).
