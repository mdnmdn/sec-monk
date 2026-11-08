---
title: Process collector (process / executable monitor)
summary: Process collector and monitor covering platform-neutral core with per-OS backends, launch classification, identity resolution, snapshot format, risk flags, watch mode, porting.
read_when: you change the process monitor, add an OS backend, extend the secmonk-process-snapshot format or the risk flags
type: tech
context: tech
status: implemented
tags: [collector, process, macos, launchd, provenance]
updated: 2026-11-08
verified: 2026-11-08
sample: mixed
fixtures: tests/fixtures/collectors/process/
code: src/secmonk/collectors/process/, src/secmonk/procmon.py
related: [features/process-monitor.md, decisions/0007-process-monitor.md, tech/collectors/macos.md, tech/collectors/homebrew.md, tech/collectors/dependencies.md, tech/engine/classification.md, plans/on-macos.md]
---

# Process collector

## Summary

The other collectors answer *what is installed*. This one answers *what is running right now*, and for every running
executable:

1. **How it was started**: a generic launch kind (`service`, `agent`, `login-item`, `scheduled`, `gui-app`,
   `xpc-service`, `interactive`, `remote-session`, `child`, `kernel`) plus the platform mechanism, the launch item label
   and the file that configures it (`/Library/LaunchDaemons/x.plist`).
2. **What software and version it is**: the same identities the inventory collectors produce (`.app` bundle, Homebrew
   keg, pkgutil receipt, OS, Go/Rust build info), so the shared engine matches vulnerabilities with no new code.
3. **Where it came from and when**: quarantine xattr and the LaunchServices download event (URL, browser, time),
   `kMDItemWhereFroms`, code signature, Homebrew/pkgutil install time, file birth time, sha256.
4. **Trust flags**: unsigned, ad-hoc signed, downloaded, translocated, running from a user-writable path (as root,
   or persistently), executable deleted on disk, unidentified.

It is a normal collector (`process`, asset `process:<host>`, type `host-processes`): `collect` / `scan process` work as
for every target. The monitor view (`secmonk procs`, tree + findings + flags, `--watch`) is built on the same
analysis in `src/secmonk/procmon.py` (see [the feature](../../features/process-monitor.md)).

## Layout: shared core, one backend per OS

```
 live machine ──backend.take_snapshot()──┐            snapshot.json (secmonk-process-snapshot/1)
                                         v                       │ snapshot.load() (validated, re-redacted)
                               Snapshot(processes, launch_items, os, executables)
                                         │
           ┌─────────────────────────────┼──────────────────────────────────┐
           v                             v                                  v
  launch.LaunchClassifier       backend Inspector.resolve(exe)      Inspector.facts(exe)
  (shared, PlatformHints)       -> Resolution(method, components)   -> signature, quarantine, where_froms,
                                                                       times, sha256 ...
           └──────────────> collector.build_views() -> ProcessView[] <────────┘
                                         │  risk_flags() (shared)
                     ┌───────────────────┴───────────────────┐
                     v                                       v
      collector.inventory(): Inventory               procmon: tree rows, findings join,
      components with meta.process,                  Watcher (new executables / launch items)
      asset.meta.processes (tree)
```

| Module | Role | Platform-specific? |
|---|---|---|
| `model.py` | `ProcessRecord`, `LaunchItem`, `LaunchInfo`, `Snapshot`, launch kinds | no |
| `snapshot.py` | JSON form of a `Snapshot`; type-checked, capped, command lines re-redacted on load | no |
| `launch.py` | launch classification over the process tree; `PlatformHints` (init pids, shells, terminals, schedulers, bundle patterns, GUI label pattern) | hints only |
| `backend.py` | `Backend` registry (`BACKENDS`), base `Inspector` (snapshot-provided identity/facts, otherwise `executable`) | no |
| `macos.py` | `take_snapshot`, `MacOSInspector`, pure parsers (ps, launchctl, launchd plist, codesign, pkgutil, quarantine, where-froms, QuarantineEventsV2, embedded `__info_plist`) | macOS |
| `collector.py` | registered `process` collector, `risk_flags`, components, asset meta | no |
| `../../procmon.py` | CLI views: tree rows, findings per process, `Watcher` | no |

## Where the data lives (macOS)

| Fact | Source | Notes |
|---|---|---|
| processes | `ps -axww -o pid=,ppid=,uid=,user=,lstart=,comm=` (`LC_ALL=C`), then `proc_pidpath()` (libproc via ctypes) for the exact image path | non-root sees every pid but `proc_pidpath` fails for other users' processes: falls back to `comm` |
| command lines | `ps -axww -o pid=,args=`, split on spaces, redacted (`redact_command`); only the interpreter script/jar is kept in the inventory (`-o args=false` skips them) | argv with spaces cannot be recovered from `ps` |
| pid -> launchd job | `launchctl list` (PID, status, label); as root also `launchctl asuser <uid> launchctl list` for each user (uid >= 501, at most 32) owning unlabelled processes | as a user: the user's GUI domain only; as root: the system domain, plus each user's domain for that user's pids (without it GUI apps and login-item helpers lost their labels, macOS 26.5). GUI apps appear as `application.<bundle-id>.<n>.<n>` |
| launch items | `*.plist` in `/Library/LaunchDaemons`, `/Library/LaunchAgents`, `/System/Library/Launch{Daemons,Agents}` (`-o include_system=false` skips), `~/Library/LaunchAgents` of every `/Users/*` (when `/Users` cannot be listed on the live Mac: the current user's home); inside every app the macOS collector walks (`/Applications`, each `~/Applications`, same depth): `Contents/Library/LaunchAgents|LaunchDaemons/*.plist` (SMAppService; mechanisms `launchd-app-agent` / `launchd-app-daemon`, `BundleProgram` and relative programs resolved against the bundle, `..` out of it rejected) and `Contents/Library/LoginItems/*.app` (SMLoginItemSetEnabled helpers: mechanism `login-item`, label = `CFBundleIdentifier`, program = `CFBundleExecutable`) | `Program` or `ProgramArguments[0]`, `RunAtLoad`, `KeepAlive`, `Disabled`, `MachServices`, intervals. Parsed with `macos.loads_plist`, which accepts Apple's unquoted XML prolog (`com.apple.familycircled.plist` on macOS 26.5) |
| OS | `/System/Library/CoreServices/SystemVersion.plist` | |
| identity | see next section | |
| quarantine | xattr `com.apple.quarantine` = `flags;hex-time;agent;event-uuid` on the bundle (apps) or the file | read with `getxattr(2)` via ctypes, no `xattr` subprocess |
| download event | `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` (SQLite, opened `mode=ro&immutable=1`), row by event uuid: data URL, origin URL, agent bundle id, CFAbsoluteTime | URLs stripped of credentials/query |
| download URLs | xattr `com.apple.metadata:kMDItemWhereFroms` (binary plist list) | same stripping |
| signature | `codesign -dv --verbose=2 <executable>` (stderr) -> signed, adhoc, authority chain (Developer ID / Mac App Store / Apple), Team ID, hardened runtime. Run on the executable itself, not the bundle, so a swapped helper does not inherit its bundle's identity. Display only; a failure that is not about the signature (missing file, permission) is `unknown` | `-o codesign=false` disables; sealed system paths are skipped unless `-o codesign_system=true` |
| signature validity | `codesign --verify --strict <executable>` -> `verified` true / false (broken seal, modified, revoked); nothing when the check cannot run | opt-in `-o verify=true` (hashes the whole bundle: seconds per large app) |
| Gatekeeper | `spctl --assess --type execute -vv` (opt-in `-o gatekeeper=true`, slow) | |
| install time | Homebrew `INSTALL_RECEIPT.json` `time`, pkgutil `install-time`, file `st_birthtime` | |
| login item / background helper state | opt-in `-o btm=true` (root: `sfltool dumpbtm`) or `-o btm=<file>` (saved dump) -> `parse_btm` | see "Background Task Management" below |

### Identity resolution order (first hit wins)

| # | Method | Rule | Components |
|---|---|---|---|
| 1 | `brew-keg` / `brew-cask` | real path (symlinks followed inside the tree) under `<prefix>/Cellar/<f>/<v>/` or `Caskroom/<t>/<v>/` | formula via `homebrew._keg_component` (receipt, SBOM, upstream identity, patched CVEs) |
| 2 | `app-bundle` | outermost `*.app` in the path; helpers (`Slack Helper.app`, `.xpc`, `.appex`, frameworks) resolve to their host app (`notes.helper`) | `MacOSCollector._read_bundle` (app + Electron/CEF/Sparkle runtimes); `system-app` under `/System/`. No `.app` in the path: the outermost `.bundle` / `.systemextension` / `.xpc` / `.appex` / `.plugin` with an `Info.plist`, outside system paths (Little Snitch's daemon `.bundle`, a camera `.systemextension` under `/Library/SystemExtensions`). A bundle without `Info.plist` falls through: to `os` on the system volume (`liquiddetectiond.app` holds only its binary), else `path-only` (`.app`) or the next rule (other bundles) |
| 3 | `os` | `/System/`, `/usr/{bin,sbin,libexec,lib}/`, `/bin/`, `/sbin/`, `/Library/Apple/` (not `/usr/local/`) | the `macOS` OS component |
| 4 | `pkgutil` | live only: `pkgutil --file-info <path>` | one `package` per owning receipt (`pkg_id`, version, install time) |
| 5 | `go-binary` / `rust-binary` / `info-plist` | file read (`-o max_binary_mb=128`): Go build info (main module first, then stdlib + deps), `cargo auditable`, or an embedded `__info_plist` (privileged helpers, CLI tools) | as `fs` binaries / an `application` with `bundle_id` |
| 6 | `none` | nothing matched | `executable` component (name = file name, no version: never matched) |

A snapshot entry `executables[path].identity` (`name`, `version`, `category`, `purl`, `bundle_id`, `vendor_hint`,
`product_hint`, `file_version`, `company`; or `os: true`) overrides all of this: that is how a future agent or the
Windows script hands over identities it computed on the target.

### Launch classification (shared)

| Evidence | Rule | Kind |
|---|---|---|
| `pid` | pid 0 / init pid | `kernel` |
| `pid-label` | service-manager label of the pid is a known launch item (one label can be both a system daemon and a per-user agent, e.g. `com.apple.lsd`: chosen like `exe-match` below; a per-instance `.<UUID>` suffix, `PlatformHints.instance_suffix`, is stripped first) | from mechanism (`launchd-daemon` -> `service`, `launchd-agent` -> `agent`, `run-key` -> `login-item` ...) |
| `pid-label` | label matches `PlatformHints.gui_label` (`application.<id>.<n>.<n>`, optionally `.<UUID>`: apps relaunched by the system, real on macOS 26.5) | `gui-app` |
| `exe-match` | label names no plist but the executable is a launch item's program (login-item helpers run as `<TeamID>.<bundle id>`) | from mechanism |
| `pid-label` | label unknown (job submitted at runtime / unreadable plist) | `service` (uid 0) / `agent` |
| `exe-match` | executable is a launch item's program (several: the one in the process user's scope, then a plist whose `UserName` is the process user, then a service for root and an agent for anyone else: `cfprefsd` has both a daemon and a per-user agent, the agent also runs as `_locationd`). Never for shells, interpreters and wrappers (`sh`, `bash`, `python3`, `env`, `nohup` ...): a plist running `/bin/bash` must not claim every bash; those are attributed by `pid-label` only | from mechanism |
| `parent` | parent is init: `.xpc` or `.appex` bundle (app extensions are XPC services: widgets started without a label) -> `xpc-service`, `.app` bundle -> `gui-app`, else `service`/`agent` by uid | |
| `parent` | parent is a scheduler (`cron`, `periodic`, `atrun`) / a GUI launcher (Finder, Dock) | `scheduled` / `gui-app` |
| `ancestry` | parent is a shell: first ancestor that is `sshd` -> `remote-session`, a scheduler -> `scheduled`, a terminal (Terminal.app, iTerm2, tmux, VS Code helper ...) -> `interactive (terminal)`; else a console `login` / `getty` above it -> `interactive (login)`; else (an `sh -c` run by a daemon, an app, an updater) it falls through to `child` | |
| `parent` | anything else | `child`; `via` = top ancestor below init (the app/service that owns the tree) |

The tree walk is cycle-safe and capped (64 levels).

### Background Task Management (`-o btm`)

`sfltool dumpbtm` (root only; undocumented text, layout taken from macOS 26.5 on 2026-11-08, synthetic fixture
`process/sfltool-dumpbtm.txt`): blocks `Records for UID <n>` (`-2`, `0`, each user), records ` #<n>:` with `Type`
(`legacy daemon|legacy agent|agent|daemon|login item|app|developer|quicklook|spotlight|dock tile|...` plus a hex code),
`Disposition` (`[enabled|disabled, allowed|disallowed, notified|not notified]`), `Identifier` (`<type code>.<id>`),
`URL`, `Executable Path`, `Bundle Identifier`, `Parent Identifier`. Items embedded in an app give `URL` / `Executable
Path` relative to the app; `parse_btm` resolves them through the parent `app` record of the same UID block and rejects
`..` out of it. Unknown fields are ignored, unknown types kept, lines outside a record skipped.

`apply_btm` attaches `meta.btm = {type, enabled, allowed}` to the indexed item with the same plist / bundle path, then
program, then label. `enabled` and `allowed` must both hold for macOS to run it. `allowed` is the user's switch:
turning an app off under System Settings > Login Items > *Allow in the Background* changed its embedded agent from
`[enabled, allowed]` to `[enabled, disallowed]` (macOS 26, 2026-11-08); the app record itself stayed `allowed`.
`enabled` is the app's own registration (SMAppService register / unregister): items the app never registered are
`disabled, allowed`. Removing an app from *Open at Login* deletes its `app` record rather than flipping a flag, so
`app` records (not launch items, never indexed) are not tagged;
otherwise the item gets `disabled = true`, which also removes it from the missing-program report. Records of launch
types that match nothing indexed are added (`meta.from_btm`) only when their plist / bundle exists and the index could
not judge it (an unreadable root-only plist, an app outside the walked folders): BTM keeps records of deleted plists
and of plists without a `Label` (Google Keystone's emptied plists), which launchd ignores. Real run, user with the dump
of the same Mac: 98 items tagged (legacy daemon 47, legacy agent 41, login item 6, agent 4), 46 marked off, one item
added (the root-only Teams updater plist), missing programs 4 -> 0 (all four were turned off). Captured in the
snapshot (`launch_items[].meta`), so `secmonk procs <snapshot.json>` keeps it.

## Data format

Inventory: one component per identity, process facts merged under `meta.process`:

```json
{"processes": [{"pid": 300, "ppid": 1, "user": "alice", "started": "...", "exe": ".../MacOS/Slack",
                "launch": "gui-app", "mechanism": "launchservices", "label": "application.com.tinyspeck...", "via": null}],
 "executables": ["/Applications/Slack.app/Contents/MacOS/Slack", ".../Slack Helper"],
 "launch": ["gui-app", "child"], "users": ["alice"], "flags": [], "resolution": "app-bundle", "count": 2,
 "provenance": {"/Applications/Slack.app/Contents/MacOS/Slack": {"quarantine": {...}, "signature": {...}, "sha256": "..."}},
 "helper": "Slack Helper.app", "via_executable": null}
```

`asset.meta`: `taken_at`, `process_count`, `launch_items`, `launch_kinds` (counts), `without_exe`, `processes` (flat tree,
max 5000 rows: pid, ppid, user, exe, launch, label, identity, flags) and `launch_items_missing_program` (enabled launch
items whose program does not exist: stale or removed persistence).

## Snapshot file format (`secmonk-process-snapshot/1`)

Written by `secmonk procs --snapshot-out F` / `-o snapshot_out=F`; read by `secmonk procs F` and `collect|scan process F`.
It is the hand-off format for other platforms and future agents, so it is a public contract: extend it compatibly.

| Field | Type | Notes |
|---|---|---|
| `schema` | `"secmonk-process-snapshot/1"` | required; anything else is refused |
| `platform` | `darwin`, `linux`, `windows` | selects the backend (`backend.BACKENDS`); others get the filesystem-free base `Inspector` |
| `host`, `taken_at` | string | `taken_at` ISO 8601 |
| `os` | `{name, version, build, vendor?}` | becomes the OS component |
| `processes[]` | `{pid, ppid, uid?, user?, exe?, started?, args[], name?, label?}` | `pid` (int) required; `exe` absolute path; `label` = service-manager job owning the pid; `args` redacted argv (max 64) |
| `launch_items[]` | `{mechanism, label, program?, args[], source?, scope?, run_at_load?, keep_alive?, disabled?, meta{}}` | `mechanism` = a key of `launch.MECHANISM_KIND`; `scope` = `system` or `user:<name>` |
| `executables{path: facts}` | object | precomputed facts, used instead of reading files (keys below) |
| `warnings[]` | string list | shown with the collector warnings |

`executables[path]` keys, all optional: `exists`, `size`, `mtime`, `created`, `owner_uid`, `world_writable`, `sha256`;
`signature` (`signed`, `adhoc`, `identifier`, `team_id`, `timestamp`, `hardened_runtime`, `apple`, `mac_app_store`,
`developer_id`, `verified`, `error`, `unknown`, `authority[]`, `flags[]`); `quarantine` (`raw_flags`, `time`, `agent`,
`event_id`, `user_approved`, `on`, `event{time, agent_bundle_id, agent, sender, data_url, origin_url}`);
`where_froms[]`; `gatekeeper{accepted, source}`; `identity{name, version, category, purl, bundle_id, vendor_hint,
product_hint, file_version, company, os}`.

Loading treats the file as untrusted (`snapshot.from_dict`, `snapshot.clean_facts`): unknown keys are dropped, every
value is type-checked, sizes are capped (64 MB file, 100 000 processes, 64 args), command lines are re-redacted and every
URL is stripped of credentials, query and fragment again.

## Classification

Components are the ones of the inventory collectors (same keys, same `classify()`), so a process component shares its
`component` row with `macos:<host>` / `homebrew:<host>`: identity facts match, process facts sit under `meta.process`.
The `executable` category is new and is never matched (no version). The OS component is always emitted when the version
is known (it is what every system process runs).

## Risk flags

Computed by `collector.risk_flags()` from facts, platform-neutral; informational, they do not create findings:
`exe-missing`, `unsigned`, `adhoc-signed`, `signature-invalid` (only with `-o verify=true`), `downloaded`, `world-writable`, `translocated`,
`user-writable-path` (macOS: `/Users/`, `/tmp/`, `/private/var/folders/`, `/Volumes/`, AppTranslocation),
`root-from-user-path`, `persistent-from-user-path` (service/agent/login item running from there), `unidentified`.

In a copied tree (`-o root=`) a symlink resolving outside the root is never followed: the executable gets the fact
`outside_root` instead of the analyst's own file data, and launch-item programs are checked with `lexists`.

## Watch mode

`procmon.Watcher` keeps one inspector for the session (identity and facts cached per path). Every tick it:

- stats every running executable (`Inspector.stamp`: inode, size, mtime); a changed stamp drops the cached identity and
  facts (`Inspector.forget`) and yields `changed-executable` (in-place update, replaced helper);
- reports `new-executable` once per new path, and `new-launch-item` / `changed-launch-item` (program, args, disabled)
  / `removed-launch-item` keyed by (label, plist path); plists are re-parsed only when their stat changes;
- matches new and changed executables: into `process:<host>#watch` in the temporary overlay, or with `--save` into
  `process:<host>` as a **partial** scan, so components the increment did not see stay current and the baseline process
  tree in `asset.meta` is kept.

## Cost (expected on a real Mac, not measured)

Per unique executable, once per session: one streamed sha256 (capped by `max_binary_mb`), one `codesign -dv` (skipped
for sealed system paths), at most one `pkgutil --file-info` (only when no bundle / keg / system rule matched, never for
user-writable paths), one full read for Go/Rust/plist parsing when nothing else identified it. Per tick: `ps` twice,
`launchctl list`, one `proc_pidpath` and one `stat` per process, one `stat` per launchd plist.

## Porting (Linux, Windows)

A backend = `take_snapshot(root, opts)` + an `Inspector` subclass, registered in `backend.BACKENDS`; launch hints go in
`launch.PlatformHints`. Nothing else changes (classification, flags, components, CLI, watch). Planned mapping:

| Concern | Linux | Windows |
|---|---|---|
| processes | `/proc/<pid>/{stat,status,exe,cmdline}`, start time from `stat` field 22 + boot time; `exe` ` (deleted)` suffix -> `exists: false` | `Get-CimInstance Win32_Process` (ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate), or the inventory script / osquery `processes` |
| pid -> job | `/proc/<pid>/cgroup` -> systemd unit (`system.slice/x.service`, `user@1000.service/app.slice/...`) | `Win32_Service.ProcessId` -> service name |
| launch items | systemd units (`ExecStart`), `/etc/xdg/autostart` + `~/.config/autostart`, crontabs | services (`ImagePath`), Run/RunOnce keys, Startup folders, scheduled tasks (`Get-ScheduledTask` actions) |
| hints | init pid 1 = systemd, kernel threads (ppid 2, no exe), terminals (gnome-terminal-server, konsole), `sshd` | System (4), `services.exe`, `explorer.exe` as GUI launcher, `svchost.exe -k` groups, `taskeng`/`svchost Schedule` as scheduler, `conhost`/`WindowsTerminal` |
| identity | dpkg `/var/lib/dpkg/info/*.list` / `rpm -qf` / apk `installed` file -> os-package (reuse `rootfs.py` parsers, build a path index once), snap/flatpak paths, Homebrew (Linuxbrew), Go/Rust binaries | file version resource (`VersionInfo`), Uninstall-key `InstallLocation` prefix -> program component (reuse `windows.py`), Appx package path, `C:\Windows\` -> OS build |
| provenance | file times, package install time (dpkg `.list` mtime, rpm `INSTALLTIME`), IMA/fs-verity if present | `Zone.Identifier` ADS (`ZoneId`, `ReferrerUrl`, `HostUrl`), Authenticode (`Get-AuthenticodeSignature`), MSI install date |
| user-writable | `/home/`, `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/user/` | `%USERPROFILE%`, `%TEMP%`, `%APPDATA%`, `C:\Users\Public` |

The Windows side can ship as an extension of `secmonk-inventory.ps1` that emits a process snapshot (identity and
`Zone.Identifier` precomputed in `executables`), analysed on any OS with the base `Inspector`.

## Limitations

- Fixtures are synthetic plus real ones: an Apple launchd plist (`../macos/real/launchd/`) and a trimmed non-root live
  snapshot (`process/real/snapshot-user.json`). Live run as a user with Full Disk Access (macOS 26.5 arm64, 2026-11-08):
  989 processes = `ps -ax`, 8 s with `--no-match`; `exe` missing for 2 (a zombie, the `ps` that exited); `started` parsed
  for all; 312 pids labelled. Launch kinds: agent 340, service 257, xpc-service 245 (before `.appex` was added; 49
  widgets were `agent`), child 121, gui-app 20, interactive 2. Identity: `os` 744, `app-bundle` 199, `brew-keg` 13,
  `pkgutil` 5, `none` 23 (before the non-`.app` bundle rule). Root run the same day: 979 processes, 2 without `exe`,
  167/198 root processes labelled, the root-only Teams plist read, no warnings; it showed the user-domain label gap and
  the shared-label pick, both fixed afterwards; a second root run: 544 pids labelled (228 before), the user's 311 equal
  the user run, and root vs user differ only on 4 system processes that root labels better. Real fixtures:
  `process/real/snapshot-user.json`, `snapshot-root.json`.
- `sudo secmonk procs` on macOS keeps `HOME`, so the default database folder is the invoking user's and root refuses
  it (ownership check, ADR-0006). `procs` then lists processes without findings and says so; `--save` and other
  commands exit 1 with the hint (`sudo -H`, `--db`, or `--no-match --snapshot-out` as root + `secmonk procs <file>` as
  the user). Before 2026-11-08 this was a `PermissionError` traceback.
- Shells and their tools: the shell under a terminal is `child (<terminal>)` and the commands typed into it are
  `interactive (terminal)` (by design); Warp is matched by its bundle name (`Warp.app/Contents/MacOS/stable`).
- Toolchain-managed runtimes carry their version only in the path and stay `none`: `~/.local/share/uv/python/cpython-3.13.5-*`,
  `~/.nvm/versions/node/v24.11.0`, `/nix/store/*-nix-2.13.3`, self-updating CLIs under `~/.local/share/<tool>/versions/`.
- Launch items whose program is missing are reported (stale persistence) except those the backend marks `meta.os_owned`
  (macOS: `/System/Library/Launch*`, sealed system volume): 5 Apple items point at programs absent on this hardware
  (`com.apple.cvmsCompAgent_arm64` -> `OpenGLES.framework/CVMCompiler`), dormant rather than left behind. Snapshots taken
  before 2026-11-08 have no `os_owned` and still list them.
- **Restricted host (no Full Disk Access, sandboxed or managed session).** Every failure is named, never a traceback
  and never a silently empty result:
  - `ps` cannot run (`PermissionError` on exec, timeout, non-zero exit): the live snapshot fails as a collector error
    (`process: RuntimeError: ps failed: <reason>; ... analyse a snapshot file taken elsewhere`), exit 1, nothing on
    stdout. There is no process list without `ps` (a `proc_listallpids` fallback via libproc is not implemented).
  - `ps -o args=` fails: warning, command lines empty. `launchctl list` fails (exit 1 was observed): warning
    `launchctl list failed (<reason>)`, no labels; launch kinds come from the tree and the plists.
  - A launchd or `/Users` folder that cannot be listed (`EPERM`; `stat` may fail too, so it looks absent): one warning
    `cannot list <path>: permission denied (macOS privacy protection: grant Full Disk Access ...)`; the readable folders
    are still indexed. Observed denied on macOS 26.5: `/Users`, `/Library/LaunchDaemons`, `/Library/LaunchAgents`,
    `~/Library/LaunchAgents`; `/System/Library/Launch{Daemons,Agents}` were readable (886 items).
  - An executable that cannot be `stat`ed gets no facts (not `exists: false`, so no `exe-missing` flag); an app bundle
    whose `Info.plist` is denied is identified `path-only` (name, no version). `codesign`, `pkgutil` or `spctl` that
    cannot run: one warning per command, the facts it would give are absent. Each of these warns once per run.
- Command lines come from `ps`, which joins argv with spaces: arguments containing spaces cannot be recovered, so after
  a redacted value every following non-option token is redacted too (over-redaction). `-o args=false` skips them.
- Point-in-time: short-lived processes between two `--watch` ticks are missed (no Endpoint Security / `kqueue`
  `NOTE_EXEC` / eBPF / ETW subscription; that would need a privileged agent).
- Without root, `proc_pidpath` and `launchctl list` cover only the current user; other users' processes keep the `ps`
  `comm` path and get launch kinds from the tree.
- Background Task Management is read only on request (`-o btm`): without it, whether macOS lets a login item or a
  background helper run (System Settings > General > Login Items) is unknown, so a helper turned off there still
  counts as configured (and a missing program there is reported). Legacy `backgrounditems.btm` is not read.
- Interpreted code: only the interpreter is identified; the script/jar path is recorded (`script`) but its own
  dependencies are not parsed (run `scan fs` on it).
- Apps run from a cryptex (`/System/Volumes/Preboot/Cryptexes/App/...Safari.app`) resolve through the bundle rule;
  not checked on real data (Safari was not running during the capture).
- Two unidentified binaries with the same file name in different directories are kept apart in the collector
  (`exe:<path>` key) but share one `component` row in the database (paths merged).
