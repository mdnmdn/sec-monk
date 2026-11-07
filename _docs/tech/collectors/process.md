---
title: Process collector (process / executable monitor)
type: tech
context: tech
status: implemented
tags: [collector, process, macos, launchd, provenance]
updated: 2026-11-07
sample: synthetic
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
| pid -> launchd job | `launchctl list` (PID, status, label) | as a user: the user's GUI domain; as root: the system domain. GUI apps appear as `application.<bundle-id>.<n>.<n>` |
| launch items | `*.plist` in `/Library/LaunchDaemons`, `/Library/LaunchAgents`, `/System/Library/Launch{Daemons,Agents}` (`-o include_system=false` skips), `~/Library/LaunchAgents` of every `/Users/*` | `Program` or `ProgramArguments[0]`, `RunAtLoad`, `KeepAlive`, `Disabled`, `MachServices`, intervals |
| OS | `/System/Library/CoreServices/SystemVersion.plist` | |
| identity | see next section | |
| quarantine | xattr `com.apple.quarantine` = `flags;hex-time;agent;event-uuid` on the bundle (apps) or the file | read with `getxattr(2)` via ctypes, no `xattr` subprocess |
| download event | `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` (SQLite, opened `mode=ro&immutable=1`), row by event uuid: data URL, origin URL, agent bundle id, CFAbsoluteTime | URLs stripped of credentials/query |
| download URLs | xattr `com.apple.metadata:kMDItemWhereFroms` (binary plist list) | same stripping |
| signature | `codesign -dv --verbose=2 <executable>` (stderr) -> signed, adhoc, authority chain (Developer ID / Mac App Store / Apple), Team ID, hardened runtime. Run on the executable itself, not the bundle, so a swapped helper does not inherit its bundle's identity. Display only; a failure that is not about the signature (missing file, permission) is `unknown` | `-o codesign=false` disables; sealed system paths are skipped unless `-o codesign_system=true` |
| signature validity | `codesign --verify --strict <executable>` -> `verified` true / false (broken seal, modified, revoked); nothing when the check cannot run | opt-in `-o verify=true` (hashes the whole bundle: seconds per large app) |
| Gatekeeper | `spctl --assess --type execute -vv` (opt-in `-o gatekeeper=true`, slow) | |
| install time | Homebrew `INSTALL_RECEIPT.json` `time`, pkgutil `install-time`, file `st_birthtime` | |

### Identity resolution order (first hit wins)

| # | Method | Rule | Components |
|---|---|---|---|
| 1 | `brew-keg` / `brew-cask` | real path (symlinks followed inside the tree) under `<prefix>/Cellar/<f>/<v>/` or `Caskroom/<t>/<v>/` | formula via `homebrew._keg_component` (receipt, SBOM, upstream identity, patched CVEs) |
| 2 | `app-bundle` | outermost `*.app` in the path; helpers (`Slack Helper.app`, `.xpc`, `.appex`, frameworks) resolve to their host app (`notes.helper`) | `MacOSCollector._read_bundle` (app + Electron/CEF/Sparkle runtimes); `system-app` under `/System/` |
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
| `pid-label` | service-manager label of the pid is a known launch item | from mechanism (`launchd-daemon` -> `service`, `launchd-agent` -> `agent`, `run-key` -> `login-item` ...) |
| `pid-label` | label matches `PlatformHints.gui_label` (`application.<id>.<n>.<n>`) | `gui-app` |
| `pid-label` | label unknown (job submitted at runtime / unreadable plist) | `service` (uid 0) / `agent` |
| `exe-match` | executable is a launch item's program (several: the one in the process user's scope). Never for shells, interpreters and wrappers (`sh`, `bash`, `python3`, `env`, `nohup` ...): a plist running `/bin/bash` must not claim every bash; those are attributed by `pid-label` only | from mechanism |
| `parent` | parent is init: `.xpc` bundle -> `xpc-service`, `.app` bundle -> `gui-app`, else `service`/`agent` by uid | |
| `parent` | parent is a scheduler (`cron`, `periodic`, `atrun`) / a GUI launcher (Finder, Dock) | `scheduled` / `gui-app` |
| `ancestry` | parent is a shell: first ancestor that is `sshd` -> `remote-session`, a scheduler -> `scheduled`, a terminal (Terminal.app, iTerm2, tmux, VS Code helper ...) -> `interactive (terminal)`; else a console `login` / `getty` above it -> `interactive (login)`; else (an `sh -c` run by a daemon, an app, an updater) it falls through to `child` | |
| `parent` | anything else | `child`; `via` = top ancestor below init (the app/service that owns the tree) |

The tree walk is cycle-safe and capped (64 levels).

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

- Fixtures are **synthetic**; never run on a real Mac (see [plans/on-macos.md](../../plans/on-macos.md) section F).
- Command lines come from `ps`, which joins argv with spaces: arguments containing spaces cannot be recovered, so after
  a redacted value every following non-option token is redacted too (over-redaction). `-o args=false` skips them.
- Point-in-time: short-lived processes between two `--watch` ticks are missed (no Endpoint Security / `kqueue`
  `NOTE_EXEC` / eBPF / ETW subscription; that would need a privileged agent).
- Without root, `proc_pidpath` and `launchctl list` cover only the current user; other users' processes keep the `ps`
  `comm` path and get launch kinds from the tree.
- Login items of the Background Task Management database (`sfltool dumpbtm`, root-only, opaque format) and legacy
  `backgrounditems.btm` are not read: login items appear as `agent`/`gui-app` by evidence.
- Interpreted code: only the interpreter is identified; the script/jar path is recorded (`script`) but its own
  dependencies are not parsed (run `scan fs` on it).
- Apps run from a cryptex (`/System/Volumes/Preboot/Cryptexes/App/...Safari.app`) resolve through the bundle rule;
  not checked on real data.
- Two unidentified binaries with the same file name in different directories are kept apart in the collector
  (`exe:<path>` key) but share one `component` row in the database (paths merged).
