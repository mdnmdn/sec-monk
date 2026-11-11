---
title: Process collector (process / executable monitor)
summary: Process collector and monitor covering platform-neutral core with per-OS backends (macOS, Linux local and over ssh), launch classification, identity resolution, snapshot format, risk flags, watch mode, porting.
read_when: you change the process monitor, add an OS backend, extend the secmonk-process-snapshot format or the risk flags
type: tech
context: tech
status: implemented
tags: [collector, process, macos, launchd, linux, systemd, ssh, provenance]
updated: 2026-11-11
verified: 2026-11-11
sample: mixed
fixtures: tests/fixtures/collectors/process/
code: src/secmonk/collectors/process/, src/secmonk/procmon.py
related: [features/process-monitor.md, decisions/0007-process-monitor.md, decisions/0010-remote-process-snapshot.md, tech/collectors/macos.md, tech/collectors/homebrew.md, tech/collectors/rootfs.md, tech/collectors/ssh.md, tech/collectors/dependencies.md, tech/engine/classification.md, plans/on-macos.md, plans/on-linux-docker.md]
---

# Process collector

## Summary

The other collectors answer *what is installed*. This one answers *what is running right now*, and for every running
executable:

1. **How it was started**: a generic launch kind (`service`, `agent`, `login-item`, `scheduled`, `gui-app`,
   `xpc-service`, `interactive`, `remote-session`, `child`, `kernel`) plus the platform mechanism, the launch item label
   and the file that configures it (`/Library/LaunchDaemons/x.plist`).
2. **What software and version it is**: the same identities the inventory collectors produce (`.app` bundle, Homebrew
   keg, pkgutil receipt, OS, Go/Rust build info; on Linux the dpkg / rpm / apk package owning the executable, snap,
   flatpak, Linuxbrew), so the shared engine matches vulnerabilities with no new code.
3. **Where it came from and when**: quarantine xattr and the LaunchServices download event (URL, browser, time),
   `kMDItemWhereFroms`, code signature, Homebrew/pkgutil install time, file birth time, sha256 (Linux: package install
   time, file mtime / owner / mode, sha256).
4. **Trust flags**: unsigned, ad-hoc signed, downloaded, translocated, running from a user-writable path (as root,
   or persistently), executable deleted on disk, unidentified.

It is a normal collector (`process`, asset `process:<host>`, type `host-processes`): `collect` / `scan process` work as
for every target. Targets: none (this machine, macOS or Linux), `ssh://[user@]host[:port]` (a remote Linux host, see
"Remote Linux over ssh"), or a snapshot file. The monitor view (`secmonk procs`, tree + findings + flags, `--watch`) is built on the same
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
| `launch.py` | launch classification over the process tree; `PlatformHints` (init pids, shells, terminals, schedulers, bundle patterns, GUI label pattern; Linux: kernel-thread parent, container shims, label kinds, cgroup -> unit) | hints only |
| `backend.py` | `Backend` registry (`BACKENDS`), base `Inspector` (snapshot-provided identity/facts, otherwise `executable`) | no |
| `macos.py` | `take_snapshot`, `MacOSInspector`, pure parsers (ps, launchctl, launchd plist, codesign, pkgutil, quarantine, where-froms, QuarantineEventsV2, embedded `__info_plist`) | macOS |
| `linux.py` | `take_snapshot` (local `/proc`), `Capture` (raw contents), `snapshot_from_capture`, `LinuxInspector`, pure parsers (stat, status, cmdline, exe link, cgroup, unit files, desktop entries, crontabs, `dpkg-query -S`, `rpm -qf`, apk file lists), `package_component` (rootfs-identical os-package components) | Linux |
| `remote.py` | `SCRIPT` (the fixed remote `sh` script), `parse_output`, `remote_executables`, `take_remote_snapshot(target, **opts)` | Linux over ssh |
| `collector.py` | registered `process` collector (`ssh://` targets -> `remote.py`), `risk_flags`, components, asset meta; processes inside a container are not resolved against the host (`container` resolution) | no |
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

### Identity resolution order (macOS, first hit wins)

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
| `pid` | pid 0 / init pid (Linux: also pid 2, `kthreadd`) | `kernel` |
| `parent` | Linux: child of pid 2 without executable (kernel thread, kept with `-o kernel_threads=true`) | `kernel` (`kernel-thread`) |
| `pid-label` | service-manager label of the pid is a known launch item (one label can be both a system daemon and a per-user agent, e.g. `com.apple.lsd`: chosen like `exe-match` below; a per-instance `.<UUID>` suffix, `PlatformHints.instance_suffix`, is stripped first) | from mechanism (`launchd-daemon` -> `service`, `launchd-agent` -> `agent`, `run-key` -> `login-item` ...) |
| `pid-label` | label matches `PlatformHints.gui_label` (`application.<id>.<n>.<n>`, optionally `.<UUID>`: apps relaunched by the system, real on macOS 26.5) | `gui-app` |
| `exe-match` | label names no plist but the executable is a launch item's program (login-item helpers run as `<TeamID>.<bundle id>`) | from mechanism |
| `pid-label` | Linux, `PlatformHints.label_kinds`: `app-*@autostart.service` (systemd-xdg-autostart-generator) -> `login-item` (`xdg-autostart`); `app-*.scope` (an app started by GNOME / KDE) -> `gui-app` (`desktop`). A template instance `getty@tty1.service` is looked up as `getty@.service` (`instance_suffix`) | |
| `pid-label` | label unknown (job submitted at runtime / unreadable plist / transient unit) | `service` (uid 0) / `agent` |
| `exe-match` | executable is a launch item's program (several: the one in the process user's scope, then a plist whose `UserName` is the process user, then a service for root and an agent for anyone else: `cfprefsd` has both a daemon and a per-user agent, the agent also runs as `_locationd`). Never for shells, interpreters and wrappers (`sh`, `bash`, `python3`, `env`, `nohup` ...): a plist running `/bin/bash` must not claim every bash; those are attributed by `pid-label` only | from mechanism |
| `exe-match` | Linux restrictions (`PlatformHints.cgroup_unit`): a `systemd-*` item claims a process only when the process's cgroup unit is that unit (an sshd session process in `session-3.scope` is not `ssh.service`, a container's `nginx` is not the host's `nginx.service`); a `cron` item only when a scheduler is among the ancestors (the same binary started from a shell is not the cron job) | |
| `parent` | parent is init: `.xpc` or `.appex` bundle (app extensions are XPC services: widgets started without a label) -> `xpc-service`, `.app` bundle -> `gui-app`, else `service`/`agent` by uid | |
| `parent` | parent is a scheduler (`cron`, `periodic`, `atrun`) / a GUI launcher (Finder, Dock) | `scheduled` / `gui-app` |
| `ancestry` | parent is a shell: first ancestor that is `sshd` -> `remote-session`, a scheduler -> `scheduled`, a terminal (Terminal.app, iTerm2, tmux, VS Code helper ...) -> `interactive (terminal)`; else a console `login` / `getty` above it -> `interactive (login)`; else (an `sh -c` run by a daemon, an app, an updater) it falls through to `child` | |
| `ancestry` | Linux: a container shim (`containerd-shim*`, `conmon`, `lxc-start`, `PlatformHints.container_shims`) above it | `child` (`container`), `label` = the first 12 characters of the container id, `via` = the shim |
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

## Where the data lives (Linux)

`linux.take_snapshot(root, opts)` reads `<root>/proc` (`/` live; a copied tree in tests) into a `Capture` (raw file
contents), and `snapshot_from_capture` turns it into a `Snapshot`; the remote script fills the same `Capture`, so both
paths share every parser. Files are read through `read_within` with size caps (64 KiB per `/proc` file, 128 KiB
`cmdline`, 1 MiB per unit / desktop / crontab file); the `exe` link is only `readlink`ed, never followed.

| Fact | Source | Notes |
|---|---|---|
| processes | `/proc/<pid>/stat` (pid, `comm` up to the *last* `)` since it may contain spaces and parentheses, ppid, flags, field 22 `starttime`), `status` (`Name`, `PPid`, real `Uid`), `/etc/passwd` (uid -> name) | `started` = `btime` (`/proc/stat`) + `starttime` / `CLK_TCK` (`os.sysconf`; the remote `getconf CLK_TCK`), ISO 8601 UTC |
| executable | `readlink /proc/<pid>/exe`; a ` (deleted)` suffix (file removed or replaced by an upgrade while running) is stripped and recorded as `executables[path].exists = false` (-> `exe-missing`; the identity is kept with the note `version_is_installed_not_running`, see Limitations) | other users' processes as non-root: `EACCES`, counted in one warning; zombies (state `Z`/`X`, no executable) and a root reader never count |
| root filesystem | `stat /proc/<pid>/root` (device:inode; stat only, nothing is read through it), compared with pid 1's | a different root (chroot, `RootDirectory=`, a sandbox the cgroup does not name) -> `container = {runtime: chroot, id: <unit>}`: not resolved against the host. A private mount namespace with the same root (`PrivateTmp=`, `ProtectSystem=`) is still the host |
| command lines | `/proc/<pid>/cmdline`, NUL-separated: exact argv boundaries (no over-redaction as with `ps`), redacted, max 64 args; an argument holding whitespace (a `setproctitle()` title such as `worker --api-key=K --queue q`) is redacted again in its string form; `-o args=false` skips | |
| kernel threads | `PF_KTHREAD` in the stat flags, pid 2 (`kthreadd`) or a child of 2 without executable | omitted unless `-o kernel_threads=true` (then `kernel`, mechanism `kernel-thread`) |
| pid -> unit (`label`) | `/proc/<pid>/cgroup`: the `name=systemd` hierarchy (cgroup v1), else the unified `0::` path (v2), else the first non-root controller path; unit = innermost `.service` / `.scope` / `.socket` (`user@<uid>.service/init.scope` = the `systemd --user` manager -> `user@<uid>.service`) | only `.service` units and `app-*` scopes become labels, and only on the unit's main process (its parent is outside the unit's cgroup), like `launchctl list` names one pid per job; `session-N.scope` and container scopes are not labels. The path is kept as `processes[].cgroup` |
| container | the cgroup paths: `docker-<id>.scope`, `/docker/<id>`, `cri-containerd-<id>.scope` + `pod<uid>` (Kubernetes), `crio-<id>.scope`, `libpod-<id>.scope` (podman; `libpod-conmon-` is not the container), LXC `^/lxc.payload.<name>` / `^/lxc/<name>` (not `lxc.monitor.*`, not `lxc.service`), systemd-nspawn `machine-<name>.scope` (`nspawn`), flatpak `app-flatpak-<app id>-<n>.scope` (`flatpak`) | `processes[].container = {runtime, id, pod?}`; such a process is not resolved against the host (its `exe` is a path in the container's filesystem): `container` resolution, an `executable` component, no file facts |
| launch items | systemd unit files `*.service` / `*.timer` in `/etc/systemd/system`, `/usr/local/lib/systemd/system`, `/lib/systemd/system`, `/usr/lib/systemd/system` (that precedence: the first file of a name wins, an `/etc` override hides the vendor unit) -> `systemd-system`; `/etc/systemd/user`, `/usr/local/lib/systemd/user`, `/usr/lib/systemd/user` and `~/.config/systemd/user` of every `/home/*` and `/root` -> `systemd-user` (scope `user:<name>` for home units). A unit linked to `/dev/null` is masked (`disabled`, `meta.masked`). A `.timer` (`Unit=` or the same name) turns its service into `systemd-timer` (`scheduled`, `meta.timer`) | first effective `ExecStart` (an empty one resets; prefixes `-@:+!` stripped, with `@` argv[0] dropped; continuation lines joined), `User` -> `meta.UserName`, `Type`, `Description`. Drop-ins (`*.service.d/*.conf`) and generated units are not read |
| | XDG autostart: `/etc/xdg/autostart/*.desktop`, `~/.config/autostart/*.desktop` -> `xdg-autostart` (`login-item`); `Exec` without field codes (`%u`), `Hidden=true` / `X-GNOME-Autostart-enabled=false` -> disabled | |
| | crontabs: `/etc/crontab`, `/etc/cron.d/*` (with a user field), `/var/spool/cron/crontabs/*` (Debian), `/var/spool/cron/*` (RHEL) -> `cron` (`scheduled`), label `<file>:<line>`, `meta.schedule`, `meta.UserName`; program = first `&&` / `||` / `;` segment starting with an absolute path (Debian's `test -x X && X`), else the first word of the last segment | user crontabs need root to list: one warning |
| | in every `ExecStart`, `Exec` and cron command, leading `NAME=value` assignments and an `env [-i] NAME=value` wrapper are skipped before the program (`PGPASSWORD=... pg_dump` -> `pg_dump`): they are never stored. A bare program name (`ExecStart=foo`, `Exec=nm-applet`) is resolved locally against `/usr/local/{s,}bin`, `/usr/{s,}bin`, `/{s,}bin` under the root (`meta.command` keeps the redacted name); over ssh it stays unresolved (`program` null) | |
| | files under a home directory (`~/.config/systemd/user`, `~/.config/autostart`) are read only when they are not symlinks and their directory resolves inside that home (a user cannot point an entry at a root-only file) | |
| OS | `/etc/os-release` (or `/usr/lib/os-release`), `/etc/debian_version` -> `Snapshot.os` (`name`, `version`, `vendor`, `id`, `id_like`, codenames, `debian_version`) | the OS component is the rootfs one (`rootfs._os_component`, OSV distro ecosystem included) |
| hostname | `-o hostname=`, else `socket.gethostname()` (live), else `/proc/sys/kernel/hostname`, `/etc/hostname` | |

### Identity resolution order (Linux, first hit wins)

| # | Method | Rule | Components |
|---|---|---|---|
| 0 | `container` | the process runs in a container or another root filesystem (`processes[].container`); decided in `collector.build_views` before any inspector, so it wins over everything below, snapshot identities included | `executable` component with `container_runtime` / `container_id` (scan the image with `docker-engine` instead) |
| 0 | `snapshot` | `executables[path].identity` present (remote snapshots: the package owner resolved on the target) | as given, incl. `ecosystem`, `source_package`, `source_version`, `install_time` |
| 1 | `brew-keg` | real path under `<prefix>/Cellar/<f>/<v>/` (Linuxbrew `/home/linuxbrew/.linuxbrew`) | `homebrew._keg_component` (path only without a filesystem) |
| 2 | `snap` | `/snap/<name>/<rev>/...` | `application` named after the snap, version from `meta/snap.yaml` (`version:`) |
| 3 | `flatpak` | `/var/lib/flatpak/app/<id>/...` or `~/.local/share/flatpak/app/<id>/...` | `application` = app id, path-only (a sandboxed process shows its in-sandbox `/app/...` path instead: unidentified) |
| 4 | `os-package` | owner of the real path, then of the link itself (`/usr/bin/python3`), each also in its merged-/usr form (`/usr/bin/x` <-> `/bin/x`): dpkg `var/lib/dpkg/info/*.list` (`pkg:arch.list` -> `pkg`), apk `lib/apk/db/installed` (`F:` / `R:` lines); live rpm hosts: `rpm -qf --queryformat ... -- <path>` (not for user-writable paths). The path -> package index of every listed file is built once and rebuilt only when the package databases change (stat of the dpkg info dir and status, apk db, rpmdb dirs: `--watch` after an upgrade) | the component `rootfs.collect_from_view` produces for that package (dpkg status / apk installed / rpmdb.sqlite; same purl, OSV ecosystem, source package): it shares its `component` row with `rootfs:` / `ssh:` inventories. `pkg_install_time` = mtime of the `.list` file / rpm `INSTALLTIME` |
| 5 | `go-binary` / `rust-binary` | file read (`-o max_binary_mb=128`, `-o binaries=false` skips) | as `fs` binaries |
| 6 | `none` | nothing matched | `executable` component |

Facts (local): `exists`, `size`, `mtime`, `owner_uid`, `world_writable`, `sha256` (`-o hash=false` skips). `-o
packages=false` disables the package index. Commands run locally: only `rpm -qf` on live rpm-based hosts.

### Remote Linux over ssh

`ProcessCollector().collect("ssh://[user@]host[:port]", **opts)` (also `analyse`, `snapshot`) calls
`remote.take_remote_snapshot(target, **opts)` ([ADR-0010](../../decisions/0010-remote-process-snapshot.md)):

1. The ssh target is parsed by `ssh.parse_target` and a transport made by `ssh.make_transport` (or a `Transport`
   instance passed as `transport=`): same options as `scan ssh`: `transport=openssh|paramiko|auto`, `identity`,
   `known_hosts`, `insecure_host_key`, `connect_timeout`, `ssh_option`, `ssh_bin`, `ssh_config`, `verbose`. Plus
   `sudo=true` (runs `sudo -n sh -s`: a NOPASSWD rule is needed), `timeout` (seconds, default 300), `hostname`.
2. `remote.SCRIPT`, one constant POSIX `sh` script, is sent on stdin to `sh -s`. It reads, in order: `ostype`,
   hostname, boot id, `btime`, `getconf CLK_TCK`, `id -u`, `name:uid` pairs of `/etc/passwd` (`cut -d: -f1,3`: no GECOS),
   os-release, `debian_version`; for each `/proc/<pid>`: `stat`, the `Name|PPid|Uid` lines of `status`, `cmdline`,
   `cgroup`, `stat -L -c '%d:%i'` of `root`, `readlink exe` (`!` only when the link exists but cannot be read; paths
   containing a newline are kept for the process but not queried further); on dpkg hosts the package table (`dpkg-query -W` with Package,
   Version, Architecture, Source, Status) and the `.list` mtimes (`stat -c '%Y %n'`); apk's `installed` (8 MiB cap);
   then for each distinct executable path: `stat -c '%Y %s %u %a'` and the `version:` of a snap's `meta/snap.yaml`;
   then the owners of all paths and their merged-/usr forms in **one** call (`dpkg-query -S -- "$@"`), or on rpm hosts
   one `rpm -qf --queryformat ... -- "$@"` whose output is used when it has exactly one line per path (else one call
   per path); finally the unit files (masked ones by `readlink`), autostart files and crontabs listed above (home-dir
   files skipped when they are symlinks or their directory resolves outside the home, `pwd -P`). Every value is hex-encoded
   (`od -An -v -tx1`), one `TAG key hex` record per line between `@@SECMONK-PROCS/1@@ BEGIN` / `END`. Nothing is
   written; every redirection goes to `/dev/null`.
3. The output is read up to 32 MiB (`remote.MAX_OUTPUT`), parsed by `parse_output` into a `Capture` (malformed records
   skipped; a last line without newline, i.e. cut by the cap or a killed stream, dropped with a warning; numbers longer
   than 20 digits and times `datetime` cannot represent ignored; at most 100 000 processes and executables and 20 000
   unit / autostart / crontab / masked entries each, with a warning when exceeded) and by `linux.snapshot_from_capture`; `remote_executables` adds the file facts and the package owners as
   `executables[path].identity` (built by `linux.package_component`, identical to the rootfs components: purl, OSV
   ecosystem, source package / version, install time from the `.list` mtime or rpm `INSTALLTIME`), and snap versions.
4. The snapshot has `platform: linux` and `host` = `ssh:<host>` for the default port, `ssh:<host>:<port>` otherwise
   (`ssh.ssh_asset_id` of the target, IPv6 bracketed), so the asset id is `process:ssh:<host>[:port]`; `-o hostname=`
   overrides it explicitly. The name the host reports for itself is only recorded (`source.remote_hostname`): many
   hosts are `localhost` or `ubuntu`, and a hostile host must not be able to overwrite another asset. `source = {kind:
   ssh, target, transport, sudo, boot_id, remote_hostname}` (also in `asset.meta.source`). It is analysed with `LinuxInspector(root=None)`: nothing on
   the analyst's machine is read (`-o root=` is refused for `ssh://` targets). `snapshot_out` writes it like a local one.

Errors: no `BEGIN` marker -> `SSHError` with the remote stderr (and the `sudo -n` hint with `sudo=true`); a non-Linux
`ostype` -> `SSHError`; no process listed -> `SSHError`. Output cut at the cap, a timeout or a missing `END` -> warning,
snapshot kept (partial). A non-root login -> warning; executables of other users' processes count in one warning.

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
| `processes[]` | `{pid, ppid, uid?, user?, exe?, started?, args[], name?, label?, cgroup?, container?}` | `pid` (int) required; `exe` absolute path; `label` = service-manager job owning the pid; `args` redacted argv (max 64); `cgroup` (Linux, max 4096 chars) the systemd cgroup path; `container` (Linux) `{runtime, id, pod?}` |
| `launch_items[]` | `{mechanism, label, program?, args[], source?, scope?, run_at_load?, keep_alive?, disabled?, meta{}}` | `mechanism` = a key of `launch.MECHANISM_KIND`; `scope` = `system` or `user:<name>` |
| `executables{path: facts}` | object | precomputed facts, used instead of reading files (keys below) |
| `warnings[]` | string list | shown with the collector warnings |
| `source` | `{kind, target?, transport?, sudo?, boot_id?, remote_hostname?}` | optional: how the snapshot was taken (`local`, `ssh`); copied to `asset.meta.source` |

`executables[path]` keys, all optional: `exists`, `size`, `mtime`, `created`, `owner_uid`, `world_writable`, `sha256`;
`signature` (`signed`, `adhoc`, `identifier`, `team_id`, `timestamp`, `hardened_runtime`, `apple`, `mac_app_store`,
`developer_id`, `verified`, `error`, `unknown`, `authority[]`, `flags[]`); `quarantine` (`raw_flags`, `time`, `agent`,
`event_id`, `user_approved`, `on`, `event{time, agent_bundle_id, agent, sender, data_url, origin_url}`);
`where_froms[]`; `gatekeeper{accepted, source}`; `identity{name, version, category, purl, bundle_id, vendor_hint,
product_hint, file_version, company, os, source_package, source_version, arch, pkg_type, install_time, ecosystem}`
(the last six for distro packages resolved on a Linux target; `install_time` becomes the provenance
`pkg_install_time`, `ecosystem` the OSV ecosystem used for matching).

`cgroup`, `container`, `source` and the six identity keys were added on 2026-11-11 (Linux backend); they are optional,
type-checked on load, and older files load unchanged.

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
`user-writable-path` (macOS: `/Users/`, `/tmp/`, `/private/var/folders/`, `/Volumes/`, AppTranslocation; Linux:
`/home/`, `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/user/`),
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
`launch.PlatformHints`. Nothing else changes (classification, flags, components, CLI, watch). macOS and Linux are
implemented (`BACKENDS = {"darwin", "linux"}`; Linux mapping in "Where the data lives (Linux)"). Planned mapping for
Windows:

| Concern | Windows |
|---|---|
| processes | `Get-CimInstance Win32_Process` (ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate), or the inventory script / osquery `processes` |
| pid -> job | `Win32_Service.ProcessId` -> service name |
| launch items | services (`ImagePath`), Run/RunOnce keys, Startup folders, scheduled tasks (`Get-ScheduledTask` actions) |
| hints | System (4), `services.exe`, `explorer.exe` as GUI launcher, `svchost.exe -k` groups, `taskeng`/`svchost Schedule` as scheduler, `conhost`/`WindowsTerminal` |
| identity | file version resource (`VersionInfo`), Uninstall-key `InstallLocation` prefix -> program component (reuse `windows.py`), Appx package path, `C:\Windows\` -> OS build |
| provenance | `Zone.Identifier` ADS (`ZoneId`, `ReferrerUrl`, `HostUrl`), Authenticode (`Get-AuthenticodeSignature`), MSI install date |
| user-writable | `%USERPROFILE%`, `%TEMP%`, `%APPDATA%`, `C:\Users\Public` |

The Windows side can ship as an extension of `secmonk-inventory.ps1` that emits a process snapshot (identity and
`Zone.Identifier` precomputed in `executables`), analysed on any OS with the base `Inspector`, the way the Linux remote
script hands over package owners.

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
- **Linux** (developed on macOS against a synthetic tree, `process/linux/`; not run on a real Linux host yet, see
  [plans/on-linux-docker.md](../../plans/on-linux-docker.md) section F):
  - an executable deleted or replaced while running (` (deleted)`, typically after a package upgrade) is flagged
    `exe-missing` and identified by the package that owns the path *now*; the running version may be older, so the
    resolution carries `version_is_installed_not_running` (also in `meta.process`) instead of silently reporting it;
  - systemd drop-ins, generated and transient units are not read (an `ExecStart` overridden in a drop-in is missed;
    a transient `run-*.service` is a label without an item: `service` / `agent` by uid); unit enablement
    (`*.wants/` links) is not recorded, only masking;
  - rpm file lists are not parsed: on a copied rpm tree executables stay `unidentified`; live and remote rpm hosts use
    `rpm -qf`. BerkeleyDB / ndb rpm databases (CentOS 7, SLES 12) work only through `rpm -qf`;
  - processes in a container are not identified (the image is the target of `docker-engine` / `docker-image`), nor
    are flatpak-sandboxed processes, whose `exe` is an in-sandbox `/app/...` path;
  - pacman (Arch), xbps, nix and other package databases are not indexed: their executables stay `unidentified`;
  - over ssh: no sha256 and no Go/Rust build-info parsing (that would read every binary over the wire); bare `Exec` /
    `ExecStart` names are not resolved; `--watch` would re-run the whole script per tick (not wired in the CLI);
    `dpkg-query -S` runs once for all executables; `rpm -qf` once too unless a file has several owners (then once per
    executable); the argument list is not chunked (a few hundred paths stay far below `ARG_MAX`);
  - the remote script relies on `od`, `dd`, `tr`, `sed`, `grep -E`, `cut`, `sort`, `readlink`, `stat -c` (GNU
    coreutils or busybox), `getconf`; on a host without one of them the related records are empty (no error).
