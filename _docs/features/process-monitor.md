---
title: Process / executable monitor
summary: The `secmonk procs` view shows running processes (macOS, Linux, remote Linux over ssh) with launch origin, executable identity, open findings, provenance and trust flags, plus a --watch differ and snapshot files.
read_when: you want to see what is running on a machine, use procs options or --watch, or change what the process monitor reports
type: feature
context: features
status: implemented
tags: [process, macos, linux, ssh, cli, collector, provenance]
updated: 2026-11-11
verified: 2026-11-11
code: src/secmonk/procmon.py, src/secmonk/collectors/process/, src/secmonk/cli.py
related: [tech/collectors/process.md, decisions/0007-process-monitor.md, decisions/0010-remote-process-snapshot.md, features/scan-and-findings.md, features/inventory-macos.md, features/inventory-ssh.md, plans/on-macos.md, plans/on-linux-docker.md]
---

# Process / executable monitor

## What the user gets

A view of **what is running** on a machine instead of what is installed:

- the process tree, each process with **how it was started** (launchd daemon/agent and its plist, systemd service /
  user unit / timer and its unit file, GUI app, XPC service, XDG autostart, terminal, SSH session, cron, container,
  child of another app);
- the **software and version** behind each executable (app bundle, Homebrew formula, pkgutil package, the dpkg / rpm /
  apk package that owns it, snap, the OS itself, Go/Rust modules compiled in) and the **open vulnerabilities** of that
  exact version, from the local mirror;
- **provenance**: downloaded by which browser from which URL and when (quarantine + LaunchServices events), code
  signature / Team ID, install time;
- **trust flags** (unsigned, downloaded, running from a user-writable folder as root or persistently, deleted on disk ...)
  and launch items that point to programs that no longer exist;
- a `--watch` mode that reports **new executables** and **new / removed launch items** while it runs.

macOS and Linux are implemented, Linux also **remotely over ssh** (agentless: one fixed read-only script, package
owners resolved on the target, nothing installed); a Windows backend is designed (see [tech doc,
Porting](../tech/collectors/process.md#porting-linux-windows)). Snapshots taken on any machine can be analysed anywhere.

## Usage

```bash
uv run secmonk procs                          # this Mac: tree + findings (temporary overlay, nothing saved)
sudo uv run secmonk procs                     # all users' processes and system launchd labels
uv run secmonk procs --suspicious             # only processes with findings or flags
uv run secmonk procs --flat -f json > procs.json        # one row per process (also csv)
uv run secmonk procs --save                   # persist asset process:<host> + findings (then `secmonk findings process:<host>`)
uv run secmonk procs --watch 10               # baseline, then report new executables / launch items every 10 s
uv run secmonk procs --watch 10 -f json       # the same as JSON lines (one event per line)
uv run secmonk procs --snapshot-out snap.json # also write the raw snapshot
uv run secmonk procs snap.json                # analyse a snapshot taken elsewhere (paths only, reads nothing here)
uv run secmonk procs snap.json -o root=/mnt/mac   # ... resolving executables against a copied/mounted tree
uv run secmonk scan process                   # the same data through the generic collect/scan/match pipeline
uv run secmonk scan process --fail-on P1      # CI/cron gate on running software only

# Linux: the same commands on the machine itself (sudo for other users' executables and crontabs)
sudo uv run secmonk procs --suspicious
# a remote Linux host over ssh (key / agent auth as for `scan ssh`; nothing is installed there)
uv run secmonk procs ssh://alice@web-1                       # -> asset process:ssh:web-1 (with a port: :2222)
uv run secmonk procs ssh://alice@web-1:2222 -o sudo=true     # sudo -n (NOPASSWD rule needed): all users
uv run secmonk procs ssh://alice@web-1 --snapshot-out web-1.json   # keep the snapshot, re-analyse offline later
uv run secmonk scan process ssh://alice@web-1 --fail-on P1
```

Options (`-o key=value`): `codesign=false`, `codesign_system=true` (also sealed system paths), `verify=true`
(`codesign --verify --strict`, needed for the `signature-invalid` flag; slow on big apps), `gatekeeper=true` (spctl, slow), `hash=false`, `binaries=false` (no Go/Rust/
embedded-plist parsing), `max_binary_mb=128`, `pkgutil=false`, `quarantine_db=false`, `args=false` (do not read
command lines), `include_system=false` (skip `/System/Library/Launch*`), `home=/Users/x` (homes to index),
`hostname=...`, `root=<dir>`, `snapshot_out=<file>`, `btm=true` (root: read macOS Background Task Management with
`sfltool dumpbtm` to know which login items / background helpers are turned off) or `btm=<file>` (a saved
`sudo sfltool dumpbtm > file`, usable without root).

Linux options: `kernel_threads=true` (list kernel threads, omitted by default), `packages=false` (no dpkg / apk / rpm
owner lookup), `args=false`, `hash=false`, `binaries=false`, `max_binary_mb=128`, `home=/home/x`, `hostname=...`,
`root=<dir>`. Over ssh (`ssh://[user@]host[:port]`): the ssh options of `scan ssh` (`transport=openssh|paramiko`,
`identity=`, `known_hosts=`, `insecure_host_key=true`, `connect_timeout=`, `ssh_option=`), `sudo=true`, `timeout=300`;
`root=` is refused. `--watch` needs a local live snapshot (not `ssh://`).

## Behaviour & rules

- Columns: pid, user, launch (`kind (label)` / `kind (mechanism)`), process (indented by tree depth; interpreter
  scripts in brackets), identity (`name version`), findings (`P1x2 P3x1 KEV:1`), flags.
- `--match` (default) uses the database if it exists, in a temporary overlay unless `--save`; without a database the
  tree is shown without findings and a note.
- Findings of a process are those of **every component its executable resolved to** (an Electron app shows the
  app's and Electron's advisories; a Go binary its modules').
- `--watch` keeps the analysis caches, so codesign/hash/parse run once per executable. Events: `NEW exe`,
  `CHANGED exe` (binary replaced on disk: re-identified and re-matched), `NEW` / `CHANGED` / `REMOVED launch item`.
  New and changed executables are matched as they appear (asset `process:<host>#watch` in the overlay; with `--save`, a
  partial scan of `process:<host>` that keeps the baseline). Ctrl-C stops.
- Exit codes as everywhere: 0 ok, 1 collector error (e.g. live snapshot on a platform without a backend, ssh
  connection / `sudo -n` failure, a remote host that is not Linux), 2 usage (`--watch` with a snapshot file or an
  `ssh://` target).
- Linux: a unit labels its main process only (workers and helpers are its children); processes inside a container are
  shown as `child (container)` with the container id and are not identified (scan the image with `docker-engine`);
  an executable deleted or replaced on disk while running is flagged `exe-missing` and its version marked as the
  installed one, not necessarily the running one. A remote host's asset is keyed on the ssh target
  (`process:ssh:<host>[:port]`), never on the name the host reports (kept as `asset.meta.source.remote_hostname`);
  `asset.meta.source` also says how it was taken (`ssh`, target, transport, sudo, boot id); a non-root login warns
  that other users' executables are hidden. Environment assignments in cron lines and unit commands
  (`PGPASSWORD=...`) are never stored.
- Privacy: command lines are redacted (`--password x`, `token=...`, URL credentials; also the tokens after a redacted
  value up to the next option, since `ps` loses argv boundaries). The inventory and `--format json` keep only the
  script/jar path of interpreters; `--snapshot-out` files contain the redacted argv. Snapshot files are re-redacted and
  their URLs re-stripped on load.

## Acceptance criteria

- On a Mac with Slack, Chrome, a Homebrew `curl` run from Terminal and a user LaunchAgent, `secmonk procs` shows
  Slack + helpers as one identity with Electron, Chrome with its download URL, curl as `curl <version>` launched
  `interactive (terminal)`, and the agent as `agent (<label>)` with its plist.
- `secmonk procs --save` then `secmonk findings process:<host>` lists the same findings as the table.
- Adding a LaunchAgent plist or starting a new binary during `--watch` prints one event each.
- On a Linux server, `secmonk procs` (as root) shows `sshd`, `nginx` and `cron` as `service (<unit>)` with the Debian /
  RHEL / Alpine package and version, a cron job as `scheduled`, commands typed in an ssh session as `remote-session`,
  and `secmonk procs ssh://user@server -o sudo=true` from another machine shows the same rows.
- Covered offline by `tests/collectors/test_process.py` and `tests/collectors/test_process_linux.py` (synthetic
  fixtures; the remote script runs under the local `sh` against a fixture tree).

## Implemented by

- [tech/collectors/process.md](../tech/collectors/process.md): backends, identity order, launch rules, provenance, flags.
- [decisions/0007-process-monitor.md](../decisions/0007-process-monitor.md): why a separate asset, a snapshot format and per-OS backends.
- Matching and findings: [scan-and-findings.md](scan-and-findings.md).
