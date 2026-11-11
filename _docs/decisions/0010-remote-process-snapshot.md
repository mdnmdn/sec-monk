---
title: ADR-0010 — Remote Linux process snapshots over ssh with one fixed script
summary: Decision to take Linux process snapshots over ssh with one constant read-only sh script; its framed hex output is parsed by the local backend parsers and package owners are resolved on the target.
read_when: you change how remote process snapshots are taken, extend the remote script, or question why package owners are resolved on the target instead of harvesting files
type: decision
context: decisions
status: accepted
tags: [process, ssh, linux, collector, security]
updated: 2026-11-11
verified: 2026-11-11
related: [decisions/0007-process-monitor.md, tech/collectors/process.md, tech/collectors/ssh.md, features/process-monitor.md]
code: src/secmonk/collectors/process/remote.py, src/secmonk/collectors/process/linux.py
---

# ADR-0010 — Remote Linux process snapshots over ssh with one fixed script

## Context
[ADR-0007](0007-process-monitor.md) made the process monitor a collector with per-OS backends and a snapshot file
format. Users want to see what runs on remote Linux servers without installing anything there. The ssh inventory
collector already reaches those hosts (transports, `sudo -n`, host-key policy), but its model is "harvest files with
`find | tar`, then run a local collector on the copy". A running system's process list is not a set of files:
`/proc` cannot be archived meaningfully, the `exe` links point into the remote filesystem, and package ownership of
an executable needs the full dpkg file lists (tens of MB) or rpm's header blobs (file lists are not parsed by
`rootfs.py`). Alternatives considered:

1. Harvest `/proc/*/{stat,status,cmdline,cgroup}` plus package databases with tar: `exe` is a link (tar records only
   the link text, fine) but the dpkg `.list` files and rpmdb are large and rpm file lists would need a new parser.
2. Run `ps` remotely and parse it: loses exact argv boundaries, executable paths and cgroups; differs per distro.
3. Install an agent: out of scope for the prototype (ADR-0007 already chose polling and no privileged agent).
4. One fixed shell script that reads `/proc` and the launch configuration and asks the target's own package manager
   who owns each running executable.

## Decision
- **Option 4.** `remote.SCRIPT` is constant text (no user, target or remote value is ever interpolated), fed on stdin
  to `sh -s` / `sudo -n sh -s` through the ssh collector's transports (`ssh.make_transport`, same options). It only
  reads: `/proc`, `/etc/os-release`, `/etc/passwd` (`name:uid` pairs only), unit files, autostart files, crontabs,
  apk's `installed`; and runs `od`, `dd`, `tr`, `sed`, `grep`, `cut`, `sort`, `readlink`, `stat -c`, `getconf`, `id`,
  `dpkg-query -W` / `-S`, `rpm -qf --queryformat`. Paths it got from the target are passed as `"$p"` / `"$@"` after
  `--`; owners of all executables are asked in one `dpkg-query -S` (one `rpm -qf` when its output aligns 1:1).
- **Framed, hex-encoded records.** One line per record, `TAG key hex`; every value from the target goes through
  `od -An -v -tx1` (process names, paths and command lines may contain any byte, including newlines and NULs). Begin
  and end markers detect login noise and truncation. Output capped at 32 MiB, parsed by `remote.parse_output` into
  the same `linux.Capture` the local reader produces, then by the same pure parsers.
- **Package ownership resolved on the target**, written into the snapshot as `executables[path].identity` with the
  rootfs component fields (purl, ecosystem, source package / version, install time). The snapshot is self-contained:
  it is analysed without reading anything on the analyst's machine, saved with `snapshot_out`, and reloads identical.
- **Target syntax `ssh://[user@]host[:port]` only** for the `process` collector (a bare `user@host` would be ambiguous
  with a snapshot file name).
- **The asset is keyed on the ssh target**, `process:` + `ssh.ssh_asset_id(target)` = `process:ssh:<host>[:port]`, the
  same key scheme as the `ssh:` inventory asset. The hostname the target reports is untrusted (many hosts are
  `localhost` / `ubuntu`; a hostile host could name itself after another asset and overwrite it), so it is only kept
  as `source.remote_hostname`. `-o hostname=` overrides the key explicitly.

## Consequences
- Remote hosts get the same launch classification, identities and findings as a local Linux run, with no agent and
  no extra dependency; the script is reviewable in one place and tested by running it under `sh` against a fixture
  tree.
- The snapshot format gained optional, validated fields (`processes[].cgroup`, `processes[].container`, `source`,
  identity keys for distro packages); older readers ignore them.
- Not done remotely: hashing and Go/Rust build-info parsing of binaries (would mean reading every executable over
  the wire), so those executables stay `unidentified`; `--watch` over ssh re-runs the whole script per tick.
- Non-root logins see other users' processes without their executables; the snapshot says how many.
- The same machine scanned locally (`process:<hostname>`) and over ssh (`process:ssh:<host>`) gives two assets.
