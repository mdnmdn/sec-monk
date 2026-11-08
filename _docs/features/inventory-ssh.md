---
title: Agentless inventory over SSH
summary: Agentless SSH inventory of Linux, macOS and Windows hosts - fixed read-only harvest script, transports, host key checks, size caps, safe extraction, asset ids, acceptance criteria.
read_when: you change how the SSH collector connects, what it runs on the host or how it extracts the harvest
type: feature
context: features
status: implemented
tags: [ssh, agentless, linux, macos, windows, inventory, dependencies]
updated: 2026-11-07
verified: 2026-11-07
code: src/secmonk/collectors/ssh.py, src/secmonk/collectors/harvest.py
related: [tech/collectors/ssh.md, tech/collectors/rootfs.md, tech/collectors/macos.md, features/inventory-docker.md, features/inventory-macos.md, features/inventory-homebrew.md, features/inventory-windows.md, features/inventory-dependencies.md, features/README.md]
---

# Agentless inventory over SSH

## What the user gets

The software installed on a remote Linux server, macOS machine or Windows host - OS, distro packages, Python/npm, Go, Rust, Java, .NET and PHP language packages (lockfiles, installed metadata; jars and Go/Rust binaries with `-o binaries=true`, see [inventory-dependencies](inventory-dependencies.md)),
macOS apps, Homebrew formulae and casks (see [inventory-homebrew](inventory-homebrew.md)), pkgutil receipts, and Windows hosts via the OpenSSH server (see [inventory-windows](inventory-windows.md)) - without installing an agent, without running anything but a fixed
read-only script, ready for `secmonk match` / `secmonk scan`. One asset per machine and port: `ssh:<host>` (port 22) or `ssh:<host>:<port>`; `asset.meta.machine_id` (hashed) recognises a host whose address changed.

## Usage

```bash
secmonk scan ssh admin@10.0.0.5                     # collect + save + match; ssh config / agent / keys as usual
secmonk collect ssh admin@srv.example.com:2222      # inventory only
secmonk collect ssh ssh://admin@10.0.0.5:22
secmonk scan ssh admin@10.0.0.5 -o sudo=true        # read root-only files via `sudo -n` (needs NOPASSWD)
secmonk scan ssh admin@10.0.0.5 -o binaries=true -o max_binary_mb=100   # also jars and bin/ executables
secmonk scan ssh admin@10.0.0.5 -o transport=paramiko -o identity=~/.ssh/id_ed25519
SECMONK_SSH_PASSWORD=... secmonk scan ssh admin@10.0.0.5 -o transport=paramiko   # password never on the command line
secmonk scan ssh admin@10.0.0.5 -o ssh_option=ProxyJump=bastion
secmonk scan ssh admin@10.0.0.5 -o root=/ -o exclude=/data,/mnt -o xdev=false -o max_mb=1024
secmonk scan ssh me@mac.local -o os=macos -o verbose=true      # os: linux | macos | windows
```

## Behaviour & rules

* Remote prerequisites: POSIX `sh`, `find`, `tar`, `gzip` (+ `uname`, `hostname`; `sw_vers` on macOS). Linux and macOS (Windows hosts use the PowerShell path, see below; no POSIX tools needed there).
* **Read-only and fixed**: exactly two scripts run (OS detection, then harvest) via `sh -s` on stdin, optionally the second under `sudo -n`.
  Nothing is written remotely. `-o verbose=true` logs them.
* Host keys are verified (system `ssh`: `known_hosts`, BatchMode; paramiko: `~/.ssh/known_hosts` with reject policy). `-o insecure_host_key=true`
  disables this and is **unsafe** (man-in-the-middle possible). Passwords only through `SECMONK_SSH_PASSWORD`.
* Every step has a timeout (`connect_timeout` 15 s, `timeout` 900 s total harvest). Size/count caps (`max_files`, `max_mb`, per-file caps) stop
  runaway harvests: the result is then partial and carries a `harvest truncated` warning.
* Harvested files are extracted defensively into a private temp dir that is always removed.
* Unreadable files are skipped silently; use `-o sudo=true` for them (for package databases this usually changes nothing).
* Default walk skips `/proc /sys /dev /run /tmp /var/tmp /var/cache /var/lib/docker /var/lib/containerd /snap /nix/store`, `.git` and stays on one filesystem (Linux).

## Windows

```bash
secmonk scan ssh admin@win-host                 # auto-detected (cmd.exe/PowerShell login shell)
secmonk scan ssh admin@win-host -o os=windows   # skip the POSIX probe
```

Prerequisite on the host: the Windows OpenSSH server (built into Windows 10 1809+/Server 2019+). The collector runs the same read-only
PowerShell inventory script as `secmonk windows-script` over stdin and feeds its JSON to the [Windows collector](inventory-windows.md);
the asset is still `ssh:<host>[:<port>]`. Tested with a fake transport (`tests/collectors/test_ssh_windows.py`); never against a real Windows host.

## Acceptance criteria

1. `secmonk collect ssh user@host` on a Debian/Alpine/RPM host yields the same components (PURLs) as `secmonk collect rootfs /` would on that host; asset `ssh:<host>[:<port>]`, type `server`.
2. On macOS the components equal those of `secmonk collect macos` for the same filesystem; asset type `desktop`.
3. An unknown or changed host key aborts with an explanatory error (no auto-accept) unless `insecure_host_key=true` is given.
4. No remote command other than the two fixed scripts is executed; hostile file names (quotes, newlines, `$(...)`) and hostile tar entries (`..`, absolute, devices, escaping symlinks) cannot cause code execution or writes outside the temp dir.
5. With system `ssh` absent the collector falls back to paramiko transparently.
6. Exceeding `max_files`/`max_mb` returns a partial inventory with a warning instead of hanging or filling the disk.
7. A Windows OpenSSH host (cmd.exe login shell) is detected and inventoried through the PowerShell script; `-o os=windows` skips the probe (`tests/collectors/test_ssh_windows.py`, fake transport).
8. Criteria 1-6 are covered by `tests/collectors/test_ssh.py` (local `sh` double and an in-process paramiko server; BSD `find`/`bsdtar` untested).

## Implemented by

[tech/collectors/ssh.md](../tech/collectors/ssh.md), [tech/collectors/rootfs.md](../tech/collectors/rootfs.md), [tech/collectors/macos.md](../tech/collectors/macos.md).

