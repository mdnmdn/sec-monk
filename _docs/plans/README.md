---
title: Plans - what remains to test and which sources to add
summary: Index of the plans that list unverified collectors and sources by platform (macOS, Linux/Docker, Windows, open network) plus engine quality, with open-item counts.
read_when: you look for the plan that matches the machine or network you are on, or want to see what is still unverified
type: plan
context: plans
status: open
platform: any
tags: [plan, index]
updated: 2026-11-07
verified: 2026-11-07
related: [_meta/README.md, product/vision.md, decisions/0005-prototype-scope-nov-2026.md]
---

# Plans

Everything so far was developed in a **Linux cloud sandbox** with a restrictive egress proxy, no Docker daemon, no macOS, no Windows, no PowerShell, no ssh/sshd.
These plans list what is still **unverified** (collectors/sources exercised only with synthetic fixtures) and which **sources** to integrate next, grouped by the **platform you need to be on**.
Each gap lives in exactly one file; the others link to it.

| Plan | Platform | Open items | Purpose |
|---|---|---|---|
| [on-macos.md](on-macos.md) | macos | 28 | Run the macOS and Homebrew collectors on a real Mac; Electron/CEF/Sparkle, pkgutil, system_profiler, SSH to a Mac, Docker socket variants, alias growth, `brew_cpe_seed` precision; process monitor live run (launch kinds, identity, provenance, `--watch`) and the web interface. |
| [on-linux-docker.md](on-linux-docker.md) | linux | 26 | Docker/Podman engine collector against real sockets; `docker save` (Docker >= 25) and whiteouts; zstd; rpm BDB/ndb; registry auth; live-`/` rootfs; Linuxbrew; real SSH servers (OpenSSH, sudo, busybox, ProxyJump); Linux backend of the process monitor. |
| [on-windows.md](on-windows.md) | windows | 19 | Execute the PowerShell inventory script (5.1 and 7), live `winreg`, osquery, Windows OpenSSH, Appx/winget/choco/scoop, MSRC end-to-end, vendor drift, Office; process snapshot from the script. |
| [on-open-network.md](on-open-network.md) | open-network | 19 | Validate every blocked source (Debian tracker, EPSS, NVD, EUVD, MSRC, KEV official, OSV API, formulae.brew.sh, cvelist modes, sizes); includes the "first hour" sync script. |
| [engine-and-quality.md](engine-and-quality.md) | any | 32 | Detection gaps, distro policy, VEX, confidence/priority calibration, test-suite gaps (property tests, golden e2e, CI matrix), performance. |
| [next-sources.md](next-sources.md) | any (per item) | 14 + 28-row backlog | Prioritized source backlog (other Linux distributions first), reachability probes of 2026-11-07, mapping targets, effort, where to develop/validate. |

Counts are the number of `- [ ]` checkboxes at `updated: 2026-11-07`; the backlog table in `next-sources.md` has 28 rows.

## How to use

1. **Pick the file for the machine you are on** (macOS laptop -> `on-macos.md`, Windows box -> `on-windows.md`, a Linux host with Docker and a second SSH-reachable server -> `on-linux-docker.md`, any laptop on an unrestricted network -> `on-open-network.md` first, it unblocks the rest).
2. Work through the checklist top to bottom; every item gives the exact commands, what to verify, and which doc/test to update. **Tick the box** (`- [x]`) when done and add the date and result in a short sub-bullet.
3. **Update the linked doc's frontmatter** (`sample: synthetic` -> `mixed`/`real`, `reachable:`, `status:`) and its Limitations/TODO text; **add real fixtures** (trimmed and anonymized: no hostnames, user names, serials, tokens) under the doc's `fixtures:` path with a README stating provenance, and a test that reads them.
4. Fix importers/collectors when a documented assumption turns out wrong (the assumptions are named in each item); keep the old synthetic fixture only if it still documents a case the real data does not.
5. When every box of a plan is ticked set its `status: done`, bump `updated:`, regenerate [../INDEX.md](../INDEX.md) with `uv run python scripts/docs.py index`.
6. New findings that belong to another platform go into **that** plan (one place per gap), not here.

Suggested order if you only have a day: `on-open-network.md` first hour -> Debian tracker + MSRC + NVD checks -> `engine-and-quality.md` section D (tests/CI) -> the platform you have at hand.
