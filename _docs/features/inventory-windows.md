---
title: Windows inventory
type: feature
context: features
status: implemented
tags: [windows, inventory, registry, msrc, cli]
updated: 2026-11-07
code: src/secmonk/collectors/windows.py
related: [tech/collectors/windows.md, references/windows-inventory.md, features/inventory-ssh.md, features/vuln-sync.md, references/vuln-sources/msrc.md, references/probes.md, features/README.md]
---

# Windows inventory

## What the user gets

The software on a Windows desktop or server, matched against vulnerability data: the **Windows OS itself** (release + build +
update revision, e.g. `Windows 11 Version 23H2` build `10.0.22631.3880`), installed programs (machine-wide and per-user), Microsoft Store apps,
Chocolatey and Scoop packages and .NET runtimes. Patch KBs are kept as context. A host that is behind the fixed build of a Windows CVE gets a finding
with the fixed build as the target; a host at or above it gets none. The collection is a read-only PowerShell script with no modules and no agent.

## Usage

```bash
# 1. collect on the Windows host (PowerShell 5.1, any account; elevated also lists Appx packages of all users)
powershell -NoProfile -ExecutionPolicy Bypass -File secmonk-inventory.ps1 -OutFile inv.json
#    add -Winget for `winget export` (slow, per-user, optional)
#    get the script with `secmonk windows-script > secmonk-inventory.ps1` (`--compact` strips blank/comment lines, used for stdin over SSH)

# 2. match on the analyst machine
secmonk scan windows inv.json              # collect + save + match
secmonk collect windows inv.json           # inventory only

# live, when secmonk itself runs on the Windows host (no PowerShell needed for programs/OS)
secmonk scan windows

# osquery results (programs, os_version, patches, registry rows for UBR, system_info) merged in one JSON object
secmonk scan windows -o osquery=results.json

# remotely over OpenSSH on the Windows host (Intune: deploy the script and collect the -OutFile instead)
secmonk scan ssh admin@win-host
secmonk windows-script --compact | ssh admin@win-host 'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -' > inv.json
```

Vulnerability data: `secmonk sync cvelist` (Microsoft CNA records carry per-build fixed versions for Windows, .NET, Edge, Visual Studio) and optionally
`secmonk sync msrc` (CVRF fixed builds + KBs; needs `api.msrc.microsoft.com`, or `--path` for downloaded documents).

## Behaviour & rules

- OS name and version follow Microsoft's CNA spelling (build table, `CurrentBuild >= 22000` means Windows 11 although `ProductName` says Windows 10); no update revision means no OS version and a warning.
- Updates, hidden system components, duplicate 32/64-bit and per-user entries and .NET Uninstall entries are not listed; Chocolatey/Scoop packages that are also registered programs are not listed twice.
- Appx packages shipped with Windows are `system-app`; frameworks are skipped.
- Display names are cleaned (`Mozilla Firefox (x64 en-US)` becomes `Mozilla Firefox`, `7-Zip 23.01 (x64)` becomes `7-Zip`) and mapped to CVE vendor/product via the alias table.
- Users whose registry hive is not loaded are reported as warnings (their per-user installs are not seen).
- The script changes nothing (registry/file reads, standard cmdlets); output is UTF-8 JSON on stdout or in `-OutFile`.

## Validation status

All Windows fixtures are **synthetic**; the 10 Microsoft CNA records they are matched against are **real** (CVE List, fetched 2026-11-07). The PowerShell script has never run on a real Windows host (the dev sandbox is Linux), and MSRC (`api.msrc.microsoft.com`) is unreachable from the sandbox, so `sync msrc` is fixture-tested only. Status stays `implemented` for the code path; real-host validation is open (see [windows-inventory reference](../references/windows-inventory.md), [probe log](../references/probes.md)).

## Acceptance criteria

- A Windows 11 23H2 inventory at `10.0.22631.3880` yields a finding for CVE-2024-38063 (`cve-product`, fixed `10.0.22631.4037`); at `22631.4037` it does not.
- A Server 2022 inventory at `10.0.20348.2655` matches the same CVE with fixed `10.0.20348.2700`.
- Edge 126.0.2592.87 matches CVE-2024-43472, .NET 8.0.8 matches CVE-2024-38229, Visual Studio 17.12.2 matches CVE-2025-26682.
- osquery results without a UBR produce no OS findings rather than false ones.
- `secmonk collect windows <fixture> --quiet` exits 0.

## Implemented by

[tech/collectors/windows.md](../tech/collectors/windows.md), [references/windows-inventory.md](../references/windows-inventory.md)
