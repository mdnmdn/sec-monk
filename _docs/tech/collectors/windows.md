---
title: Windows collector
type: tech
context: tech
status: implemented
tags: [collector, windows, desktop, server, registry, msrc]
updated: 2026-11-07
sample: synthetic
fixtures: tests/fixtures/collectors/windows/
code: [src/secmonk/collectors/windows.py, src/secmonk/data/windows/secmonk-inventory.ps1]
related: [references/windows-inventory.md, features/inventory-windows.md, tech/engine/classification.md, tech/engine/matching.md, references/vuln-sources/msrc.md]
---

# Windows collector

The PowerShell script ships in `src/secmonk/data/windows/`; print it with `secmonk windows-script > secmonk-inventory.ps1`.

## Summary

Inventories a Windows desktop/server **without needing Windows at test time**. Input is one of:

| Mode | How | Notes |
|---|---|---|
| Script JSON (primary) | `secmonk scan windows inventory.json` | JSON from the PowerShell script (`secmonk windows-script > secmonk-inventory.ps1`) (schema `secmonk-windows-inventory/1`) |
| osquery | `secmonk scan windows -o osquery=results.json` | `{programs, os_version, patches, registry, system_info}` row lists |
| Live | `secmonk scan windows` **on Windows** | `winreg` for OS + Uninstall keys; PowerShell (best effort) for Appx + hotfixes; files for Chocolatey/Scoop/.NET |

**All fixtures are synthetic.** The PowerShell script itself is **untested on real Windows** (the sandbox has no PowerShell): it is
written for 5.1, ASCII-only and checked for balanced syntax only. Validate on a real machine before marking `reference`.

Public API (`collectors/windows.py`): `parse_inventory_json(data) -> Inventory`, `parse_osquery(data) -> Inventory`,
`collect_live() -> Inventory` (raises off Windows), `read_live_inventory() -> dict`, `windows_os_identity(os_info)`,
`normalize_display_name(raw)`, `inventory_script() -> str` (read with `importlib.resources` from `secmonk.data`).

## Where the data lives

See [references/windows-inventory.md](../../references/windows-inventory.md) for the registry paths, Appx, winget, Chocolatey, Scoop,
.NET and osquery details. The script reads, read-only: Uninstall keys in HKLM (64 + 32-bit views) and every **loaded** HKU hive
(`unloaded_profiles` lists the rest), `Get-AppxPackage`, `Win32_QuickFixEngineering`, `lib\*\*.nuspec`, scoop `manifest.json`,
`dotnet\shared` directories, `NDP\v4\Full`; optional `winget export`.

## Data format

JSON document: `{schema, script_version, collected_at, hostname, domain, is_admin, powershell_version, os{product_name,
display_version, release_id, current_build, ubr, edition_id, installation_type, current_version, major, minor, install_date,
architecture}, dotnet_framework{version,release}, uninstall[{hive, scope, sid, user, wow6432, key_name, display_name,
display_version, publisher, install_date, install_location, system_component, windows_installer, parent_key_name, release_type}],
appx[{name, package_full_name, version, publisher, architecture, signature_kind, is_framework, ...}], hotfixes[{id, description,
installed_on, installed_by}], chocolatey[{id, version, title, ...}], scoop[{app, version, bucket, architecture, user, global}],
winget[{id, version, source}] | null, dotnet_runtimes[{name, version, arch, path}], dotnet_sdks[], unloaded_profiles[], warnings[]}`.
Text is UTF-8 without BOM; the loader also accepts UTF-8 BOM and UTF-16 (what `powershell > file` writes).

## Classification

| Source | category | name / version | purl | identity |
|---|---|---|---|---|
| OS | `os` | `Windows 11 Version 23H2` / `10.0.<CurrentBuild>.<UBR>` | `pkg:generic/microsoft/windows@<ver>?release=11-23H2` | vendor `microsoft`, `meta.product` = CNA product (lowercase) |
| Uninstall entry | `application` | cleaned DisplayName / DisplayVersion | `pkg:generic/<publisher-slug>/<name>@<ver>` | alias table through `meta.product_hint` |
| Appx, `SignatureKind=System` | `system-app` | `Name` / `Version` | `pkg:generic/appx/<Name>@<ver>` | hint = lowercase Name (`MSTeams` -> microsoft teams) |
| Appx, other | `application` | same | same | same |
| Chocolatey | `package` | id / nuspec version | `pkg:chocolatey/<id>@<ver>` | hint = id minus `.install`/`.portable` |
| Scoop | `package` | app / manifest version | `pkg:generic/scoop/<app>@<ver>` | hint = app |
| .NET runtime | `runtime` | `.NET 8.0`, `ASP.NET Core 8.0`, `.NET Desktop Runtime 8.0` / `8.0.8` | `pkg:generic/microsoft/dotnet-runtime@8.0.8?arch=x64` | `meta.product` = `.net` / `asp.net core` (CPE spelling), name gives the CNA spelling |

### OS name and version

`windows_os_identity()` maps `CurrentBuild` (+ `InstallationType`, `DisplayVersion`) to the string Microsoft CNA records use:

* client `build >= 22000` -> `Windows 11 Version <22000:21H2, 22621:22H2, 22631:23H2, 26100:24H2, 26200:25H2>` (else `DisplayVersion`);
  `ProductName` says Windows 10 on Windows 11 and is only used (fixed up) for `Asset.os_name`.
* client `10240..19045` -> `Windows 10 Version <1507, 1607, 1809, 21H2, 22H2, ...>` (else `DisplayVersion` / `ReleaseId`).
* server -> `Windows Server 2016|2019|2022|2025|2012 R2|...` by build (`25398` = `Windows Server 2022, 23H2 Edition (Server Core installation)`).
  Server Core hosts use the base product: CNA lists it for the same CVEs (Core variants are extra products).
* `meta.product`: lowercase of the name, except build 22631 where it is `windows 11 version 22h3` (CNA's spelling for the ARM64
  build); the name itself is the second lookup candidate in `_match_product`, so both spellings are searched.
* `meta.product_source = "alias-table"` (curated build table in the collector) so the matcher uses confidence 0.8.
* Version = `<major>.<minor>.<CurrentBuild>.<UBR>`; **no UBR -> version None + warning** (a 3-part version would match every CVE).
* Hotfix KBs: `meta.hotfixes`, `meta.last_hotfix_on` of the OS component; never components.

### Display-name normalization

`normalize_display_name()`: removes parenthesised arch/locale tags (`(x64 en-US)`, `(64-bit x64)`), standalone arch tokens
(`x64`, `X86`, `64-bit`), a trailing ` - 14.38.33135`, the first embedded dotted version (`7-Zip 23.01`, `PuTTY release 0.81`), a locale tail
(` - en-us`) and trailing `release`/`version`; the removed version is used when `DisplayVersion` is missing (Python: DisplayVersion
`3.12.4150.0`, name `3.12.4` wins). The result is the component name and `meta.product_hint`; the original is `meta.display_name`.
`classify()` honors `meta.product_hint` as an extra alias key and as fallback product (small hook in `engine/classify.py`).
Windows aliases are in `data/product_aliases.yaml` (`# ---- windows` section; `[cna]` comments mark spellings checked against real CVE records).

### Filtering and dedupe

Skipped: `SystemComponent=1`, updates (`ParentKeyName`, `ReleaseType`, `KB` names), Python MSI sub-components, .NET Uninstall entries
(runtimes come from the dotnet directories; SDK versions are not runtime versions), Appx frameworks. Merged: x86+x64 duplicates and
machine+per-user duplicates with the same cleaned name+version (`meta.arch_variants`, `meta.scopes`); Chocolatey/Scoop packages equal (same alias
identity, same version) to an Uninstall program are dropped and noted as `meta.also_chocolatey` / `meta.also_scoop`. MSI GUID -> `meta.msi_product_code`.

### Asset

`windows:<hostname>`, `type` = `server` (Server SKUs) or `desktop`, `os_name` (`Windows 11 Pro`), `os_version` (`23H2 (build 22631.3880)`),
`platform` `windows/amd64|arm64|386`; meta: domain, is_admin, edition, dotnet_sdks, winget packages, collected_at.

## SSH integration contract

For Windows targets reached over OpenSSH (the `ssh` collector, built separately): run

```
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -
```
with `windows.inventory_script()` on stdin, read stdout as UTF-8 and call `windows.parse_inventory_json(json.loads(stdout))`;
the asset id then becomes `windows:<hostname>` (or override with `-o hostname=`). `inventory_script()` returns the script without blank/comment-only
lines and with CRLF newlines (blank lines are what most often confuse `-Command -` on a pipe). Fallbacks if stdin piping misbehaves: `scp` the script and
run `powershell -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\secmonk-inventory.ps1 -OutFile C:\Windows\Temp\inv.json`, then fetch the file.
The default OpenSSH shell on Windows is `cmd.exe`: a command longer than 8191 characters fails, so never pass the script as `-Command "<script>"`.
Detection: `ssh host ver` / `cmd /c ver` printing `Microsoft Windows` (uname does not exist).

## Limitations

*Describes current behaviour. What is still to do (and how to verify it) is tracked in the plan [on-windows.md](../../plans/on-windows.md); measurements and real-data validation are in the [probe log](../../references/probes.md).*

- Script untested on real Windows; live-mode `winreg` tested only against a fake module.
- Per-user software of users whose hive is not loaded is invisible (reported in warnings). Run as SYSTEM or while users are logged on.
- Office: Click-to-Run versions cannot be matched (CNA bound is a URL, see the reference doc). Microsoft Store apps match only through the alias table.
- ARM64 Windows 11 23H2 is `22H3` in CNA: covered via the second product candidate. Windows 10 LTSC/IoT, Windows 7/8.1 (no 4-part UBR rules tested) and Server 2008 are mapped but untested.
- CNA vs NVD vendor spelling drift drops some third-party matches (alias table picks one spelling).
- Only HKLM/HKU registry; software without an Uninstall key (portable apps, services) is found only through Scoop/Chocolatey.
- osquery without `os_version.revision` or a `registry` row for `UBR` yields no OS version (warning).

## Review fixes (2026-11)

- `os_version` never contains `None`: `<DisplayVersion> (build <build>.<UBR>)`, or `... (build <build>)` when the UBR is unknown.
- A document without hostname uses `-o hostname=` or the input file name (`web01.json` -> `windows:web01`; generic names such as
  `inventory.json` are not used) with a warning; with neither it is `windows:unknown` plus a loud warning.
