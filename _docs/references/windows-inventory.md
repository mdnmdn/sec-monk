---
title: Windows inventory and Microsoft vulnerability data
type: reference
context: references
status: reference
tags: [windows, inventory, registry, msrc, cve, cpe]
updated: 2026-11-07
sample: mixed
reachable: partial
fixtures: tests/fixtures/sources/cvelist/microsoft/
code: src/secmonk/collectors/windows.py
related: [tech/collectors/windows.md, features/inventory-windows.md, references/vuln-sources/msrc.md, references/vuln-sources/cvelist-v5.md]
---

# Windows inventory and Microsoft vulnerability data

What Windows exposes about installed software, and how Microsoft's CNA records in the CVE List express
Windows and Office products. **Real** = fetched 2026-11-07 from `raw.githubusercontent.com`
(CVE List v5, saved in `tests/fixtures/sources/cvelist/microsoft/`). **From knowledge** = written from
memory, marked *unverified* (the dev sandbox is Linux; MSRC and NVD are blocked).

## 1. Where installed software lives

### 1.1 Registry Uninstall keys (the "Programs and Features" list)

| Hive / path | Holds |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<key>` | machine-wide installs, 64-bit view |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\<key>` | 32-bit software on a 64-bit OS. A 32-bit process is redirected here automatically: open with an explicit view (`KEY_WOW64_64KEY` / `KEY_WOW64_32KEY`, .NET `RegistryView`) |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<key>` | per-user installs (VS Code user installer, Slack, OneDrive, Teams classic, Chrome user install) |
| `HKU\<SID>\SOFTWARE\...\Uninstall` | the same for every **loaded** user hive. Users that are not logged in are not loaded (`NTUSER.DAT` would need `reg load`, a registry write; we do not do that and report them as `unloaded_profiles`) |
| `HKU\<SID>\SOFTWARE\WOW6432Node\...\Uninstall` | 32-bit per-user installs |

Only SIDs `S-1-5-21-*` (local/domain) and `S-1-12-1-*` (Entra ID) are user hives; skip `*_Classes`, `.DEFAULT`,
`S-1-5-18/19/20`. SID to user name: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>\ProfileImagePath`.

Values (all optional; there is no schema, installers write what they like):

| Value | Use |
|---|---|
| `DisplayName` | what the user sees. Often contains arch, locale, **and the version** (`7-Zip 23.01 (x64)`). Entries without it are not shown in Programs and Features: skip |
| `DisplayVersion` | version string; sometimes not the product version (Python `3.12.4150.0` for 3.12.4; Zoom `6.0.11 (33160)`) or a DWORD |
| `Publisher`, `InstallDate` (`YYYYMMDD` string), `InstallLocation` | vendor hint, date, path (often empty) |
| `SystemComponent` = 1 | hidden from the UI (drivers, runtimes, helper MSIs): skip |
| `ParentKeyName`, `ReleaseType` (`Update`, `Hotfix`, `Security Update`, `Update Rollup`, `Service Pack`) | the entry is a patch of another product: skip (KB entries also look like `KB5001716` / `(KB5002561)`) |
| `WindowsInstaller` = 1 | MSI product. The **key name is then the product code GUID** (`{AC76BA86-...}`), stable across versions of one product line (upgrade code is elsewhere) |
| `UninstallString`, `QuietUninstallString`, `DisplayIcon`, `EstimatedSize`, `VersionMajor/Minor` | not used |

Quirks: the same product often appears twice (x86 + x64 redistributables, machine + per-user), one product can
register several entries (Python: Core Interpreter, Standard Library, Documentation, Launcher...), .NET installers add
Runtime / Shared Framework / SDK / Host / Targeting Pack entries, Chocolatey/winget installs of MSI/EXE software appear here too.

### 1.2 Other package sources

| Source | Where / how | Notes |
|---|---|---|
| **MSI** | the GUID keys above; `Win32_Product` (WMI) is *not* used: slow and it triggers MSI self-repair | osquery `programs.identifying_number` = the GUID |
| **Appx / MSIX** | `Get-AppxPackage [-AllUsers]` (`-AllUsers` needs elevation): `Name`, `PackageFullName`, `Version`, `Publisher` (`CN=...`), `PublisherId`, `Architecture`, `SignatureKind` = `System` \| `Store` \| `Developer` \| `Enterprise` \| `None`, `IsFramework`, `NonRemovable`, `InstallLocation` | `System` = shipped with Windows (version follows the OS build). Frameworks (`Microsoft.VCLibs.140.00`, `Microsoft.UI.Xaml.*`, `Microsoft.NET.Native.*`) are plumbing. New Teams is the Appx `MSTeams`. |
| **winget** | `winget export -o file.json --include-versions`: `{Sources:[{SourceDetails:{Name}, Packages:[{PackageIdentifier, Version}]}]}`. `winget list` has no JSON output | per-user, needs the app-execution-alias (not available to SYSTEM), can hang on first run (source agreement) and hits the network: opt-in, 90 s timeout |
| **Chocolatey** | `%ChocolateyInstall%` (default `C:\ProgramData\chocolatey`)`\lib\<id>\<id>.nuspec` (`<id>`, `<version>`, `<title>`, `<authors>`, `<projectUrl>`) | no need to run `choco`. `.install` / `.portable` suffix packages are the real software, the bare id is a meta package |
| **Scoop** | `~\scoop\apps\<app>\current\manifest.json` (`version`, `homepage`) + `current\install.json` (`bucket`, `architecture`); global: `%ProgramData%\scoop`; `$env:SCOOP` overrides the root | portable apps: **not** in Uninstall keys. Per-user, so scan every profile directory |
| **.NET** | runtimes: directory names `dotnet\shared\<Microsoft.NETCore.App\|Microsoft.AspNetCore.App\|Microsoft.WindowsDesktop.App>\<version>` (= `dotnet --list-runtimes`) under `%ProgramFiles%\dotnet` (+ `\x64` on ARM64, `%ProgramFiles(x86)%\dotnet`); SDKs `dotnet\sdk\<version>`; registry `HKLM\SOFTWARE\dotnet\Setup\InstalledVersions\<arch>\sharedfx\<fx>` (values named by version). .NET Framework 4.x: `HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full` (`Release` DWORD: 533320 = 4.8.1, 528040+ = 4.8) | SDK versions (8.0.4xx) are not runtime versions: do not match them against runtime ranges |

### 1.3 OS identity

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`:

| Value | Example | Notes |
|---|---|---|
| `ProductName` | `Windows 10 Pro` | **says "Windows 10" on Windows 11** (never updated). Use `CurrentBuild >= 22000` => Windows 11 |
| `DisplayVersion` | `23H2` | exists since 20H2; older builds use `ReleaseId` (`1809`) |
| `CurrentBuild` / `CurrentBuildNumber` | `22631` | the build that CNA versions are keyed on |
| `UBR` | `3880` (DWORD) | update build revision, changes with every cumulative update: the 4th component of `10.0.22631.3880`. Missing on Windows 7 |
| `CurrentMajorVersionNumber` / `CurrentMinorVersionNumber` | `10` / `0` | absent before Windows 10 / Server 2016: `CurrentVersion` = `6.3` (2012 R2 and 8.1), `6.1` (7 / 2008 R2) |
| `EditionID` | `Professional`, `Enterprise`, `ServerDatacenter` | |
| `InstallationType` | `Client`, `Server`, `Server Core` | |
| `BuildLabEx`, `InstallDate` (epoch seconds), `CompositionEditionID` | | |

`winver` / `[Environment]::OSVersion` can lie under compatibility shims (they report 6.2 / 10.0.0 for unmanifested
processes); the registry is authoritative.

Build to product:

| Build | Client | Server |
|---|---|---|
| 10240 / 14393 / 17763 | Win10 1507 / 1607 / 1809 | - / Server 2016 / Server 2019 |
| 19044 / 19045 | Win10 21H2 / 22H2 | - |
| 20348 / 25398 | - | Server 2022 / Server 2022 23H2 Edition (Core only) |
| 22000 / 22621 / 22631 | Win11 21H2 / 22H2 / 23H2 | - |
| 26100 | Win11 24H2 | Server 2025 |
| 26200 | Win11 25H2 (from memory) | - |
| 9200 / 9600 / 7601 / 6003 | - | Server 2012 / 2012 R2 / 2008 R2 SP1 / 2008 SP2 |

Client and Server share builds (17763, 14393, 26100): `InstallationType` decides.

### 1.4 Patches

`Get-HotFix` = `Win32_QuickFixEngineering` (`HotFixID` = `KB...`, `Description`, `InstalledOn`, `InstalledBy`).
It is *incomplete* (does not list every servicing-stack/.NET/Defender update) and cumulative updates supersede each
other, so a KB list is **not** a reliable patch level: the **UBR** is. We keep KBs as context metadata only.
`Get-WindowsPackage -Online` / DISM list more, but are slow and need elevation.

### 1.5 osquery tables (Windows)

`programs` (`name`, `version`, `install_location`, `install_source`, `language`, `publisher`, `uninstall_string`,
`install_date`, `identifying_number` = MSI GUID; HKLM only in older releases), `os_version` (`name` =
`Microsoft Windows 11 Pro`, `version` = `10.0.22631`, `major`, `minor`, `build`, `arch`, `codename`, and in recent
osquery `revision` = UBR; *unverified*), `patches` (`hotfix_id`, `description`, `installed_on`, `installed_by`),
`registry` (generic; read `UBR`, `DisplayVersion`, `InstallationType` from `...\CurrentVersion`), `system_info`
(`hostname`), `appx_packages` (recent osquery), `windows_security_products`. osquery's `os_version.version` has **no
UBR**: without `revision` or a registry read the build is only `10.0.22631`, which cannot be compared with CNA
ranges (see below).

## 2. Vulnerability side: Microsoft CNA records in the CVE List (real)

Microsoft is a CNA (`providerMetadata.shortName = "microsoft"`) and publishes one record per CVE with
`affected[]` entries per product. Records examined (all saved as fixtures):

| CVE | What | Notes |
|---|---|---|
| CVE-2024-38063 | Windows TCP/IP RCE | 24 products, ranges per Windows/Server line; has `cpeApplicability` |
| CVE-2025-21418 | Windows AFD for WinSock EoP | 2025, adds Win11 24H2 / Server 2025 |
| CVE-2025-30400 | Windows DWM Core Library EoP | |
| CVE-2024-38021, CVE-2025-24057 | Outlook / Office RCE | Microsoft 365 Apps, Office 2016/2019/LTSC |
| CVE-2024-43472 | Edge (Chromium-based) EoP | |
| CVE-2024-38229 | .NET and Visual Studio RCE | |
| CVE-2025-21176 | .NET, .NET Framework and Visual Studio RCE | Framework 3.5/4.x products |
| CVE-2025-26682 | ASP.NET Core and Visual Studio DoS | |
| CVE-2023-24881 | Microsoft Teams info disclosure | |

### 2.1 Windows

```json
{ "vendor": "Microsoft", "product": "Windows 11 Version 23H2", "platforms": ["x64-based Systems"],
  "versions": [{ "version": "10.0.22631.0", "lessThan": "10.0.22631.4037", "versionType": "custom", "status": "affected" }] }
```

* **vendor** is always `Microsoft`; **product** is the Windows *release*, spelled by Microsoft (case varies:
  `Windows 11 Version 23H2` vs `Windows 11 version 22H2`; sec-monk lowercases everything).
* Product strings seen: `Windows 10 Version 1507 | 1607 | 1809 | 21H2 | 22H2`, `Windows 11 version 21H2 | 22H2 | 22H3`,
  `Windows 11 Version 23H2 | 24H2`, `Windows Server 2008 Service Pack 2`, `Windows Server 2008  Service Pack 2` (two
  spaces!), `Windows Server 2008 R2 Service Pack 1`, `Windows Server 2012`, `2012 R2`, `2016`, `2019`, `2022`, `2025`, each
  also as `... (Server Core installation)`, and `Windows Server 2022, 23H2 Edition (Server Core installation)`.
  There is **no** "Windows 11" or "Windows 10" without a version, and no edition (Home/Pro) split.
* **Quirk:** the ARM64 build of 23H2 is `Windows 11 version 22H3` (build 22631 too). Both rows carry the same range.
* **versions:** `version` = first build of the line, `lessThan` = the fixed build, `versionType: custom`, status
  `affected`, 4-part `10.0.<build>.<UBR>`. The start is `10.0.<build>.0`, except `10.0.0` for Win11 21H2 and `10.0.19043.0` for
  Win10 21H2 (whose range spans 19043 and 19044: 21H1 and 21H2 share a servicing line). Older Windows keep 6.x: `6.3.9600.0` -> `6.3.9600.22134`
  (2012 R2), `6.1.7601.0` (2008 R2), `6.0.6003.0` (2008). **Fixed build = the first build containing the fix**, i.e. a
  host is vulnerable iff `10.0.<CurrentBuild>.<UBR> < lessThan`.
* **platforms:** `x64-based Systems`, `ARM64-based Systems`, `32-bit Systems` (arch lists; same range for all). sec-monk
  keeps them in `affected.extra` and does not filter on them.
* **cpeApplicability** (same record) repeats it as CPE rows: `cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*`
  + `versionStartIncluding 10.0.22631.0` / `versionEndExcluding 10.0.22631.4037` (products `windows_10_1809`,
  `windows_10_22H2`, `windows_11_24H2`, `windows_server_2022`, `windows_server_23h2`...). The CPE name != the CNA product
  name; sec-monk's importer stores both (`range_type` CVE and CPE), so `windows 11 version 23h2` and `windows 11 23h2` rows coexist.
* `defaultStatus` is absent. Each CVE lists a **different subset** of products (only the supported ones affected by it), and
  older records list Windows 7/8.1 too.
* CVSS comes from `metrics` (`cvssV3_1`), and `adp[]` carries the CISA-ADP enrichment (see cvelist-v5.md).

### 2.2 Office / Microsoft 365 Apps

```json
{ "vendor": "Microsoft", "product": "Microsoft 365 Apps for Enterprise", "platforms": ["32-bit Systems", "x64-based Systems"],
  "versions": [{ "version": "16.0.1", "lessThan": "https://aka.ms/OfficeSecurityReleases", "versionType": "custom", "status": "affected" }] }
```

* Click-to-Run products (`Microsoft 365 Apps for Enterprise`, `Microsoft Office 2019`, `Microsoft Office LTSC 2021/2024`)
  have **no version in `lessThan`: it is the URL `https://aka.ms/OfficeSecurityReleases`** (the fixed build depends on the
  update channel). MSI products (`Microsoft Office 2016`) have a real bound (`16.0.5456.1000`); Mac LTSC has `16.95.25030928`.
* The sec-monk importer cannot use the URL: the CNA row becomes `CVE-UNPARSED` (safe: never matches), but the
  generated **CPE row** (`cpe:2.3:a:microsoft:365_apps:*:*:*:*:enterprise`) keeps only `introduced 16.0.1` with the end bound dropped
  (`extra.dropped_bounds`): an open-ended range that would match *every* 365 Apps build. The Windows alias table therefore maps the
  product to the CNA spelling (`microsoft 365 apps for enterprise`), so the CVE-UNPARSED row is looked up instead of the open CPE row.
  Real Office matching needs the channel/build tables on the Microsoft release-notes pages: not implemented.
* Installed 365 Apps: Uninstall key `O365ProPlusRetail - en-us`, DisplayName `Microsoft 365 Apps for enterprise - en-us`,
  DisplayVersion = build `16.0.17628.20144` (also `HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\VersionToReport`).

### 2.3 Edge, .NET, Visual Studio, Teams

| Product | CNA `product` | CPE (`cpeApplicability`) | Versions |
|---|---|---|---|
| Edge | `Microsoft Edge (Chromium-based)` | `microsoft:edge_chromium` | `1.0.0` -> `127.0.2651.105` (the Chromium-style 4-part version, equals the installed `DisplayVersion`) |
| .NET | `.NET 8.0`, `.NET 9.0` (one product per major, no vendor prefix) | `microsoft:.net` | `8.0.0` -> `8.0.10` (equals `dotnet --list-runtimes` version). **.NET Framework rows use the same CPE `.net`** with `4.8.0` -> `4.8.04775.01` |
| ASP.NET Core | `ASP.NET Core 8.0` | `microsoft:asp.net_core` | `8.0` -> `8.0.15` |
| .NET Framework | `Microsoft .NET Framework 3.5 AND 4.8` etc. (combos), `platforms` = Windows releases | | `4.8.0` -> `4.8.04775.01` (not the registry `Version`, e.g. `4.8.09032`) |
| Visual Studio | `Microsoft Visual Studio 2022 version 17.12` (one product per servicing baseline) | `microsoft:visual_studio` **or** `visual_studio_2022` / `_2019` / `_2017` (varies by record) | `17.12.0` -> `17.12.7` (installed `DisplayVersion` is the same 17.x.y) |
| Teams | `Microsoft Teams`, `Microsoft Teams for Desktop`, `... for iOS/Android/Mac` | `microsoft:teams` | `2.0.0` -> `2.10.1`; classic Teams was 1.x |
| PowerShell | `PowerShell 7.4` | | `7.4.0` -> `7.4.4` |

Edge/.NET/VS records carry **both** a product-string row (CNA) and CPE rows, with *different* product names
(`microsoft edge (chromium-based)` vs `edge chromium`); either one can be used for lookup. Visual Studio's product string
embeds the version (`version 17.12`), so the CPE rows are the only practical key.

### 2.4 What this means for matching

1. OS: component name `Windows 11 Version 23H2`, version `10.0.<CurrentBuild>.<UBR>`, `meta.product` = lowercase CNA string. The
   generic comparator works (`10.0.22631.3880 < 10.0.22631.4037`).
2. Without the UBR a version like `10.0.22631` equals `10.0.22631.0` and sorts **below every fix**: it would flag every CVE, so
   the collector emits no version (and a warning) instead.
3. CNA vendor/product spellings differ from NVD CPE vendors for many third-party apps (`win.rar GmbH` vs `rarlab`, `git` vs `git-scm`,
   `The Document Foundation` vs `libreoffice`): the matcher drops candidates whose vendor differs, so each alias entry picks one spelling.

## 3. MSRC CVRF v3 API (unverified: `api.msrc.microsoft.com` is blocked here)

From knowledge; see [vuln-sources/msrc.md](vuln-sources/msrc.md) for how sec-monk uses it.

* `GET https://api.msrc.microsoft.com/cvrf/v3.0/updates` (header `Accept: application/json`) -> `{"value":[{"ID":"2024-Aug","Alias":"2024-Aug","DocumentTitle":"August 2024 Security Updates","Severity":null,"InitialReleaseDate":...,"CurrentReleaseDate":...,"CvrfUrl":"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2024-Aug"}]}`
* `GET /cvrf/v3.0/cvrf/{YYYY-Mon}` -> CVRF document: `DocumentTracking`, `ProductTree.FullProductName[]` (`ProductID`, `Value`
  = `Windows 11 Version 23H2 for x64-based Systems`), `Vulnerability[]` (`CVE`, `Title.Value`, `Notes`, `CVSSScoreSets[]`
  `BaseScore`/`Vector`/`ProductID[]`, `Threats[]` (type 0 impact, 1 exploitability, 3 severity), `Remediations[]`).
  A remediation of `Type` 2 (Vendor Fix) has `Description.Value` = KB number, `URL`, `ProductID[]`, `Supercedence` (the KB it
  replaces), `RestartRequired`, `SubType` (`Security Update`, `Monthly Rollup`), and for Windows **`FixedBuild`** (`10.0.22631.4037`).
* Also `GET /cvrf/v3.0/cvrf/{CVE-id}` (a single-CVE document), `/cvrf/v3.0/updates('2024-Aug')`, and the `/sug/v2.0` Update
  Guide API (richer, needs the `api-key` header, not covered).
* Product names carry an arch suffix (`... for x64-based Systems`, `... for ARM64-based Systems`, `... for 32-bit Systems`) and Core
  products (`... (Server Core installation)`) that CNA strings do not; `Windows Server, version 23H2 (Server Core installation)` is CNA's
  `Windows Server 2022, 23H2 Edition (Server Core installation)`.
* Office/Apps remediations have no `FixedBuild` (channel-dependent), so MSRC does not solve the URL problem of 2.2.

## 4. Fixtures

`tests/fixtures/sources/cvelist/microsoft/*.json`: 10 real records listed in 2.
`tests/fixtures/collectors/windows/`: `inventory-win11.json`, `inventory-server2022.json`, `osquery-win11.json`: **synthetic**
(realistic shapes; Win11 build 22631.3880 chosen older than the CVE-2024-38063 fix 22631.4037).
