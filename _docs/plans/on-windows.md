---
title: Plan - on Windows
summary: Checklist to run the PowerShell inventory script, live winreg mode, osquery input, Windows OpenSSH and MSRC matching on real Windows machines.
read_when: you are on Windows and want to verify the inventory script, live mode, OpenSSH or Windows CVE matching
type: plan
context: plans
status: open
platform: windows
tags: [plan, windows, powershell, registry, msrc, ssh]
updated: 2026-11-07
verified: 2026-11-07
related: [tech/collectors/windows.md, features/inventory-windows.md, references/windows-inventory.md, references/vuln-sources/msrc.md, tech/collectors/ssh.md]
---

# Plan: what to do on Windows

The Windows collector is **fixture-tested on Linux only**: the PowerShell script `src/secmonk/data/windows/secmonk-inventory.ps1`
(`secmonk windows-script`) has **never been executed** (no PowerShell in the sandbox), live `winreg` mode was tested against a fake module, the
OpenSSH path against a fake transport, osquery input against a synthetic JSON. Machines: one Windows 11 (23H2 or 24H2) desktop with Office/M365 +
a few third-party apps + winget/scoop/choco, one Windows Server 2022/2025 (VM ok), ideally one Windows 10 22H2. PowerShell **5.1 and 7** both.

Setup (Python side, once; needs Python 3.13 + uv, or just run the script and copy the JSON to a Linux/Mac box):

```powershell
git clone <repo> sec-monk; cd sec-monk; uv sync
uv run pytest -q tests\collectors\test_windows.py tests\collectors\test_ssh_windows.py   # baseline on Windows (path separators!)
```

Real outputs (anonymized: hostname, user names, SIDs, serials) go to `tests\fixtures\collectors\windows\real\`; flip `sample:` in
[windows.md](../tech/collectors/windows.md) afterwards.

## A. PowerShell inventory script

- [ ] **Run in Windows PowerShell 5.1 (elevated and non-elevated).**
  ```powershell
  uv run secmonk windows-script > $env:TEMP\secmonk-inventory.ps1
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\secmonk-inventory.ps1 -OutFile $env:TEMP\inv51.json
  Get-Content $env:TEMP\inv51.json -Raw | ConvertFrom-Json | Select-Object -ExpandProperty warnings
  ```
  Verify: no parse errors; valid JSON (UTF-8 **without** BOM - Python `json.load` must read it; test `uv run secmonk collect windows $env:TEMP\inv51.json`);
  keys equal the synthetic `inventory-win11.json` (os build, UBR, uninstall entries, appx, choco, scoop, dotnet); warnings listed for non-elevated run.
  Fix the script and update the synthetic fixtures to match. Update [windows.md](../tech/collectors/windows.md) "Script untested" lines.
- [ ] **Run in PowerShell 7 (`pwsh`)** and compare with 5.1.
  ```powershell
  pwsh -NoProfile -File $env:TEMP\secmonk-inventory.ps1 -OutFile $env:TEMP\inv7.json
  fc.exe /b $env:TEMP\inv51.json $env:TEMP\inv7.json    # expect small diffs only; compare sets below
  Compare-Object ((gc $env:TEMP\inv51.json -Raw|ConvertFrom-Json).uninstall.DisplayName) ((gc $env:TEMP\inv7.json -Raw|ConvertFrom-Json).uninstall.DisplayName)
  ```
  Verify: `Get-AppxPackage -AllUsers` needs elevation in 5.1 and a compat shim in 7 (`Import-Module Appx -UseWindowsPowerShell`) - check Appx is not silently empty in pwsh.
- [ ] **Constrained language mode / AppLocker / ExecutionPolicy AllSigned** (enterprise): run under `$ExecutionContext.SessionState.LanguageMode='ConstrainedLanguage'`
  (`powershell -Command "[Environment]::SetEnvironmentVariable('__PSLockdownPolicy','4','Machine')"` then new shell; revert after) and record what breaks. Decide: document, or sign the script.
- [ ] **OS identification: build + UBR on real systems** (Win10 22H2, Win11 23H2/24H2/25H2, Server 2019/2022/2025).
  ```powershell
  (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion') | Select ProductName,DisplayVersion,CurrentBuild,UBR,EditionID,InstallationType
  winver; [Environment]::OSVersion.Version
  ```
  Verify: the asset's OS component version is `10.0.<CurrentBuild>.<UBR>` and `meta.product` maps to the CNA product string for **each** SKU
  (Win11 25H2? ARM64 `22H3`; Server Core; LTSC/IoT; Windows 11 Enterprise multi-session). Add every seen mapping to the collector tests; this is the
  base of all Windows matching ([windows-inventory.md](../references/windows-inventory.md) section 2.4).
- [ ] **Uninstall keys: 64/32-bit views, HKU loaded hives, per-user installs, `SystemComponent=1`, MSI vs EXE, missing DisplayVersion.** Run as the logged-in user and as SYSTEM
  (`psexec -s -i powershell`) and compare counts with `Get-Package` / "Installed apps" UI. Verify: per-user software of **not loaded** hives is reported in warnings (documented), Office
  Click-to-Run `O365ProPlusRetail - en-us` entry appears with the build as DisplayVersion.
- [ ] **Appx/MSIX, winget, Chocolatey, Scoop on real hosts.**
  ```powershell
  Get-AppxPackage -AllUsers | Measure-Object; winget list --accept-source-agreements | Measure-Object -Line
  choco list --local-only; scoop list; scoop export
  uv run secmonk inventory show <asset> --category application | Select-String -Pattern 'appx|choco|scoop'
  ```
  Verify: counts reconcile; dedupe between Uninstall key and winget entries (same app twice?); Store apps match only through the alias table (documented) - list the top 20 unmatched and
  feed `src/secmonk/data/product_aliases.yaml` (see [engine-and-quality.md](engine-and-quality.md) "alias table growth").
- [ ] **Portable apps / services without an Uninstall key** (documented gap: only via Scoop/Chocolatey). Install 7-Zip portable, Sysinternals, Node via nvm-windows; note what is invisible;
  decide whether `Get-Service`/`Get-Process` module paths or `Get-ChildItem` of `Program Files` file versions are worth adding.

## B. Live `winreg` mode (no script) and osquery input

- [ ] **Live mode on Windows with Python.**
  ```powershell
  uv run secmonk scan windows --db $env:TEMP\win.db
  uv run secmonk inventory show <asset-id> --db $env:TEMP\win.db | more
  ```
  Verify: same component set as the script output of section A (diff purls); both 64- and 32-bit views read (`KEY_WOW64_64KEY`/`32KEY`); HKU loaded hives; no admin needed for HKLM reads.
  Replace the fake-`winreg` test with one that also validates the real output shape.
- [ ] **osquery input.**
  ```powershell
  winget install osquery.osquery
  osqueryi --json "select * from os_version; select name,version,publisher,install_location from programs; select * from registry where path like 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UBR'; select * from patches;" > $env:TEMP\osq.json
  uv run secmonk scan windows -o osquery=$env:TEMP\osq.json --db $env:TEMP\win2.db
  ```
  Verify: keys the importer expects (`os_version.revision` = UBR, `programs`, `patches`, `registry` row for UBR) exist in real osquery output; without them the documented warning appears; one file vs a
  multi-query export shape. Replace synthetic `osquery-win11.json` with a trimmed real one; check Fleet/`osqueryi --json` single-array vs map layouts.

## C. Windows OpenSSH (fake transport only so far)

Needs a Linux/macOS machine (or WSL) with secmonk, and a Windows host with **OpenSSH Server** (`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; Start-Service sshd`).

- [ ] **Default shell cmd.exe** (the stock setting).
  ```bash
  uv run secmonk scan ssh admin@win-host -o verbose=true --db /tmp/winssh.db
  uv run secmonk scan ssh admin@win-host -o os=windows --db /tmp/winssh2.db      # skips the POSIX probe
  ```
  Verify: detection (`ver` prints `Microsoft Windows`, POSIX probe fails cleanly), script piped via `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -` over stdin works
  (blank lines / CRLF are the known pitfall; `secmonk windows-script --compact`), result equals local script output (section A).
- [ ] **Default shell PowerShell** (`New-ItemProperty HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value 'C:\Program Files\PowerShell\7\pwsh.exe'`) and **8191-char cmd limit**: confirm no inline `-Command "<script>"`; fallback `scp` + `-File` path described in [ssh.md](../tech/collectors/ssh.md) works.
- [ ] **Admin vs standard user, key auth with `administrators_authorized_keys`, ProxyJump through Linux**, host with spaces in user name / domain accounts (`DOMAIN\user@host`): record failures, fix, test. Update [inventory-ssh.md](../features/inventory-ssh.md).

## D. Vulnerability matching on real Windows data

- [ ] **MSRC CVRF end-to-end (requires open network).**
  ```powershell
  uv run secmonk sync msrc --since 2024-01-01 --db $env:TEMP\win.db
  uv run secmonk scan windows --db $env:TEMP\win.db
  uv run secmonk findings --db $env:TEMP\win.db | more
  ```
  Verify on an **unpatched** Win11 VM (older UBR): findings = CVEs whose `FixedBuild` > installed UBR; on a fully patched box: zero OS findings; Server Core / ARM64 product-name
  normalization hits. Schema validation of the CVRF JSON itself is in [on-open-network.md](on-open-network.md) ("MSRC").
- [ ] **Vendor drift (CNA vs NVD spellings) on real software.** For the top ~40 installed third-party apps (7-Zip, WinRAR, Git, VLC, Notepad++, Chrome, Firefox, Zoom, Adobe Reader, Java, PuTTY, LibreOffice):
  ```powershell
  uv run secmonk inventory unmatched --db $env:TEMP\win.db
  uv run secmonk vuln search --package "winrar" --db $env:TEMP\win.db
  ```
  Verify: for each, which vendor/product spelling the **CVE List v5 CNA** uses vs **NVD CPE**; add an alias (one spelling per entry is a documented limitation - consider letting an alias carry several spellings). Output: a table in
  [windows-inventory.md](../references/windows-inventory.md) and new rows in `product_aliases.yaml`.
- [ ] **Office / M365 matching (not implemented; CNA bound is the URL `https://aka.ms/OfficeSecurityReleases`).** On a machine with M365 Apps (Current, Monthly Enterprise, Semi-Annual channels) and one with Office LTSC 2021:
  ```powershell
  (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration') | Select VersionToReport,UpdateChannel,CDNBaseUrl,Platform
  ```
  Verify: collect channel + build; confirm the CVE-UNPARSED/aliased lookup never matches (no open-ended 365-Apps range). The design (channel/build tables scraped from the Office release notes, or MSRC Update Guide `/sug/v2.0` with an API key) is tracked in
  [next-sources.md](next-sources.md) ("Office release tables").
- [ ] **Windows 10 LTSC/IoT, Windows 7/8.1, Server 2008/2012 R2** mapping (listed as "mapped but untested"): run on any such VM or feed historical `winver` outputs into the test suite; check 4-part UBR comparison.
- [ ] **.NET / Visual Studio / Edge / Teams / WebView2** on the real host: compare found versions against the CNA product strings listed in [windows-inventory.md](../references/windows-inventory.md) section 2.3; log mismatches as alias entries.

## F. Process monitor: Windows backend (not implemented; design in tech/collectors/process.md "Porting")

- [ ] **Emit a process snapshot from the PowerShell script** (or a `collectors/process/windows.py` backend for live runs):
  `Win32_Process` (ProcessId, ParentProcessId, ExecutablePath, CommandLine redacted, CreationDate), services
  (`Win32_Service` PathName/ProcessId -> `label`), Run/RunOnce keys, Startup folders, scheduled task actions as
  `launch_items`; per executable precompute `identity` (file `VersionInfo` ProductName/ProductVersion/CompanyName,
  owning Uninstall entry), `Zone.Identifier` (ZoneId, HostUrl, ReferrerUrl) as provenance and
  `Get-AuthenticodeSignature` as `signature`. Analyse with `secmonk procs snap.json` on any OS.
  Verify: `svchost.exe -k` groups map to their services; Explorer-launched apps -> `gui-app`; WindowsTerminal/conhost
  shells -> `interactive`; a downloaded exe shows its `HostUrl`.

## E. Wrap-up

- [ ] Commit real fixtures; set `sample: mixed` or `real` in `tech/collectors/windows.md`, `features/inventory-windows.md`, `references/windows-inventory.md`; update Limitations; regenerate INDEX.
