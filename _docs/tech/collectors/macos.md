---
title: macOS collector
summary: macOS collector reading a filesystem root covering app bundle Info.plist, Electron runtimes, Homebrew, pkgutil receipts, OS version, classification and limits.
read_when: you change how macOS apps, bundled runtimes or receipts are discovered and identified
type: tech
context: tech
status: implemented
tags: [collector, macos, desktop, homebrew]
updated: 2026-11-08
verified: 2026-11-08
sample: mixed
fixtures: tests/fixtures/collectors/macos/
related: [features/inventory-macos.md, tech/engine/classification.md]
code: src/secmonk/collectors/macos.py
---

# macOS collector

## Summary

Discovers software on a macOS host **without needing macOS at test time**: the collector takes a
filesystem root (`/` on a live Mac, or `tests/fixtures/collectors/macos/root/` in tests) and reads
plists and JSON with the Python stdlib (`plistlib` reads XML *and* binary plists). Four sources:

1. `.app` bundles (`Info.plist`) incl. Electron/Chromium bundled runtime detection.
2. Homebrew formulae (Cellar receipts) and casks (Caskroom metadata).
3. `pkgutil` receipts (`/var/db/receipts/*.plist` and, for Apple's own, `/Library/Apple/System/Library/Receipts/*.plist`).
4. The OS itself (`SystemVersion.plist`) as a component `cpe:2.3:o:apple:macos:<ver>`.

Fixtures in `tests/fixtures/collectors/macos/` are **synthetic** (hand-built from known real formats; binary plist
generated with `plistlib.FMT_BINARY`), except `real/`: real files captured on 2026-11-08 on macOS 26.5 (25F71, arm64)
in a restricted session (`SystemVersion.plist`, three Apple receipts, `pkgutil --pkg-info` output, the empty
`system_profiler` output, an Apple launchd plist with an unquoted XML prolog; provenance in `real/README.md`).

## Where the data lives

| What | Path (relative to root) | Notes |
|---|---|---|
| User-installed apps | `Applications/*.app`, `Users/*/Applications/*.app` | Recurse one level into subfolders (`Applications/Utilities/`, vendor folders like `Microsoft Office`). Do **not** recurse into `Contents/` for nested apps except helper detection (below). |
| System apps | `System/Applications/*.app`, `System/Applications/Utilities/*.app` | Read-only sealed volume since Big Sur. Flag `category=os-component`. Also `System/Library/CoreServices/*.app` (Finder, etc.) if desired. |
| App Info.plist | `<App>.app/Contents/Info.plist` | XML or binary; `plistlib.load()` autodetects. |
| Electron runtime | `<App>.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist` | `CFBundleVersion` / `CFBundleShortVersionString` = Electron version. |
| MAS receipt | `<App>.app/Contents/_MASReceipt/receipt` | Presence = Mac App Store app (PKCS#7, not needed to parse). |
| Sparkle | `Info.plist` key `SUFeedURL` (+ `SUPublicEDKey`) | Update channel hint; also `Contents/Frameworks/Sparkle.framework`. |
| Homebrew prefix | `opt/homebrew` (Apple Silicon), `usr/local` (Intel; also `usr/local/Homebrew`) | Probe both. Linuxbrew: `home/linuxbrew/.linuxbrew`. |
| Formulae | `<prefix>/Cellar/<formula>/<version>/INSTALL_RECEIPT.json` | Several versions may coexist; `opt/<formula>` symlink points to the active one. |
| Casks | `<prefix>/Caskroom/<cask>/<version>/` and `<prefix>/Caskroom/<cask>/.metadata/<version>/<timestamp>/Casks/<cask>.json` (new) or `.rb` (old, also still written) | |
| pkg receipts | `var/db/receipts/<PackageIdentifier>.plist` (+ `.bom`): third-party; `Library/Apple/System/Library/Receipts/<id>.plist` (+ `.bom`): Apple (CLT, XProtect, MobileAssets, GarageBand content...) since macOS 10.15 | Readable by all users. On macOS 26.5 all 87 receipts of `pkgutil --pkgs` were in the Apple directory (2026-11-08). A package id present in both is counted once (first directory wins). |
| OS version | `System/Library/CoreServices/SystemVersion.plist` | |

No elevated privileges are needed for any of these on a default install (receipts and /Applications
are world-readable; TCC may block `~/Library` and Desktop/Documents but not `~/Applications`). A sandboxed or
otherwise restricted session can still be denied any of them (see Limitations).

## Data format

### App Info.plist

Fixtures: `root/Applications/Google Chrome.app/Contents/Info.plist` (XML),
`root/Applications/Utilities/Something.app/Contents/Info.plist` (**binary**, `bplist00` magic).

| Key | Use |
|---|---|
| `CFBundleIdentifier` | Stable id (reverse DNS) -> asset-unique key; first label(s) give a vendor hint (`com.google.Chrome` -> google). |
| `CFBundleName` / `CFBundleDisplayName` | Name; prefer DisplayName, fall back to Name, then the folder name (Info.plist names are sometimes localized in `InfoPlist.strings` - ignore). |
| `CFBundleShortVersionString` | Marketing version = **component version** (e.g. `126.0.6478.127`). |
| `CFBundleVersion` | Build number; fall back when ShortVersion is missing; sometimes the only meaningful one (e.g. VS Code uses the same). Keep both as properties. |
| `LSMinimumSystemVersion` | Property only. |
| `NSHumanReadableCopyright` | Free text, regex for the vendor: `Copyright (c) 2024 Google LLC` -> "Google LLC". Weak hint only. |
| `SUFeedURL` | Sparkle appcast host = vendor/update hint. |
| `KSProductID`, `KSUpdateURL` | Google Keystone (Chrome). |
| `ElectronAsarIntegrity` | Presence suggests Electron (recent versions). |

System apps (Safari 17.5, Disk Utility) have `CFBundleVersion` = WebKit-style build (`19618.2.12.11.6`);
their real version is the OS/Safari release. Treat them as `os-component`, version-tied to macOS.

### Electron / bundled runtimes (important for CVEs)

An Electron app ships its own Chromium + Node. The app version (Slack 4.38.125) is useless for
Chromium CVEs; the Electron version is. Detection:
`Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist`
-> `CFBundleVersion` (fixtures: Slack -> `30.1.2`, VS Code -> `29.4.0`). Emit an additional component
`electron@30.1.2` (`pkg:npm/electron@30.1.2`, `cpe:2.3:a:electronjs:electron:30.1.2`), with
`parent=<app bundle id>`. Chromium version is derivable via the Electron->Chromium release table
(Electron 30 = Chromium 124); on a real Mac one can additionally read the
`Electron Framework` binary string `Chrome/<ver>` - future. Other bundled frameworks worth listing
(just names+versions, from each `*.framework/Versions/*/Resources/Info.plist`): `Sparkle`,
`Chromium Embedded Framework` (CEF apps: Spotify, Steam), `Squirrel`, `Mantle`, `ReactiveObjC`.
Other bundled runtimes: `Contents/Frameworks/Python.framework`, `Contents/Resources/jre`, `Contents/PlugIns/*.jre`
(Java), Qt (`QtCore.framework`) - future.

### Homebrew

> The filesystem walk now lives in the standalone [Homebrew collector](homebrew.md) (active kegs only, casks, vendored packages, Linuxbrew); `macos.py` calls `collect_prefixes()` and keeps the cask <-> app dedupe. The notes below are the original format research.

**Formula receipt** (`INSTALL_RECEIPT.json`; fixtures `root/opt/homebrew/Cellar/{openssl@3/3.3.1,curl/8.7.1}/`).
Relevant keys: `source.tap` ("homebrew/core"), `source.versions.stable`, `installed_on_request`,
`installed_as_dependency`, `runtime_dependencies[]` (`full_name`, `version`, `pkg_version`,
`declared_directly`), `built_as_bottle`, `arch`, `time` (epoch of install), `homebrew_version`.
**The formula name and version come from the directory names**, not the receipt: `Cellar/<name>/<version>`
where `<version>` can carry a revision suffix `3.3.1_1` (= `version` + `_` + `revision`; strip `_N` for matching).
Receipt can be missing on very old installs (fallback to dir names). Unversioned `openssl@3` means the
versioned-formula `@3` is part of the *name*.

**Cask**: `Caskroom/<cask>/<version>/` holds the staged artifact(s) (version dir name may be `latest`
for `version :latest` casks - then read the real version from the installed `.app` Info.plist).
Metadata JSON (fixture `.../visual-studio-code/.metadata/1.90.0/20240612094501.123/Casks/visual-studio-code.json`):
`token`, `version`, `name[]`, `homepage`, `url`, `artifacts[]` (`app`, `pkg`, `uninstall`, `zap`). Older installs only have
`.rb`. Cask apps also appear in `/Applications` as normal bundles; **dedupe**: if an `.app` bundle's name equals a
cask `artifacts.app` entry, keep one component (the app bundle, version from Info.plist) and add the cask token as alias/property.

**Via brew CLI**: `brew info --json=v2 --installed` (fixture `brew-info.json`, synthetic but shape-accurate). Top level `{"formulae":[...],"casks":[...]}`.
Formula object: `name`, `full_name`, `tap`, `desc`, `license`, `homepage`, `versions.{stable,head,bottle}`, `revision`,
`urls.stable.url` (upstream source tarball - **useful** for name->upstream mapping), `dependencies[]`, `keg_only`,
`installed[]` (`version`, `installed_on_request`, `installed_as_dependency`, `runtime_dependencies`, `time`),
`linked_keg`, `outdated`, `deprecated`, `disabled`. Cask object: `token`, `name[]`, `version`, `installed`,
`installed_time`, `homepage`, `url`, `artifacts[]`, `auto_updates`. `brew info --json=v2 --installed` is slow (~1-3 s, may
hit the network for API data) and must not be required: **prefer the filesystem walk; use the CLI only as optional enrichment** (homepage, urls.stable.url, license).
Never run brew as root; never execute anything from a scanned tree.

### pkgutil receipts

Fixtures `root/var/db/receipts/com.example.pkg.plist`, `com.apple.pkg.CLTools_Executables.plist` (synthetic XML plists) and
`real/receipts/*.plist` (real binary plists from `/Library/Apple/System/Library/Receipts/`, with the matching `pkgutil --pkg-info`
output: version and install time agree for all 87 receipts of the capture Mac). `InstallDate` is a naive UTC datetime and equals
`pkgutil`'s `install-time`. Keys: `PackageIdentifier`, `PackageVersion`, `InstallDate` (plistlib -> `datetime`), `InstallPrefixPath`,
`InstallProcessName`, `PackageFileName` (sometimes absent). The `.bom` (bill of materials, binary) lists files; ignore for now.
CLI equivalents: `pkgutil --pkgs`, `pkgutil --pkg-info-plist <id>`, `pkgutil --files <id>`. Receipts include many `com.apple.pkg.*`
(Xcode CLT, Rosetta, XProtect) - mark `os-component` when the id starts with `com.apple.`; CLT/Xcode versions are CVE-relevant (git, clang bundled).
Receipts are not removed when the app is deleted - **stale receipts** produce phantom components: on the capture Mac
(2026-11-08, Full Disk Access) 61 of 157 third-party receipts listed no file that still exists (old .NET SDK packs, Citrix,
Skype for Business, 1Password 7). `InstallPrefixPath` cannot tell them apart (129/157 prefixes are plain `Applications`; the 9
missing prefixes are updater staging folders whose apps are installed): detecting staleness needs the `.bom` file list
(not parsed; open decision in the plan). `PackageIdentifier` is stripped (`org.swiftwasm.2024116 ` has a trailing space;
`pkgutil` prints it stripped). Real run: 257 receipts = `pkgutil --pkgs`, all versions equal `pkgutil --pkg-info`.

### OS version

`System/Library/CoreServices/SystemVersion.plist` (fixture): `ProductName` (macOS), `ProductVersion` (`14.5`; on
Big Sur+ may read `10.16` for old binaries via compat only - the file itself is right), `ProductBuildVersion` (`23F79`),
`ProductUserVisibleVersion`. Rapid Security Responses add a suffix in `ProductVersionExtra` (`(a)`). Equivalent: `sw_vers`.
Emit component `macos` `14.5`, `cpe:2.3:o:apple:macos:14.5:*:*:*:*:*:*:*`, category `os`.

### system_profiler (optional)

`system_profiler SPApplicationsDataType -json` (fixtures `system_profiler-applications.json`, synthetic, and
`real/system_profiler-applications.json`, 13 of 707 real entries): `{"SPApplicationsDataType":[{_name, path, version, arch_kind, lastModified, obtained_from, signed_by[], info}]}`.
Real shape verified 2026-11-08 (macOS 26.5): exactly these keys; `version` absent on 52/707, `signed_by` on 579, `info` on 133;
`obtained_from` also `ios_app_store`; `arch_kind` values `arch_arm_i64`, `arch_arm`, `arch_i64`, `arch_ios`, `arch_other`, `arch_i32`.
Of 707 apps, 431 are outside the collector's walk (`/System/Library` 229, the user's home 110, `/Library/...` vendor
helpers, printer drivers, `/usr/local`): this is the opt-in path to them.
Useful extras: `obtained_from` (apple / mac_app_store / identified_developer / unknown), `signed_by` (Team ID in parentheses = strong vendor identity).
Slow (10-60 s) and includes only what Spotlight indexed; keep as optional enrichment. In a restricted session
(macOS 26.5, 2026-11-08) it printed an empty `SPApplicationsDataType` array (fixture `real/system_profiler-applications-restricted.json`):
the collector then warns that the export lists no applications. The real field shape is still unverified. osquery `apps` table (`bundle_identifier`,
`bundle_short_version`, `bundle_version`, `path`) gives the same as our direct walk, `homebrew_packages`/`package_receipts` tables are equivalent to the above.

## Classification

| Source | category | PURL | CPE (hint) |
|---|---|---|---|
| macOS | `os` | `pkg:generic/macos@14.5` | `cpe:2.3:o:apple:macos:14.5:*:*:*:*:*:*:*` |
| System app (`/System/Applications`) | `os-component` | `pkg:generic/apple/safari@17.5` | `cpe:2.3:a:apple:safari:17.5:...` |
| `.app` bundle | `application` | `pkg:generic/<vendor>/<name>@<ver>?bundle_id=<CFBundleIdentifier>` | from vendor+product guess; curated map `bundle_id -> cpe vendor:product` (e.g. `com.google.Chrome` -> `google:chrome`, `org.mozilla.firefox` -> `mozilla:firefox`) |
| Electron runtime | `runtime` | `pkg:npm/electron@30.1.2` | `cpe:2.3:a:electronjs:electron:30.1.2` |
| Brew formula | `package` | `pkg:brew/<name>@<version>` (tap in namespace if non-core: `pkg:brew/owner/tap/name@v`; `@` in names is percent-encoded: `pkg:brew/openssl%403@3.3.1`) | via name->upstream map |
| Brew cask | `application` | `pkg:brew/homebrew/cask/<token>@<ver>` (our convention; spec only defines `tap`) | as `.app` |
| pkg receipt | `package` | `pkg:generic/<PackageIdentifier>@<ver>` | none (unknown) |

**PURL**: the purl-spec **does** list a `brew` type (checked 2026-11-07 in
`raw.githubusercontent.com/package-url/purl-spec/main/purl-types-index.json` and `types/brew-definition.json`): namespace = tap
(optional, default `homebrew/core`, lowercase), name = formula (lowercase, `@` -> `%40`), version optional, qualifier `repository_url`
for third-party taps. Examples from spec: `pkg:brew/sqlite@3.43.2`, `pkg:brew/postgresql%4012@12.17`.

**Matching problem**: OSV has **no Homebrew ecosystem** (checked `osv-vulnerabilities.storage.googleapis.com/ecosystems.txt` 2026-11-07:
AlmaLinux, Alpine, Debian, Go, GitHub Actions, Maven, npm, NuGet, PyPI, Red Hat, Rocky, RubyGems, SUSE, Ubuntu, crates.io, ... no Homebrew/macOS). So brew
formulae must be matched by **upstream project name + version**, i.e. NVD CPE / CVE `affected` ranges / OSV GIT ranges, not by a brew ecosystem.
Steps: (1) curated alias table formula -> `cpe vendor:product` (`openssl@3` -> `openssl:openssl`, `curl` -> `haxx:curl`, `python@3.12` -> `python:python`,
`node` -> `nodejs:node.js`; strip `@N`, `-` variants); (2) fall back to the formula `homepage`/`urls.stable.url` (from `brew info`) to derive
vendor/product; (3) version = brew version minus `_N` revision. Bottle rebuilds/backports are rare (Homebrew tracks upstream versions), so plain upstream version comparison is good.
Note `homebrew/core` is also available as the public JSON API `https://formulae.brew.sh/api/formula.json` (not probed here).

## Limitations

*Describes current behaviour. What is still to do (and how to verify it) is tracked in the plan [on-macos.md](../../plans/on-macos.md); measurements and real-data validation are in the [probe log](../../references/probes.md).*

- Checked on a real Mac with Full Disk Access (macOS 26.5 arm64, 2026-11-08): every top-level `.app` on disk in
  `/Applications`, `/System/Applications`, `~/Applications` (incl. one level of subfolders) is listed or warned about.
  Symlinked bundles are listed once under their target (`Adobe Digital Editions.app -> ... 4.5.app`, OpenVPN Connect);
  a symlink whose target is outside the walked folders is listed under the link (`Safari.app` -> the App cryptex); a
  self-referencing link inside a bundle is harmless; the iOS app `FortiToken.app/Wrapper/` is read (`ios_app_on_mac`).
  Empty leftover `.app` folders (Karabiner, 2021) give one `Contents/Info.plist missing` warning each. Electron (33),
  CEF (3) and Sparkle (35) versions equal their framework `Info.plist` in all 70 cases; a vendor build suffix
  (`33.4.0+wcus`, Discord) is kept and still range-matches as SemVer. Rosetta/universal architecture is not recorded.
- **Restricted access (no Full Disk Access, sandboxed or managed session).** macOS privacy protection can deny listing a
  folder or reading a plist with `EPERM` even to its owner; then `stat` may fail too, so the folder looks absent. The collector
  never treats a denied path as missing: each unreadable folder (`/Users`, `/Applications`, `~/Applications`,
  `/System/Applications`, a receipts folder, a subfolder of `/Applications`) or plist (`SystemVersion.plist`, a bundle's
  `Info.plist`, a receipt) becomes one warning `cannot list|read <path>: permission denied (macOS privacy protection: grant
  Full Disk Access ...)`, and everything still readable is collected (exit 0). Observed on macOS 26.5 (2026-11-08): with
  `/Applications`, `/System/Applications`, `~/Applications`, `/Users` and `/var/db/receipts` denied, the run produced the OS,
  87 Apple receipts and the Homebrew inventory, no apps, and five such warnings.
- Python's `plistlib` rejects XML plists whose prolog has unquoted attributes (`<?xml version=1.0 ...?>`); Apple ships at
  least one (`com.apple.familycircled.plist`, 1 of ~1000 system plists on macOS 26.5); likewise a UTF-8 plist (with BOM)
  that declares `encoding="utf-16"` (Royal TSX). `loads_plist` replaces the prolog and retries (only for 8-bit content).
- Apps outside standard folders are missed by design. On the capture Mac `mdfind` found them in vendor support folders
  (Citrix, Pulse Secure, JetBrains, Steam, Battle.net), printer/scanner drivers and development build outputs; use
  `-o system_profiler=<export.json>` to add them.
- Nested helper apps (`Contents/Library/LoginItems/*.app`, `Contents/Frameworks/*Helper.app`) are not listed individually.
- Bundle version != vendor release version for some apps (Office uses `16.89`); CPE versions may need mapping. Safari
  and Xcode follow the macOS year numbering since 26: (macOS 26.5 25F71, Safari 26.5 / 21624.2.5.11.4, Xcode 26.6 17F113),
  so `CFBundleShortVersionString` matches Apple's security notes directly. Xcode gets `cpe:...:apple:xcode` from the alias table.
- No signature verification (`codesign`), so spoofed Info.plist is possible - the collector trusts the filesystem.
- Future: MacPorts (`/opt/local/var/macports/registry/registry.db`, sqlite; `port installed`), pip `site-packages` (`/Library/Frameworks/Python.framework`, `~/Library/Python`, brew's `Cellar/python@*/lib/python3.*/site-packages`), npm global (`/opt/homebrew/lib/node_modules/*/package.json`), VS Code extensions (`~/.vscode/extensions`), browser extensions, Xcode/CLT version via receipts.

## Implementation notes

Code: `src/secmonk/collectors/macos.py` (`MacOSCollector`, `parse_system_profiler_json`, `loads_plist` (also used by the process monitor); `parse_brew_info_json` re-exported from `homebrew.py`); tests `tests/collectors/test_macos.py` (synthetic fixture tree, real files from `real/`, simulated `EPERM` via patched `Path.iterdir` / `os.open` and a `chmod 000` folder).

**Collected**
- OS: `macOS` (`os`, vendor apple, meta.build) plus the asset (`macos:<hostname>`, `desktop`).
- Apps: `/Applications` (depth <= 3), `<home>/Applications`, `/System/Applications` (`system-app`, skipped with `include_system=False`). Purl `pkg:generic/<vendor_hint>/<name>@<ver>?bundle_id=...`; `meta.vendor_hint` comes from the bundle id, `vendor` is set later by classify.
- Bundled runtimes (`runtime`): Electron (`pkg:npm/electron@<v>`, so OSV npm applies), Chromium Embedded Framework and Sparkle (`pkg:generic/...`), each with `meta.embedded_in`.
- Homebrew: see [homebrew.md](homebrew.md). The filesystem walk (`collect_prefixes`) always runs; with `use_brew_cli` the output of `brew info --json=v2 --installed` (parsed with the collector's `all_kegs` option) is merged into it by `merge_brew`: matched by purl, else by kind + name + raw version where the name may also be one of the CLI's `meta.brew_oldnames` (`oldnames` / `old_tokens`: a renamed formula keeps its old rack, so the walk says `mprocs` and the CLI `dekit`; one component, walk name and purl kept, new name in `meta.brew_current_name`). A walked component keeps its values and gains the meta keys only the CLI knows (`license`, `homepage`, `source_url`...; marked `meta.brew_cli`). When the walk has the same formula/cask but the CLI picked another active keg (walk: `opt` link then `linked`; CLI: `linked_keg` else highest version), the CLI never adds a second keg: the walked active keg gains formula-level keys only (`homepage`, `license`, `keg_only`, `pinned`, `auto_updates`, `brew_oldnames`) and `meta.brew_cli_version`. Only formulae/casks the walk does not have under any name are added, with `meta.source=brew-cli`. The CLI never replaces the walk: on a real prefix (2026-11-08) it skipped 20 formulae (untapped taps, removed or renamed formulae) and cannot see a second prefix such as a leftover x86_64 `/usr/local`. A failing CLI is a warning with its first stderr line. The CLI describes the host, so it is asked only when the scanned root resolves to the live `/` (the same rule decides the hostname and `platform` of the asset); for any other root (copied or mounted tree) it is skipped with the warning `use_brew_cli ignored: root is not the live system (<root>)` (also a warning when `brew` is not on PATH). Formulae are `package` with `pkg:brew/[<tap>/]<name>@<pkg_version>` (`@` percent-encoded, `homebrew/core` namespace omitted), only the **active** keg, `version` = upstream version (`_N` stripped, raw in `meta.brew_version`); casks `application` with `pkg:brew/homebrew/cask/<token>@<ver>`; vendored PyPI/npm packages as `library` components.
- pkgutil receipts from both receipt folders (`RECEIPT_DIRS`): `package`, `pkg:generic/<id>@<ver>`, `meta.pkg_id`, `meta.install_date` (naive UTC); `com.apple.*` only with `include_system`.
- Optional `system_profiler` JSON export (`opts["system_profiler"]`), added only for apps not already found; an export with no application is a warning.

**Dedupe rule**: a cask is not emitted when an app bundle matches its app name, token, display name (normalized, alphanumerics only) or `uninstall quit:` bundle id; the app gets `meta.also_cask=<token>`. Casks without an installed app stay as separate components.

**Known gaps**: stale non-Apple receipts are not flagged low-confidence; Apple system apps keep their bundle version (not mapped to the macOS release); MacPorts and nested helper apps are not handled; a `latest` cask without an app bundle has no version; all plist errors and every unreadable folder become `Inventory.warnings` (`_list_dir`: a missing folder is empty, a denied one is empty plus a warning).


## Review fixes (2026-11)

- `-o home=/Users/bob` (a string) is one home, not iterated per character.
- Scanning a mounted tree never follows a symlink out of it: bundles, plists, receipts must resolve under the scan root (explicit homes: under that home); symlink loops are skipped with a warning. Plists are capped at 8 MB.
- iOS/iPadOS apps on Apple silicon (`<App>.app/Wrapper/<App>.app/Info.plist`) are read (`meta.ios_app_on_mac`).
- `meta.sparkle_feed` has userinfo/query/fragment removed.
