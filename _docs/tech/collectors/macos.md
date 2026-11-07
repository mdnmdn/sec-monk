---
title: macOS collector
type: tech
context: tech
status: implemented
tags: [collector, macos, desktop, homebrew]
updated: 2026-11-07
sample: synthetic
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
3. `pkgutil` receipts (`/var/db/receipts/*.plist`).
4. The OS itself (`SystemVersion.plist`) as a component `cpe:2.3:o:apple:macos:<ver>`.

**All fixtures in `tests/fixtures/collectors/macos/` are SYNTHETIC** (hand-built from known real
formats; the sandbox is Linux). Binary plist fixture generated with `plistlib.FMT_BINARY`.
Re-verify against a real Mac before marking `implemented`.

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
| pkg receipts | `var/db/receipts/<PackageIdentifier>.plist` (+ `.bom`) | Readable by all users. |
| OS version | `System/Library/CoreServices/SystemVersion.plist` | |

No elevated privileges are needed for any of these on a default install (receipts and /Applications
are world-readable; TCC may block `~/Library` and Desktop/Documents but not `~/Applications`).

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

Fixtures `root/var/db/receipts/com.example.pkg.plist`, `com.apple.pkg.CLTools_Executables.plist` (XML plists; on real systems
usually binary). Keys: `PackageIdentifier`, `PackageVersion`, `InstallDate` (plistlib -> `datetime`), `InstallPrefixPath`,
`InstallProcessName`, `PackageFileName` (sometimes absent). The `.bom` (bill of materials, binary) lists files; ignore for now.
CLI equivalents: `pkgutil --pkgs`, `pkgutil --pkg-info-plist <id>`, `pkgutil --files <id>`. Receipts include many `com.apple.pkg.*`
(Xcode CLT, Rosetta, XProtect) - mark `os-component` when the id starts with `com.apple.`; CLT/Xcode versions are CVE-relevant (git, clang bundled).
Receipts are not removed when the app is deleted - **stale receipts** produce phantom components; cross-check `InstallPrefixPath` + `--files` (future), or
tag `confidence=low` for non-Apple receipts without a matching `.app`.

### OS version

`System/Library/CoreServices/SystemVersion.plist` (fixture): `ProductName` (macOS), `ProductVersion` (`14.5`; on
Big Sur+ may read `10.16` for old binaries via compat only - the file itself is right), `ProductBuildVersion` (`23F79`),
`ProductUserVisibleVersion`. Rapid Security Responses add a suffix in `ProductVersionExtra` (`(a)`). Equivalent: `sw_vers`.
Emit component `macos` `14.5`, `cpe:2.3:o:apple:macos:14.5:*:*:*:*:*:*:*`, category `os`.

### system_profiler (optional)

`system_profiler SPApplicationsDataType -json` (fixture `system_profiler-applications.json`, synthetic): `{"SPApplicationsDataType":[{_name, path, version, arch_kind, lastModified, obtained_from, signed_by[], info}]}`.
Useful extras: `obtained_from` (apple / mac_app_store / identified_developer / unknown), `signed_by` (Team ID in parentheses = strong vendor identity).
Slow (10-60 s) and includes only what Spotlight indexed; keep as optional enrichment. osquery `apps` table (`bundle_identifier`,
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

- Fixtures synthetic; real-Mac behaviour (symlinked bundles, `Contents/Info.plist` missing for iOS-on-Mac `Wrapper/*.app`, Rosetta) untested.
- Apps outside standard folders (Setapp, `~/Downloads`, external volumes, Xcode-bundled simulators) missed; Spotlight (`mdfind kMDItemKind=Application`) would find more.
- Nested helper apps (`Contents/Library/LoginItems/*.app`, `Contents/Frameworks/*Helper.app`) are not listed individually.
- Bundle version != vendor release version for some apps (Safari, Office uses `16.89`); CPE versions may need mapping.
- No signature verification (`codesign`), so spoofed Info.plist is possible - the collector trusts the filesystem.
- Future: MacPorts (`/opt/local/var/macports/registry/registry.db`, sqlite; `port installed`), pip `site-packages` (`/Library/Frameworks/Python.framework`, `~/Library/Python`, brew's `Cellar/python@*/lib/python3.*/site-packages`), npm global (`/opt/homebrew/lib/node_modules/*/package.json`), VS Code extensions (`~/.vscode/extensions`), browser extensions, Xcode/CLT version via receipts.

## Implementation notes

Code: `src/secmonk/collectors/macos.py` (`MacOSCollector`, `parse_system_profiler_json`; `parse_brew_info_json` re-exported from `homebrew.py`); tests `tests/collectors/test_macos.py` (fixture tree only; still synthetic).

**Collected**
- OS: `macOS` (`os`, vendor apple, meta.build) plus the asset (`macos:<hostname>`, `desktop`).
- Apps: `/Applications` (depth <= 3), `<home>/Applications`, `/System/Applications` (`system-app`, skipped with `include_system=False`). Purl `pkg:generic/<vendor_hint>/<name>@<ver>?bundle_id=...`; `meta.vendor_hint` comes from the bundle id, `vendor` is set later by classify.
- Bundled runtimes (`runtime`): Electron (`pkg:npm/electron@<v>`, so OSV npm applies), Chromium Embedded Framework and Sparkle (`pkg:generic/...`), each with `meta.embedded_in`.
- Homebrew: see [homebrew.md](homebrew.md) (`collect_prefixes`; or `brew info --json=v2` with `use_brew_cli`). Formulae are `package` with `pkg:brew/[<tap>/]<name>@<pkg_version>` (`@` percent-encoded, `homebrew/core` namespace omitted), only the **active** keg, `version` = upstream version (`_N` stripped, raw in `meta.brew_version`); casks `application` with `pkg:brew/homebrew/cask/<token>@<ver>`; vendored PyPI/npm packages as `library` components.
- pkgutil receipts: `package`, `pkg:generic/<id>@<ver>`, `meta.pkg_id`; `com.apple.*` only with `include_system`.
- Optional `system_profiler` JSON export (`opts["system_profiler"]`), added only for apps not already found.

**Dedupe rule**: a cask is not emitted when an app bundle matches its app name, token, display name (normalized, alphanumerics only) or `uninstall quit:` bundle id; the app gets `meta.also_cask=<token>`. Casks without an installed app stay as separate components.

**Known gaps**: stale non-Apple receipts are not flagged low-confidence; Apple system apps keep their bundle version (not mapped to the macOS release); MacPorts and nested helper apps are not handled; a `latest` cask without an app bundle has no version; all plist errors become `Inventory.warnings`.
