---
title: Plan - on a Mac
summary: Checklist to verify the macOS, Homebrew, SSH-to-Mac, Docker-on-macOS and process monitor code on a real Mac, producing real fixtures from synthetic ones.
read_when: you are on a Mac and want to verify the macOS, Homebrew or process collectors or capture real fixtures
type: plan
context: plans
status: open
platform: macos
tags: [plan, macos, homebrew, collector, ssh]
updated: 2026-11-11
verified: 2026-11-11
related: [tech/collectors/macos.md, tech/collectors/homebrew.md, features/inventory-macos.md, features/inventory-homebrew.md, references/homebrew.md, tech/collectors/ssh.md, tech/collectors/process.md]
---

# Plan: what to do on a Mac

Everything macOS was built in a Linux sandbox from **synthetic** fixtures (`tests/fixtures/collectors/macos/`,
`tests/fixtures/collectors/homebrew/`, see their READMEs). The `macos` and `homebrew` collectors have **never run on a
real Mac**. Do the items in order: A gives you real fixtures that B-E reuse.

Setup (once):

```bash
git clone <repo> sec-monk && cd sec-monk
uv sync                              # Python 3.13 via mise/uv (ADR-0001)
uv run pytest -q tests/collectors/test_macos.py tests/collectors/test_homebrew.py   # sanity: must pass on macOS too
uv run secmonk sync kev epss osv -e PyPI -e npm -e Maven -e Go --db /tmp/mac.db   # needs open network, see on-open-network.md
```

Rule for every item: keep the **trimmed, anonymized** real output under `tests/fixtures/collectors/macos/real/` (or
`homebrew/real/`), flip the doc's `sample:` from `synthetic` to `mixed`/`real`, and add a test that reads the real file.
Never commit hostnames, user names, serials, or full paths under `/Users/<name>`.

## Handoff 2026-11-08: what a full-access session still has to run

A first pass ran on 2026-11-08 on a real Mac (macOS 26.5 build 25F71, arm64, `/opt/homebrew`) inside a **restricted
agent session**: listing `/Applications`, `/System/Applications`, `~/Applications`, `/Users`, `/var/db/receipts`,
`/Library/Launch*` was denied (EPERM, even from Python), `ps`, `launchctl`, `sudo` could not run, no Docker socket,
`system_profiler SPApplicationsDataType` returned an empty array. That pass verified what it could (see the sub-bullets
under each item) and made the collectors degrade to warnings instead of tracebacks. **Run the rest in a different
session** that has:

- a terminal app with **Full Disk Access** (System Settings -> Privacy & Security), `ps`/`launchctl` runnable, `sudo`;
- for C: a second machine (or `ssh localhost`) with Remote Login enabled; for D: at least one of Docker Desktop,
  Colima, OrbStack (installed here as a cask, not running), Rancher Desktop, Podman Machine.

Still to run there (unticked boxes below; the first pass left partial evidence on A1, A4, A5, F1):

| Item | Needs | Notes from the first pass |
|---|---|---|
| A1 first real run | Full Disk Access | asset, OS `meta.build`, Homebrew OK; app count and plist robustness on real bundles not seen (0 apps) |
| A2 symlinked / Wrapper / universal apps | Full Disk Access | not run |
| A3 Electron / CEF / Sparkle | Full Disk Access, real apps | not run |
| A4 pkgutil receipts | Full Disk Access (`/var/db/receipts`) | Apple receipts in `/Library/Apple/System/Library/Receipts` now read and verified (87); third-party count and stale-receipt decision open |
| A5 system_profiler | Full Disk Access | real output was empty here; field shape unverified, synthetic fixture kept |
| A6 apps outside standard folders (`mdfind`) | Full Disk Access | not run |
| A7 Safari / Xcode vs macOS triple | Full Disk Access | not run |
| B4 pinned / Intel prefix | a pinned formula, a working Intel brew | receipts, opt/linked, keg-only, source builds verified |
| B6 cask <-> `.app` dedupe | Full Disk Access | blocked: `/Applications` unreadable |
| C SSH to a Mac | Remote Login, second host | not run |
| D Docker socket discovery | a Docker runtime | not run |
| F1-F7 process monitor live | `ps`, `launchctl`, `sudo`, GUI (downloads, new app, LaunchAgent) | `ps` denied: clean exit 1 with message; launchctl/launchd-dir denials become warnings; no real `snap-root.json` fixture yet |

Known issues from that pass, status after the full-access pass (2026-11-08):

- `tests/collectors/test_ssh.py` failures on macOS: **fixed** (`bsdtar` `._*` AppleDouble entries -> `COPYFILE_DISABLE=1`;
  Linux-fixture tests pinned `os=linux` instead of detecting the Darwin test host). Full suite green on the Mac.
- `.app` fixtures unreadable: **not reproduced** with Full Disk Access; plain `pytest` works.
- Asset id: the full host name (e.g. `macos:mac.example.lan`), not `hostname -s`. Unchanged; use `secmonk inventory assets`.
- Partial-access fallbacks (libproc without `ps`, `pkgutil` without receipt folders): still not implemented.

**Still needs the user / another machine**: a `sudo` password (root process snapshot, `sfltool dumpbtm`), Remote Login
(real `ssh` hop), a running Docker engine (OrbStack / Docker Desktop installed but stopped), a `sync` of the mirror
(OSV Electron check), an Intel Mac or working `/usr/local` brew, a pinned formula, and the interactive F items
(downloads/provenance, `--watch`, web UI).

## A. macOS collector on a real machine

- [x] **First real run, Apple Silicon and (if available) Intel.**
  ```bash
  uv run secmonk collect macos / -O /tmp/mac-inv.json --db /tmp/mac.db
  uv run secmonk inventory assets --db /tmp/mac.db
  uv run secmonk inventory show macos:$(hostname -s) --db /tmp/mac.db | head -80
  jq '[.components[].category] | group_by(.) | map({(.[0]): length}) | add' /tmp/mac-inv.json
  jq '.warnings' /tmp/mac-inv.json
  ```
  Verify: asset `macos:<host>` type `desktop`; OS component has `meta.build`; app count within ~10 % of
  `ls /Applications | wc -l` plus `~/Applications` and `/System/Applications`; warnings are explainable (no crash on a
  malformed plist). Update [macos.md](../tech/collectors/macos.md) "Limitations" and `sample:`.
  - 2026-11-08 (partial, restricted session, macOS 26.5 25F71 arm64): fixed an abort on denied `/Users`
    (`PermissionError`, exit 1); denied `/var/db/receipts` and `/Library/Launch*` were skipped silently. Now: asset
    `macos:<host>` desktop darwin/arm64, OS 26.5 `meta.build=25F71`, Homebrew present, one Full Disk Access warning per
    denied folder, exit 0. Apple's `familycircled.plist` (unquoted XML header) broke `plistlib`: `loads_plist` repairs
    it. App count and real bundles still need Full Disk Access.
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password): 3174 components (222 apps, 65 system apps, 70 runtimes, 757 packages, 2059 libraries), 3 warnings, all explained: two empty leftover `Karabiner-*.app` folders, Royal TSX's UTF-8 `Info.plist` declaring `utf-16` (`loads_plist` now repairs it). Every `.app` on disk (top level + one subfolder) listed or warned. Asset id is `macos:<full hostname>` (e.g. `mac.example.lan`), not `hostname -s`. Intel: no machine.

- [x] **Symlinked bundles, iOS-on-Mac `Wrapper/*.app` without `Contents/Info.plist`, Rosetta/universal apps.**
  ```bash
  find /Applications -maxdepth 3 -name '*.app' -type l
  find /Applications -maxdepth 3 -path '*/Wrapper/*.app' -o -maxdepth 3 -name '*.app' ! -path '*/Contents/*' | head
  uv run secmonk inventory show macos:$(hostname -s) --category application --db /tmp/mac.db | grep -iE 'wrapper|rosetta'
  ```
  Verify: each symlinked/Wrapper app is either listed once with a version or produces exactly one warning, never a
  traceback; no double counting of the symlink target. Add a regression fixture for any case that breaks.
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password): symlinked bundles listed once under their target (Adobe Digital Editions, OpenVPN Connect), Safari (link into the App cryptex) under the link, Adobe's self-referencing inner link harmless; `FortiToken.app/Wrapper/` read (`ios_app_on_mac`). No traceback, no double count. Rosetta/universal arch not recorded (no `arch` in components; `system_profiler` `arch_kind` has it).

- [x] **Electron / CEF / Sparkle detection on real apps** (VS Code, Slack, Discord, 1Password, Chrome, a Sparkle app such as iTerm2).
  ```bash
  jq '.components[] | select(.category=="runtime") | {name,version,purl,embedded_in:.meta.embedded_in}' /tmp/mac-inv.json
  for a in "Visual Studio Code" Slack Discord; do
    /usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "/Applications/$a.app/Contents/Frameworks/Electron Framework.framework/Resources/Info.plist" 2>/dev/null
  done
  ```
  Verify: Electron version equals `Electron Framework.framework/Resources/Info.plist` (and the app's own About box),
  purl `pkg:npm/electron@<v>` matches OSV npm advisories (`uv run secmonk vuln search --ecosystem npm --package electron --version <v>`);
  CEF and Sparkle versions plausible; `meta.embedded_in` points to the app. Record false negatives (Electron apps with
  renamed framework dir, helper-only bundles).
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password): Electron 33/33, CEF 3/3, Sparkle 34/35 framework folders found (the missing one was Royal TSX, fixed above); all 70 versions equal the framework `Info.plist`; `embedded_in` names the app. Discord ships `33.4.0+wcus`: purl keeps it, engine parses and range-matches it as 33.4.0. OSV npm check not run: the local mirror is empty (no `sync`).

- [ ] **pkgutil receipts.**
  ```bash
  pkgutil --pkgs | wc -l; pkgutil --pkg-info com.apple.pkg.CLTools_Executables
  ls /var/db/receipts | head; jq '[.components[] | select(.meta.pkg_id)] | length' /tmp/mac-inv.json
  ```
  Verify: count matches non-`com.apple.*` receipts; version equals `pkgutil --pkg-info`; flag stale receipts of apps that
  were deleted (known gap: not marked low-confidence, see macos.md "Known gaps"). Decide: lower confidence for
  receipts whose install location no longer exists.
  - 2026-11-08 (partial): Apple receipts live in `/Library/Apple/System/Library/Receipts` (87 = `pkgutil --pkgs`), which
    the collector never read; now read as well as `/var/db/receipts`, deduped by id; 87/87 versions and install times
    equal `pkgutil --pkg-info` (fixture `macos/real/`). No third-party receipt here and `/var/db/receipts` denied:
    non-Apple count and the stale-receipt decision still open.
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password): 257 receipts = `pkgutil --pkgs` (157 third-party), 0 version mismatches; one id with a trailing space (`org.swiftwasm.2024116 `) now stripped. Stale: 61/157 third-party receipts list no file that still exists (old .NET SDK packs, Citrix, Skype for Business). `InstallPrefixPath` is no signal (129 are plain `Applications`; the 9 missing ones are updater staging dirs of installed apps). **Decision needed**: parse the `.bom` (binary BOM) to mark receipts with no surviving file `confidence=low`, or leave the gap documented.

- [x] **`system_profiler` input.**
  ```bash
  system_profiler SPApplicationsDataType -json > /tmp/sp-apps.json
  uv run secmonk collect macos / -o system_profiler=/tmp/sp-apps.json -O /tmp/mac-inv-sp.json
  diff <(jq -r '.components[].name' /tmp/mac-inv.json | sort -u) <(jq -r '.components[].name' /tmp/mac-inv-sp.json | sort -u)
  ```
  Verify: field names of real output equal the synthetic fixture `system_profiler-applications.json` (`_name`, `path`, `version`,
  `arch_kind`, `obtained_from`, `signed_by`); extra apps found only by system_profiler are those outside `/Applications`
  (Setapp, `~/Downloads`, external volumes: macos.md Limitations). Replace the synthetic fixture with a trimmed real one.
  - 2026-11-08 (partial): in a restricted session `system_profiler SPApplicationsDataType -json` returns an empty array
    (fixture `macos/real/`); the collector now warns. Field shape unverified, synthetic fixture kept.
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password): 707 apps; keys exactly `_name, arch_kind, lastModified, obtained_from, path, signed_by, version, info` = the synthetic fixture (`version` absent on 52, `signed_by` on 128); `obtained_from` also `ios_app_store`. 431 apps not in the walk: `/System/Library` 229, home 110, `/Library` vendor helpers/printers, `/usr/local`. Real trimmed fixture `macos/real/system_profiler-applications.json` (13 entries) + test.

- [x] **Apps outside standard folders and nested helper apps** (decide scope).
  ```bash
  mdfind "kMDItemContentType == 'com.apple.application-bundle'" | grep -v '^/\(Applications\|System\)' | head -30
  ```
  Verify: how many real apps are missed; add `mdfind` only if the count is material. Log decision in macos.md.
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password): `mdfind` finds 701 bundles; outside `/Applications` and `/System` they are vendor helpers (Citrix, Pulse Secure, JetBrains), printer/scanner drivers, game launchers (Steam, Battle.net) and dev build outputs (incl. this repo's fixtures). Decision: keep the walk as is; `-o system_profiler=` is the opt-in for complete coverage. Nested helpers stay unlisted.

- [x] **Apple system apps vs macOS release** (Safari, Xcode, Pages use their own bundle version).
  ```bash
  sw_vers; /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' /Applications/Safari.app/Contents/Info.plist
  ```
  Verify: whether Apple security releases (see [next-sources.md](next-sources.md) "Apple security releases") need a mapping
  Safari version <-> macOS; capture the (macOS, Safari, Xcode) triple for the mapping fixture.
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password): triple (macOS 26.5 25F71, Safari 26.5 / CFBundleVersion 21624.2.5.11.4, Xcode 26.6 build 17F113). Since the year-based numbering Safari's short version equals Apple's security-note version: no mapping needed. Xcode had no CPE: alias `apple:xcode` added.

## B. Homebrew on a real prefix (`/opt/homebrew` or `/usr/local`)

- [x] **Run the standalone collector and the macOS-embedded one; compare.**
  ```bash
  uv run secmonk scan homebrew /opt/homebrew --db /tmp/mac.db            # or /usr/local on Intel
  uv run secmonk scan homebrew /opt/homebrew -o all_kegs=true --db /tmp/mac.db
  brew list --formula --versions | sort > /tmp/brew-list.txt
  uv run secmonk inventory show <asset-id-from-"inventory assets"> --db /tmp/mac.db | sort > /tmp/secmonk-brew.txt
  ```
  Verify: formula set equals `brew list --formula --versions` (active keg only unless `all_kegs=true`); `_N` revision stripped
  from `version` but kept in `meta.brew_version`; purl `pkg:brew/<name>@<pkg_version>` with `@` percent-encoded.
  - 2026-11-08, macOS 26.5 arm64, brew 6.0.21: formula set 359 = 359 vs `brew list --formula --versions`; `all_kegs=true`
    463 = 463; `_N` stripped from `version`, kept in `meta.brew_version` and purl; `@` -> `%40`. Fixed: an `opt`/`linked`
    link into another rack (renamed `sdl2` -> `sdl2-compat`) is ignored; `keg_only` read from the formula's `keg_only`
    line (unlinked != keg-only, was wrong for 7/339); asset id of a live prefix is the hostname. The embedded run also
    walks a leftover x86_64 `/usr/local` prefix (147 formulae, its brew no longer runs): the same purl in both prefixes
    is now one component with `meta.paths` (6 were dropped before); `meta.brew_prefix` added.
- [x] **Cask `.metadata` shape.**
  ```bash
  find "$(brew --prefix)/Caskroom" -maxdepth 4 -path '*/.metadata/*' | head -20
  ls -la "$(brew --prefix)/Caskroom/google-chrome/.metadata"/*/* 2>/dev/null
  cat "$(brew --prefix)/Caskroom/"*/.metadata/INSTALL_RECEIPT.json 2>/dev/null | head -30
  ```
  Verify against the fixture README note "timestamps synthetic; `latest` literal dir name; `INSTALL_RECEIPT.json`, `config.json`
  not included": check the real dir layout (`<ver>/<timestamp>/Casks/<token>.rb` vs `.json` for API-installed casks - newer brew
  stores cask JSON, not `.rb`!). If the collector only reads `.rb`, add `.json` support. Update [homebrew.md](../tech/collectors/homebrew.md) Limitations
  and `tests/fixtures/collectors/homebrew/README.md`.
  - 2026-11-08: API-installed casks store a minimal `<token>.json` (`{}` or `url_specs`/`artifacts` only: no name,
    version, `auto_updates`); `.rb` only for untapped casks (6 json / 3 rb). `.metadata/INSTALL_RECEIPT.json` on 3/9
    (brew >= 4.5), `config.json` 9/9; versions 9/9 equal `brew info`. Fixed: renamed-cask symlink (`aws-vault ->
    aws-vault-binary`) no longer double counted. Gap: in the filesystem walk API casks have no display name or
    `auto_updates` (only in the user's API cache). Real fixtures: `homebrew/real/`.
- [x] **Keg `sbom.spdx.json` presence.**
  ```bash
  ls "$(brew --cellar)"/*/*/sbom.spdx.json 2>/dev/null | wc -l; ls "$(brew --cellar)"/*/* -d | wc -l
  cat "$(brew --cellar jq)"/*/sbom.spdx.json | jq '.packages[].name'
  ```
  Verify: which kegs have an SBOM (bottles poured by a recent brew: yes; older/source builds: no); the fixture's reconstructed
  `Archive-<f>-src`/`Bottle-<f>` packages and the derived purl `pkg:brew/homebrew/core/<f>@<v>` match reality. Replace the RECONSTRUCTED rows in the fixture README.
  - 2026-11-08: SBOM on 305/359 active kegs (398/465 total), missing on kegs from brew <= 4.2; source builds by brew
    >= 4.3 have one too (Archive + Compiler only). `Archive-*-src` carries no purl (354/398) or only
    `pkg:brew/homebrew/core/<f>@<v>` (44, brew >= 5.1.14); `pkg:brew` sits on `Bottle-<f>`; no registry purl observed.
    Real SBOM: `homebrew/real/prefix/Cellar/xz/5.8.3`.
- [ ] **`INSTALL_RECEIPT.json`, opt/linked symlinks, keg-only, pinned, source builds, Intel vs ARM.**
  ```bash
  P=$(brew --prefix); ls -l $P/opt | head; ls -l $P/var/homebrew/linked | head; ls $P/var/homebrew/pinned 2>/dev/null
  jq '{poured_from_bottle, installed_on_request, source: .source.spec, runtime_dependencies: (.runtime_dependencies|length)}' $P/Cellar/jq/*/INSTALL_RECEIPT.json
  brew install --build-from-source jq   # optional: receipt of a source build (poured_from_bottle=false)
  ```
  Verify: active-keg resolution via `opt/<f>` (keg-only `openssl@3`, `curl`), `linked` absent for keg-only, two kegs of one formula pick
  the `opt` target, `pinned` honoured, receipt of a source build parses (no `sbom`, `built_on`).
  - 2026-11-08 (partial): 465/465 receipts parse, incl. 18 source installs from third-party taps
    (`poured_from_bottle: false`); active keg = `opt` target for 357/359 (rest: no `opt` link / renamed rack).
    Still open: `pinned` (nothing pinned on this Mac), a working Intel prefix. Gap: tap formulae whose `url` sits in
    `if OS.mac?` / `on_arm` blocks get no `source_url`.
- [x] **`-o use_brew_cli=true` (`brew info --json=v2 --installed`).**
  ```bash
  brew info --json=v2 --installed > /tmp/brew-info.json
  uv run secmonk collect macos / -o use_brew_cli=true -O /tmp/mac-inv-cli.json
  diff <(jq -S '[.components[]|select(.purl|startswith("pkg:brew"))|.purl]' /tmp/mac-inv.json) \
       <(jq -S '[.components[]|select(.purl|startswith("pkg:brew"))|.purl]' /tmp/mac-inv-cli.json)
  ```
  Verify: purls identical between filesystem and CLI paths; field shape of `installed[]` (`version`, `runtime_dependencies`,
  `installed_as_dependency`) equals the fixture `brew-info.json` (synthetic; shape came from `formula.rb#to_hash`). Never run brew as root.
  - 2026-11-08: fixed `parse_brew_info_json` emitting every keg (444 vs 359): active keg only, plus `all_kegs`. After
    the fix 347 purls identical; CLI-only `dekit` (rename of `mprocs`). The CLI silently skips 20 formulae (untapped
    third-party taps, `youtube-dl`, `sdl2` leftover), so the macOS collector now always walks the filesystem and merges
    the CLI result into it. `installed[]` keys: `built_as_bottle, installed_on_request, poured_from_bottle,
    runtime_dependencies, time, used_options, version` (`installed_as_dependency` absent in current brew).
- [x] **Cask <-> `.app` dedupe on real data.**
  ```bash
  brew list --cask --versions | wc -l
  jq '[.components[]|select(.meta.also_cask)]|length' /tmp/mac-inv.json
  jq '[.components[]|select(.purl|startswith("pkg:brew/homebrew/cask"))|.name]' /tmp/mac-inv.json
  ```
  Verify: casks with an installed app are merged (`also_cask`, `cask_auto_updates`) and not listed twice; casks without
  app (pkg-only, `version :latest`) stay separate; list unmatched pairs and fix the matching rule (name/token/bundle id).
  - 2026-11-08 (blocked): `/Applications` unreadable in the restricted session, `also_cask` = 0; 4 casks would match
    by app name (KopiaUI, OrbStack, Dropstone, RedisInsight-v2), 5 have no app. Rerun with Full Disk Access.
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password): the 3 casks with an app in `/Applications` merge into it (`also_cask`: KopiaUI, OrbStack, Redis Insight), the app version wins (OrbStack cask 1.11.3, auto-updated app 2.2.5). The rest stay separate: CLI-only casks, fonts, and Dropstone, whose `.app` still sits inside its Caskroom folder.

- [x] **`brew_cpe_seed` precision on a real machine** (440 rows / 407 formulae; derived from CVE 2025 only).
  ```bash
  uv run secmonk scan homebrew --db /tmp/mac.db
  uv run secmonk findings --db /tmp/mac.db --all | head -60
  uv run secmonk inventory unmatched --db /tmp/mac.db > /tmp/unmatched.txt; wc -l /tmp/unmatched.txt
  ```
  Verify: for the top 20 findings check manually that the formula is really affected (version vs advisory) - record TP/FP per
  `matched_by` (`brew-seed`, `alias-table`, `brew-name-vendor`, `normalized-name`); count formulae with no identity. Feed results
  to [engine-and-quality.md](engine-and-quality.md) "confidence calibration". Update [references/homebrew.md](../references/homebrew.md) experiment limits.
  - 2026-11-08, /opt/homebrew (359 formulae), mirror kev + epss + cvelist 2020+ + full NVD: 1,060 findings. Top 20:
    19 TP, 1 FP (zlib CVE-2023-45853: minizip not shipped). By `product_source`: brew-seed 29 TP / 6 FP, alias-table
    95 / 1, brew-name-vendor 12 / 0, normalized-name 0 shown (stays under the 0.5 cut, correctly). FPs come from engine
    classes, not identity: 13 inverted ranges, 15 unbounded CPE rows; filed in
    [engine-and-quality.md](engine-and-quality.md). 148/359 formulae (41 %) have no CVE/CPE row. Details:
    [references/homebrew.md](../references/homebrew.md) "Measured on a real prefix".
- [x] **Grow `product_aliases.yaml` from `inventory unmatched`** (do this on your own, lived-in Mac).
  ```bash
  uv run secmonk inventory unmatched --db /tmp/mac.db | sort | uniq -c | sort -rn | head -50
  $EDITOR src/secmonk/data/product_aliases.yaml        # add vendor:product (use NVD/CNA spelling; verify in the cvelist mirror)
  uv run secmonk match macos:$(hostname -s) --db /tmp/mac.db && uv run pytest -q tests/engine tests/collectors
  ```
  Verify: each added alias is evidenced by at least one real CVE record in the mirror (`uv run secmonk vuln search --package <p>`).
  Keep a count of unmatched before/after in the PR description.
  - 2026-11-08: +41 alias entries, +17 multi-vendor seed rows (new evidence value `nvd-cpe`), each with an evidence CVE
    in the mirror. Unmatched 12 -> 10; formulae with no row 162 -> 148; findings 979 -> 1,060 (+81, 80 TP). Largest miss
    class: guessed vendor (GitHub org / homepage) disagrees with the CVE vendor, confidence 0.3, rows dropped silently.
- [x] **Go/Rust statically linked brew binaries and dependency propagation** are documented limits (formula version only; `openssl@3` propagation
  missing). Only measure here: `jq '.runtime_dependencies' $(brew --cellar)/curl/*/INSTALL_RECEIPT.json`. The implementation work lives in [engine-and-quality.md](engine-and-quality.md).

  - Measured 2026-11-08: `curl` not installed; `openssl@3` is a runtime dependency of 86 formulae, but receipts pin the
    install-time version (49 at 3.6.3, 37 at 15 older), so propagation must use the active keg. Go: 27 formulae / 39
    binaries, all with module info; Rust: 13 / 31, none with `cargo auditable`.
## C. SSH to a Mac (BSD find / bsdtar flags untested)

- [ ] **Enable Remote Login and scan the Mac from another machine** (System Settings -> General -> Sharing -> Remote Login).
  ```bash
  uv run secmonk scan ssh me@mac.local -o os=macos -o verbose=true --db /tmp/ssh-mac.db
  uv run secmonk scan ssh me@mac.local -o os=macos -o transport=paramiko -o identity=~/.ssh/id_ed25519 --db /tmp/ssh-mac2.db
  uv run secmonk scan ssh me@mac.local -o ssh_option=ProxyJump=bastion -o os=macos --db /tmp/ssh-mac3.db
  ```
  Verify: the generated detection+harvest script runs under macOS `/bin/sh` with BSD `find` and `bsdtar` (no GNU flags: `-mindepth`, `-maxdepth`
  *are* supported by BSD find, but `--null`, `-T -`, `--no-recursion` vary - note which fail); component set equals local `collect macos`;
  `meta.harvested_files/bytes` sane; `sudo=false` still sees `/Applications`. Fix flags in `src/secmonk/collectors/ssh.py`, update
  [ssh.md](../tech/collectors/ssh.md) Limitations (BSD line) and [inventory-ssh.md](../features/inventory-ssh.md). Paramiko `ProxyJump` is a documented non-feature: confirm the error message is clear.
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password): Remote Login is off (port 22 refused), not enabled here. The macOS harvest script was instead run through a local transport against `/` (BSD `find` + `bsdtar`): fixed `._*` AppleDouble entries (`COPYFILE_DISABLE=1`), missing Apple receipts dir, iOS `Wrapper` apps, Safari's cryptex link, a renamed cask harvested twice (shell glob followed `aws-vault -> aws-vault-binary`). With `lang=false` it now equals the direct collector (1122 components, 25 s) except Multipass (`Contents` is a symlink, not followed). The `lang` walk of the whole Mac ran > 10 min and was stopped. `tests/collectors/test_ssh.py` failures on macOS fixed (Linux fixtures pin `os=linux`). Still open: a real sshd hop.

- [ ] **Linuxbrew prefix on a Mac is ignored** (documented). Nothing to do; skip.

## D. Docker on macOS (Docker Desktop, Colima, OrbStack, Rancher Desktop, Podman Machine)

The engine collector is validated against a **fake socket only**; the generic test procedure is in
[on-linux-docker.md](on-linux-docker.md) section A. On the Mac only the socket discovery differs:

- [ ] **Socket discovery per runtime.**
  ```bash
  for s in ~/.docker/run/docker.sock ~/.colima/default/docker.sock ~/.rd/docker.sock ~/.orbstack/run/docker.sock; do ls -l $s 2>/dev/null; done
  docker context ls; echo $DOCKER_HOST
  uv run secmonk containers                       # auto-discovery
  uv run secmonk containers --socket ~/.colima/default/docker.sock
  ```
  Verify: each installed runtime is found (paths listed in [docker-engine.md](../tech/collectors/docker-engine.md) implementation notes). Then repeat `secmonk scan docker-engine <container>` and
  `image:<ref>` once per runtime (VM-backed engines hide the FS; the API must still work).
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password): OrbStack and Docker Desktop installed, neither running; `~/.docker/run/docker.sock` left behind by Docker Desktop refused connections and discovery stopped there. Fixed: auto-discovery skips sockets that refuse connections and names them in the error. `docker context` (current: orbstack) is still not read. Still open: a run with an engine up.

- [ ] **Docker CLI contexts of the Mac runtimes** (read from `~/.docker/contexts/meta/<sha256>/meta.json`; only tested on
  generated context trees). The current context now wins over socket discovery: with `currentContext` = `orbstack` and
  OrbStack stopped, the scan fails on OrbStack's socket instead of falling back to another runtime (by design).
  ```bash
  docker context ls; jq .currentContext ~/.docker/config.json
  uv run secmonk containers                       # the current context
  uv run secmonk containers -o context=desktop-linux; uv run secmonk containers -o context=colima; uv run secmonk containers -o context=orbstack
  DOCKER_CONTEXT=default uv run secmonk containers   # back to socket discovery
  ```
  Verify: the hosts our context listing shows equal `docker context ls` (Docker Desktop `desktop-linux` ->
  `unix:///Users/<user>/.docker/run/docker.sock`, Colima `colima` -> `~/.colima/default/docker.sock`, OrbStack `orbstack`); a stopped runtime's context gives
  a clear "cannot talk to Docker engine at unix://..." error; local containers keep the asset id `container:<name>`.
  Assumed, unverified: these runtimes write plain unix hosts in `meta.json` and no TLS directory; `config.json` may
  be unreadable under a sandbox / privacy prompt, in which case it is ignored.
  Discovered work (2026-11-10): a context on a local unix socket keeps the asset id `container:<name>`, so `web` on
  Colima and `web` on OrbStack collapse into one asset. If both runtimes are used side by side here, decide whether
  non-default local contexts get a label (e.g. `container:ctx=<context>/<name>`); that changes asset ids, so it needs a
  data-model note and a migration thought.
- [ ] **Host auto mode on the Mac** (`discover_host()`). 2026-11-11 first live run from a sandboxed agent shell
  (macOS 26.5, arm64, no Full Disk Access): `macos` (with the Full Disk Access caveat), `homebrew` (`/opt/homebrew`,
  `/usr/local`, not ticked), `process`, `fs-home`; no Docker candidate (no engine socket visible from the sandbox).
  Still open: a run from a normal terminal with an engine up (expect `docker` / `docker-images`), with Full Disk Access
  (expect no caveat), and `discover_host("<user>@<mac>")` (expect `ssh` with the remote Mac description).
- [ ] **`ssh://` from the Mac** to a Linux engine (`-o host=ssh://<user>@<server>`), with the system OpenSSH and
  1Password / Secretive ssh agents: BatchMode must still find agent keys. Same checks as
  [on-linux-docker.md](on-linux-docker.md) section A, remote engine over ssh.

## F. Process monitor on a real Mac (`secmonk procs`, synthetic fixtures only)

- [x] **First live run, as user and as root.**
  ```bash
  uv run secmonk procs --no-match --snapshot-out /tmp/snap-user.json > /tmp/procs-user.txt
  sudo uv run secmonk procs --no-match --snapshot-out /tmp/snap-root.json > /tmp/procs-root.txt
  jq '.processes | length' /tmp/snap-user.json; ps -ax | wc -l
  jq '[.processes[] | select(.exe == null)] | length' /tmp/snap-root.json
  jq '[.processes[] | select(.label != null)] | length' /tmp/snap-user.json /tmp/snap-root.json
  ```
  Verify: process count equals `ps -ax`; `proc_pidpath` fills `exe` for own processes (user) and all (root); `ps lstart`
  parses in the C locale (no `started: null`); `launchctl list` labels attach (GUI apps as `application.<id>.<n>.<n>`).
  Save a trimmed, anonymized `snap-root.json` as `tests/fixtures/collectors/process/real/` and test it.
  - 2026-11-08 (partial, restricted session): `ps` not executable -> `ps failed: PermissionError ... denied on this
    host`, exit 1, no traceback; `launchctl list` failure and denied `/Users`, `/Library/Launch*`,
    `~/Library/LaunchAgents` become warnings; 886 system launch items indexed; unreadable exe no longer flagged
    `exe-missing`. Process count, `proc_pidpath`, `lstart`, labels and a real `snap-root.json` still to do.
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password), user only: 989 processes = `ps -ax`; `exe` missing for 2 (zombie, exited `ps`); `started` parsed for all; 312 labelled incl. `application.<id>.<n>.<n>` and a `.<UUID>` variant (was `agent`, regex fixed). Warnings: not root, one root-only plist. Real trimmed fixture `process/real/snapshot-user.json` + test. `sudo uv run secmonk procs` first crashed (`PermissionError`: HOME kept, the user's DB folder refused): now degrades to no findings with a hint. Root run (same day): 979 processes, `exe` missing for 2, 167/198 root processes labelled, no warnings, only third-party missing programs reported. Fixed from it: as root the user's GUI-domain labels were missing (now `launchctl asuser <uid> launchctl list`), a label shared by a daemon and an agent ignored the process user, per-instance `.<UUID>` labels. Second root run confirmed `asuser`: 544 labelled (228 before), the user's 311 equal the user run, 20 `application.*`; root vs user now differ only on 4 system processes that root labels better. Real trimmed fixture `process/real/snapshot-root.json` + test.

- [ ] **Launch classification on real trees.**
  ```bash
  uv run secmonk procs snap-root.json -o root=/ -f json | jq -r '.processes[] | "\(.launch)\t\(.label)\t\(.exe)"' | sort | uniq -c | sort -rn | head -50
  ```
  Verify: Dock/Finder/menu-bar apps = `gui-app`; `/System/Library/...XPCServices/*.xpc` = `xpc-service`; Terminal/iTerm2/VS Code
  shells = `interactive (terminal)`; `ssh localhost` session = `remote-session`; third-party daemons match their plist
  (`service (<label>)`); count `unknown`/`child` without `via`. Add missing terminals / launchers to `launch.DARWIN`.
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password): agent 340, service 257, xpc-service 245, child 121, gui-app 20, interactive 2 (commands under a Warp shell; the shell itself is `child` by design). Fixed: 49 `.appex` widgets started by launchd were `agent` (now `xpc-service`); `cfprefsd` as `_locationd` matched the daemon plist (now the agent). Apple launch items with missing programs (5, dormant on this hardware) are no longer reported (`meta.os_owned`); third-party ones (`com.docker.socket`, an old EdgeUpdater) still are. Still open: `ssh localhost` -> `remote-session`.

- [ ] **Identity coverage.**
  ```bash
  uv run secmonk procs -f json | jq -r '.processes[] | .identity_method' | sort | uniq -c
  uv run secmonk procs -f json | jq -r '.processes[] | select(.identity_method=="none") | .exe' | sort -u | head -40
  ```
  Verify: helpers inside `.app` resolve to the host app; Homebrew binaries (via `/opt/homebrew/bin` symlinks) resolve to
  the keg; Safari from the cryptex (`/System/Volumes/Preboot/Cryptexes/App/...`) resolves; `pkgutil --file-info` hits for
  `/usr/local/bin` tools (e.g. AWS CLI); privileged helpers (`/Library/PrivilegedHelperTools/*`) give an embedded
  `__info_plist`; fat (universal) Go binaries: the Go parser skips `0xCAFEBABE`, decide whether to slice the arm64 arch.
  - 2026-11-08 (full access: Full Disk Access, `ps`/`launchctl`, no `sudo` password): os 744, app-bundle 199, brew-keg 13, pkgutil 5, none 23. Fixed: non-`.app` bundles with an `Info.plist` (Little Snitch daemon `.bundle`, OBS `.systemextension`) now resolve; `/System/.../liquiddetectiond.app` (no `Info.plist`) resolves to the OS instead of warning. Remaining `none`: toolchain runtimes versioned only by path (uv Python, nvm Node, nix, `~/.local/share/claude/versions/*`): decide whether to add path rules. Not checked: privileged helpers' `__info_plist`, fat Go binaries.

- [ ] **Provenance on real downloads.** Download an app with Safari and Chrome, open it, then
  ```bash
  xattr -l "/Applications/<App>.app"; sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 'select * from LSQuarantineEvent order by LSQuarantineTimeStamp desc limit 3'
  uv run secmonk procs -f json | jq '.processes[] | select(.exe|test("<App>")) | .provenance'
  ```
  Verify: quarantine flags/time/agent parsed, event row found (uuid case), where-froms present, `user_approved` meaning of
  flag `0x0040` confirmed (adjust `parse_quarantine` if not); `codesign` fields (Developer ID / MAS / Apple / adhoc /
  unsigned) on 5 apps; cost of `codesign` per process (time `procs`); `-o verify=true` on a deliberately modified copy of an app (expect `signature-invalid`) and its cost on Xcode-sized bundles; `-o gatekeeper=true` output (`source=Notarized Developer ID`).
- [ ] **`--watch`.** Run `uv run secmonk procs --watch 5`, then start a new app, run a new brew binary, `launchctl bootstrap`
  a test LaunchAgent and remove it. Verify one event each, no repeated events, CPU usage of the loop acceptable.
- [ ] **Web interface live** (`secmonk ui --open`; works offline, Vue is vendored).
  Verify: Processes / Software / Launch items / Activity show the live Mac; Watch reports a newly started app; Save then
  `secmonk findings process:$(hostname -s)` lists the same findings; no console errors (CSP) in Safari, Chrome and Firefox;
  first-load time with ~500 processes. Then Scan `macos` and `homebrew` from the Scan page and check the asset pages
  against `secmonk inventory show`; a `sync kev epss` job from Sources & sync. Replace `_design/screenshots/` with real (anonymized) ones only if useful.
- [x] **Login items / BTM.** `sudo sfltool dumpbtm | head -80`: decide whether to parse it to tag `login-item` (currently
  never produced on macOS).
  - 2026-11-08 (root, `sudo sfltool dumpbtm`, 3122 lines, not kept: user-specific): 231 items (uid 501: 136, root: 24,
    -2: 71). Types: developer 72, legacy daemon 47, legacy agent 41, app 40, quicklook 9, login item 6, spotlight 6,
    dock tile 5, agent 4, background app refresh 1. Text format: per-UID blocks, items with `Type`, `Flags`,
    `Disposition` ([enabled|disabled, allowed|disallowed, notified]), `Identifier` (`<type-code>.<id>`), `URL`,
    `Executable Path`, `Parent Identifier`; undocumented, root-only. What it adds over the plist index:
    (1) **SMAppService items embedded in apps** (`<App>.app/Contents/Library/LaunchAgents|LaunchDaemons/*.plist`: Teams,
    Copilot, Ollama's Squirrel, Spotify launcher) - 8 such plists on disk, **not indexed today** although readable
    without root; (2) **login items** (`SMLoginItemSetEnabled`, `Contents/Library/LoginItems/*.app`: 1Password, Raycast,
    Skitch, Tailscale, Tunnelblick) - 18 bundles on disk, enabled state only in BTM; (3) **disposition**: 45 items are
    `disallowed` (turned off in System Settings > Login Items), e.g. the stale EdgeUpdater daemon, yet still reported
    as configured. Quick Look / Spotlight / dock tile plugins are out of scope (not launch persistence).
    Decision (user, 2026-11-08): index bundle plists always + opt-in BTM. Implemented: `launchd-app-agent|daemon` and
    `login-item` items from every walked app (live: 18 login items, 6 app agents, 2 app daemons; 1Password / Skitch
    helpers now `login-item`); `-o btm=true|<file>` (`parse_btm`, `apply_btm`), synthetic fixture + tests. Confirmed
    on this Mac (2026-11-08): turning Copilot off in *Allow in the Background* flipped its agent to `disallowed`
    (`enabled` unchanged), so `allowed` is the user switch and the `enabled and allowed` rule holds; removing Figma and
    OpenVPN Connect from *Open at Login* deleted their `app` records (not tagged, nothing to change).
## E. Wrap-up

- [ ] Commit real fixtures + tests; flip `sample:` in `tech/collectors/macos.md`, `tech/collectors/homebrew.md` (stay `real`), `features/inventory-macos.md`.
- [ ] Run `uv run python scripts/docs.py index` and set this file's `status: done` only when every box above is ticked.
