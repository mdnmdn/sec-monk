---
title: Plan - on a Mac
type: plan
context: plans
status: open
platform: macos
tags: [plan, macos, homebrew, collector, ssh]
updated: 2026-11-07
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

## A. macOS collector on a real machine

- [ ] **First real run, Apple Silicon and (if available) Intel.**
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
- [ ] **Symlinked bundles, iOS-on-Mac `Wrapper/*.app` without `Contents/Info.plist`, Rosetta/universal apps.**
  ```bash
  find /Applications -maxdepth 3 -name '*.app' -type l
  find /Applications -maxdepth 3 -path '*/Wrapper/*.app' -o -maxdepth 3 -name '*.app' ! -path '*/Contents/*' | head
  uv run secmonk inventory show macos:$(hostname -s) --category application --db /tmp/mac.db | grep -iE 'wrapper|rosetta'
  ```
  Verify: each symlinked/Wrapper app is either listed once with a version or produces exactly one warning, never a
  traceback; no double counting of the symlink target. Add a regression fixture for any case that breaks.
- [ ] **Electron / CEF / Sparkle detection on real apps** (VS Code, Slack, Discord, 1Password, Chrome, a Sparkle app such as iTerm2).
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
- [ ] **pkgutil receipts.**
  ```bash
  pkgutil --pkgs | wc -l; pkgutil --pkg-info com.apple.pkg.CLTools_Executables
  ls /var/db/receipts | head; jq '[.components[] | select(.meta.pkg_id)] | length' /tmp/mac-inv.json
  ```
  Verify: count matches non-`com.apple.*` receipts; version equals `pkgutil --pkg-info`; flag stale receipts of apps that
  were deleted (known gap: not marked low-confidence, see macos.md "Known gaps"). Decide: lower confidence for
  receipts whose install location no longer exists.
- [ ] **`system_profiler` input.**
  ```bash
  system_profiler SPApplicationsDataType -json > /tmp/sp-apps.json
  uv run secmonk collect macos / -o system_profiler=/tmp/sp-apps.json -O /tmp/mac-inv-sp.json
  diff <(jq -r '.components[].name' /tmp/mac-inv.json | sort -u) <(jq -r '.components[].name' /tmp/mac-inv-sp.json | sort -u)
  ```
  Verify: field names of real output equal the synthetic fixture `system_profiler-applications.json` (`_name`, `path`, `version`,
  `arch_kind`, `obtained_from`, `signed_by`); extra apps found only by system_profiler are those outside `/Applications`
  (Setapp, `~/Downloads`, external volumes: macos.md Limitations). Replace the synthetic fixture with a trimmed real one.
- [ ] **Apps outside standard folders and nested helper apps** (decide scope).
  ```bash
  mdfind "kMDItemContentType == 'com.apple.application-bundle'" | grep -v '^/\(Applications\|System\)' | head -30
  ```
  Verify: how many real apps are missed; add `mdfind` only if the count is material. Log decision in macos.md.
- [ ] **Apple system apps vs macOS release** (Safari, Xcode, Pages use their own bundle version).
  ```bash
  sw_vers; /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' /Applications/Safari.app/Contents/Info.plist
  ```
  Verify: whether Apple security releases (see [next-sources.md](next-sources.md) "Apple security releases") need a mapping
  Safari version <-> macOS; capture the (macOS, Safari, Xcode) triple for the mapping fixture.

## B. Homebrew on a real prefix (`/opt/homebrew` or `/usr/local`)

- [ ] **Run the standalone collector and the macOS-embedded one; compare.**
  ```bash
  uv run secmonk scan homebrew /opt/homebrew --db /tmp/mac.db            # or /usr/local on Intel
  uv run secmonk scan homebrew /opt/homebrew -o all_kegs=true --db /tmp/mac.db
  brew list --formula --versions | sort > /tmp/brew-list.txt
  uv run secmonk inventory show <asset-id-from-"inventory assets"> --db /tmp/mac.db | sort > /tmp/secmonk-brew.txt
  ```
  Verify: formula set equals `brew list --formula --versions` (active keg only unless `all_kegs=true`); `_N` revision stripped
  from `version` but kept in `meta.brew_version`; purl `pkg:brew/<name>@<pkg_version>` with `@` percent-encoded.
- [ ] **Cask `.metadata` shape.**
  ```bash
  find "$(brew --prefix)/Caskroom" -maxdepth 4 -path '*/.metadata/*' | head -20
  ls -la "$(brew --prefix)/Caskroom/google-chrome/.metadata"/*/* 2>/dev/null
  cat "$(brew --prefix)/Caskroom/"*/.metadata/INSTALL_RECEIPT.json 2>/dev/null | head -30
  ```
  Verify against the fixture README note "timestamps synthetic; `latest` literal dir name; `INSTALL_RECEIPT.json`, `config.json`
  not included": check the real dir layout (`<ver>/<timestamp>/Casks/<token>.rb` vs `.json` for API-installed casks - newer brew
  stores cask JSON, not `.rb`!). If the collector only reads `.rb`, add `.json` support. Update [homebrew.md](../tech/collectors/homebrew.md) Limitations
  and `tests/fixtures/collectors/homebrew/README.md`.
- [ ] **Keg `sbom.spdx.json` presence.**
  ```bash
  ls "$(brew --cellar)"/*/*/sbom.spdx.json 2>/dev/null | wc -l; ls "$(brew --cellar)"/*/* -d | wc -l
  cat "$(brew --cellar jq)"/*/sbom.spdx.json | jq '.packages[].name'
  ```
  Verify: which kegs have an SBOM (bottles poured by a recent brew: yes; older/source builds: no); the fixture's reconstructed
  `Archive-<f>-src`/`Bottle-<f>` packages and the derived purl `pkg:brew/homebrew/core/<f>@<v>` match reality. Replace the RECONSTRUCTED rows in the fixture README.
- [ ] **`INSTALL_RECEIPT.json`, opt/linked symlinks, keg-only, pinned, source builds, Intel vs ARM.**
  ```bash
  P=$(brew --prefix); ls -l $P/opt | head; ls -l $P/var/homebrew/linked | head; ls $P/var/homebrew/pinned 2>/dev/null
  jq '{poured_from_bottle, installed_on_request, source: .source.spec, runtime_dependencies: (.runtime_dependencies|length)}' $P/Cellar/jq/*/INSTALL_RECEIPT.json
  brew install --build-from-source jq   # optional: receipt of a source build (poured_from_bottle=false)
  ```
  Verify: active-keg resolution via `opt/<f>` (keg-only `openssl@3`, `curl`), `linked` absent for keg-only, two kegs of one formula pick
  the `opt` target, `pinned` honoured, receipt of a source build parses (no `sbom`, `built_on`).
- [ ] **`-o use_brew_cli=true` (`brew info --json=v2 --installed`).**
  ```bash
  brew info --json=v2 --installed > /tmp/brew-info.json
  uv run secmonk collect macos / -o use_brew_cli=true -O /tmp/mac-inv-cli.json
  diff <(jq -S '[.components[]|select(.purl|startswith("pkg:brew"))|.purl]' /tmp/mac-inv.json) \
       <(jq -S '[.components[]|select(.purl|startswith("pkg:brew"))|.purl]' /tmp/mac-inv-cli.json)
  ```
  Verify: purls identical between filesystem and CLI paths; field shape of `installed[]` (`version`, `runtime_dependencies`,
  `installed_as_dependency`) equals the fixture `brew-info.json` (synthetic; shape came from `formula.rb#to_hash`). Never run brew as root.
- [ ] **Cask <-> `.app` dedupe on real data.**
  ```bash
  brew list --cask --versions | wc -l
  jq '[.components[]|select(.meta.also_cask)]|length' /tmp/mac-inv.json
  jq '[.components[]|select(.purl|startswith("pkg:brew/homebrew/cask"))|.name]' /tmp/mac-inv.json
  ```
  Verify: casks with an installed app are merged (`also_cask`, `cask_auto_updates`) and not listed twice; casks without
  app (pkg-only, `version :latest`) stay separate; list unmatched pairs and fix the matching rule (name/token/bundle id).
- [ ] **`brew_cpe_seed` precision on a real machine** (440 rows / 407 formulae; derived from CVE 2025 only).
  ```bash
  uv run secmonk scan homebrew --db /tmp/mac.db
  uv run secmonk findings --db /tmp/mac.db --all | head -60
  uv run secmonk inventory unmatched --db /tmp/mac.db > /tmp/unmatched.txt; wc -l /tmp/unmatched.txt
  ```
  Verify: for the top 20 findings check manually that the formula is really affected (version vs advisory) - record TP/FP per
  `matched_by` (`brew-seed`, `alias-table`, `brew-name-vendor`, `normalized-name`); count formulae with no identity. Feed results
  to [engine-and-quality.md](engine-and-quality.md) "confidence calibration". Update [references/homebrew.md](../references/homebrew.md) experiment limits.
- [ ] **Grow `product_aliases.yaml` from `inventory unmatched`** (do this on your own, lived-in Mac).
  ```bash
  uv run secmonk inventory unmatched --db /tmp/mac.db | sort | uniq -c | sort -rn | head -50
  $EDITOR src/secmonk/data/product_aliases.yaml        # add vendor:product (use NVD/CNA spelling; verify in the cvelist mirror)
  uv run secmonk match macos:$(hostname -s) --db /tmp/mac.db && uv run pytest -q tests/engine tests/collectors
  ```
  Verify: each added alias is evidenced by at least one real CVE record in the mirror (`uv run secmonk vuln search --package <p>`).
  Keep a count of unmatched before/after in the PR description.
- [ ] **Go/Rust statically linked brew binaries and dependency propagation** are documented limits (formula version only; `openssl@3` propagation
  missing). Only measure here: `jq '.runtime_dependencies' $(brew --cellar)/curl/*/INSTALL_RECEIPT.json`. The implementation work lives in [engine-and-quality.md](engine-and-quality.md).

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
  Verify: each installed runtime is found (paths listed in [docker-engine.md](../tech/collectors/docker-engine.md) implementation notes); Docker
  contexts / `ssh://` DOCKER_HOST are not implemented - confirm the error is explicit. Then repeat `secmonk scan docker-engine <container>` and
  `image:<ref>` once per runtime (VM-backed engines hide the FS; the API must still work).

## F. Process monitor on a real Mac (`secmonk procs`, synthetic fixtures only)

- [ ] **First live run, as user and as root.**
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
- [ ] **Launch classification on real trees.**
  ```bash
  uv run secmonk procs snap-root.json -o root=/ -f json | jq -r '.processes[] | "\(.launch)\t\(.label)\t\(.exe)"' | sort | uniq -c | sort -rn | head -50
  ```
  Verify: Dock/Finder/menu-bar apps = `gui-app`; `/System/Library/...XPCServices/*.xpc` = `xpc-service`; Terminal/iTerm2/VS Code
  shells = `interactive (terminal)`; `ssh localhost` session = `remote-session`; third-party daemons match their plist
  (`service (<label>)`); count `unknown`/`child` without `via`. Add missing terminals / launchers to `launch.DARWIN`.
- [ ] **Identity coverage.**
  ```bash
  uv run secmonk procs -f json | jq -r '.processes[] | .identity_method' | sort | uniq -c
  uv run secmonk procs -f json | jq -r '.processes[] | select(.identity_method=="none") | .exe' | sort -u | head -40
  ```
  Verify: helpers inside `.app` resolve to the host app; Homebrew binaries (via `/opt/homebrew/bin` symlinks) resolve to
  the keg; Safari from the cryptex (`/System/Volumes/Preboot/Cryptexes/App/...`) resolves; `pkgutil --file-info` hits for
  `/usr/local/bin` tools (e.g. AWS CLI); privileged helpers (`/Library/PrivilegedHelperTools/*`) give an embedded
  `__info_plist`; fat (universal) Go binaries: the Go parser skips `0xCAFEBABE`, decide whether to slice the arm64 arch.
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
- [ ] **Web interface live** (`secmonk ui --open`, browser with internet for the Vue CDN).
  Verify: Processes / Software / Launch items / Activity show the live Mac; Watch reports a newly started app; Save then
  `secmonk findings process:$(hostname -s)` lists the same findings; no console errors (CSP) in Safari, Chrome and Firefox;
  first-load time with ~500 processes. Replace `_design/screenshots/` with real (anonymized) ones only if useful.
- [ ] **Login items / BTM.** `sudo sfltool dumpbtm | head -80`: decide whether to parse it to tag `login-item` (currently
  never produced on macOS).

## E. Wrap-up

- [ ] Commit real fixtures + tests; flip `sample:` in `tech/collectors/macos.md`, `tech/collectors/homebrew.md` (stay `real`), `features/inventory-macos.md`.
- [ ] Run `uv run python scripts/docs_index.py` and set this file's `status: done` only when every box above is ticked.
