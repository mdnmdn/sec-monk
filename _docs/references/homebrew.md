---
title: Homebrew (inventory and vulnerability identity)
summary: Probe-based reference for Homebrew inventory from Cellar receipts and SBOMs, plus formula-to-CVE identity (no CPE), casks, taps, API shape, ghcr registry and match precision.
read_when: you change the Homebrew collector, its formula-to-CPE seed or how brew packages are matched to vulnerabilities
type: reference
context: references
status: reference
tags: [homebrew, macos, linuxbrew, collector, identity]
updated: 2026-11-08
verified: 2026-11-08
sample: mixed
reachable: partial
fixtures: tests/fixtures/collectors/homebrew/
related: [tech/collectors/macos.md, tech/engine/classification.md]
---

# Homebrew: precise inventory and formula-to-vulnerability identity

## Summary

- **Inventory is exact and offline.** `<prefix>/Cellar/<formula>/<pkg_version>/` + `INSTALL_RECEIPT.json` + `.brew/<formula>.rb`
  + `sbom.spdx.json` give name, version (incl. `_N` revision), tap, upstream source URL + sha256, license, homepage, runtime
  deps and install reason, with no `brew` execution. Several versions may coexist; **`<prefix>/opt/<formula>` (relative
  symlink) says which keg is active**. The collector now reads `opt/` and emits only the active keg by default (`-o all_kegs=true` for old kegs): see [tech/collectors/homebrew.md](../tech/collectors/homebrew.md); the earlier `_walk_brew` behaviour (every keg, `opt/` ignored) is superseded.
- **Homebrew has no CPE and no OSV ecosystem.** Nothing in 8,707 formulae, the formula DSL, the API JSON shape or the keg SBOM carries a CPE.
  What does exist: `pkg:brew/...` purls (SBOM only, nobody indexes them), the upstream **source URL** (62% GitHub, 7% PyPI, 3% npm ...) and,
  new in 2026, Homebrew's own `brew vulns` (OSV `GIT` ecosystem by repo URL + tag; reads the keg SBOM) plus the
  `Homebrew/advisory-database` (`BREW-*` records, only for CVEs fixed by formula patches; **not ingested by osv.dev yet**).
- **Name matching alone is weak, name + vendor corroboration is good.** On 8,707 formulae x 43,686 real 2025 CVE records:
  name == CVE `affected.product` hits 427 formulae (4.9%); 298 of them are also vendor-consistent with the formula's homepage/url
  (~97% correct by manual spot check); the 129 without vendor support are ~55-60% false (`portal`, `cobalt`, `dex`, `sd`, `hub`, `gh`, `protobuf` ...).
  A curated seed (`src/secmonk/data/brew_cpe_seed.csv`, 457 rows / 415 formulae) is the pragmatic backbone; measured on a real prefix (2026-11-08) it carries three quarters of the findings with high precision, see *Measured on a real prefix*.
- **Bottle layer blobs are not reachable here** (`pkg-containers.githubusercontent.com` blocked), but the **ghcr.io manifest annotations
  carry the full receipt (`sh.brew.tab`) and the SBOM supplement**, which is what the fixtures are built from (see Fixtures).

## Access / probe log (2026-11-07, dev sandbox)

| Resource | Result |
|---|---|
| `raw.githubusercontent.com/Homebrew/homebrew-core/<sha-or-main>/Formula/<l>/<name>.rb` | OK; any commit SHA works (the SHA is in the bottle manifest) |
| `git clone --depth 1 --filter=blob:none --sparse` `Homebrew/homebrew-core` + `sparse-checkout set Formula Aliases` | OK: clone 1.2 s, checkout 4.0 s, `.git` 13 MB, `Formula/` 40 MB, **8,707 formulae, 281 aliases** (HEAD `e1aed39`, 2026-11-07) |
| same for `Homebrew/homebrew-cask` (`Casks`) | OK: 2.4 s, `.git` 5 MB, `Casks/` 32 MB, **7,818 casks** |
| same for `Homebrew/brew` (`Library/Homebrew`) | OK: 1 s; used to read `tab.rb`, `sbom.rb`, `vulns/*.rb`, `cask/*.rb` as text (never run) |
| `Homebrew/advisory-database` (`data/repology.json`, `overrides.yml`) | OK: 1 s; 763 KB `repology.json` (5,524 formulae) |
| `ghcr.io/v2/homebrew/core/<name>/tags/list`, manifests (`Authorization: Bearer QQ==`) | OK (see Bottle registry) |
| ghcr blob `GET` | **307 to `pkg-containers.githubusercontent.com`: 403 CONNECT, blocked** (not worked around) |
| `pypi.org/pypi/<n>/<v>/json` + `files.pythonhosted.org` wheels | OK (used for the `dist-info` fixtures) |
| `formulae.brew.sh/api/*`, `repology.org`, `api.osv.dev`, github.com HTML/API | blocked. The API JSON shape below is therefore taken from `formula.rb#to_hash` / `cask.rb#to_h` in `Homebrew/brew`, not observed live |
| `CVEProject/cvelistV5` sparse `cves/2025` | OK (45,479 files, 28 s; deleted afterwards) |

## On-disk layout

Prefix (`HOMEBREW_PREFIX`), repository and cellar:

| Platform | Prefix | Repository (`brew` git clone) | Notes |
|---|---|---|---|
| macOS Apple Silicon | `/opt/homebrew` | same as prefix | default |
| macOS Intel | `/usr/local` | `/usr/local/Homebrew` | `/usr/local/Cellar`, `/usr/local/Caskroom` |
| Linuxbrew | `/home/linuxbrew/.linuxbrew` | `<prefix>/Homebrew` | non-default prefixes allowed (`~/.linuxbrew`, any dir) -> probe for `Cellar/` + `bin/brew` |

```
<prefix>/
  Cellar/<formula>/<version>[_<revision>]/        # a keg; several versions side by side
      INSTALL_RECEIPT.json  sbom.spdx.json  .brew/<formula>.rb  bin/ lib/ libexec/ ...
  opt/<formula> -> ../Cellar/<formula>/<version>  # ACTIVE keg (relative symlink; also one per alias and per old name)
  var/homebrew/linked/<formula> -> ../../../Cellar/<formula>/<version>   # present only if linked (NOT for keg-only)
  var/homebrew/pinned/<formula> -> ../../../Cellar/...                   # `brew pin`
  var/homebrew/pinned_casks/<token> -> ../../../Caskroom/<token>/<ver>   # `brew pin --cask`
  Caskroom/<token>/<version>/ , Caskroom/<token>/.metadata/...
  Library/Taps/<org>/homebrew-<name>/{Formula,Casks,Aliases,...}
  bin/ sbin/ lib/ include/ share/ etc/ opt/   # symlinks into kegs: global pip/npm also lands in lib/python3.x, lib/node_modules
```

Facts (paths: `Library/Homebrew/startup/config.rb`, `keg.rb`, `formula.rb`; fixture `prefix/`):

- **Version directory name = `pkg_version`** = upstream `version` + (`_<revision>` if `revision > 0`): `openssl@3/3.6.4_1`, `httpie/3.2.4_13`.
  Bottle rebuilds are **not** in the directory name (`jq` 1.8.2 rebuild 1 is still `1.8.2`; the rebuild lives in the receipt's `runtime_dependencies[].bottle_rebuild`).
  HEAD builds are `HEAD-<shortsha>`. Strip with `re.sub(r"_\d+$", "", v)` for upstream matching; keep the full string for display.
- **Active keg.** `opt/<name>` is (re)written by `Keg#optlink` on install/link/upgrade, always relative (`../Cellar/<name>/<ver>`). Resolve with
  `os.readlink` and take the last path component; do not `realpath` through the fixture root. `Formula#any_installed_prefix` prefers
  `opt`, else the **last** entry of `installed_prefixes`. Old kegs linger when `brew cleanup` has not run, when the formula is pinned, or with
  `HOMEBREW_NO_INSTALL_CLEANUP`. Fixture: `jq` has `1.8.1` + `1.8.2`, `opt/jq -> 1.8.2`.
- **Linked vs opt.** Keg-only formulae (`keg_only` DSL, 248 of 8,707 in homebrew-core: `openssl@3`, `curl` on macOS, versioned formulae) have `opt/<name>` but **no
  `var/homebrew/linked/<name>`**: still installed and runtime-relevant (other kegs load them from `opt/`). Use `linked` only as a hint; `opt` is the active marker.
- **Pinned** kegs: `var/homebrew/pinned/<name>` symlink; surface `pinned=true` (it explains why a stale version stays).
- **Names.** The rack directory is the formula *name* (`openssl@3`, `python@3.13`, `gcc@14`; 194 of 8,707 formulae are versioned `@N`). Aliases (`openssl` -> currently `openssl@4`,
  `python3` -> `python@3.15`; 281 in `Aliases/`) move over time and appear only as extra `opt/<alias>` symlinks and receipt `aliases[]`: **never derive identity from an alias**.
  Renamed formulae keep a compat symlink `opt/<oldname>`; `Cellar/<oldname>` may be a symlink to the new rack (skip symlinked racks to avoid double counting).
  `formula_renames.json` (103 entries), `tap_migrations.json` (37; formula moved to `homebrew/cask` etc.), `synced_versions_formulae.json` (64 groups that must share a version,
  e.g. all `*-binutils`) live at the root of homebrew-core.
- Permissions: Cellar is world-readable on a default install; user-owned on Apple Silicon.

## `INSTALL_RECEIPT.json` (formula)

Written by `Tab#write` (`Library/Homebrew/tab/tab.rb`, schema read from source 2026-11-07, validated against the fixtures). Real example: `prefix/Cellar/jq/1.8.2/INSTALL_RECEIPT.json`.

| Key | Meaning / use |
|---|---|
| `homebrew_version` | **Poured bottles: the brew that BUILT the bottle in CI** (`6.0.18-9-gac983be` in jq 1.8.2; `4.5.8-...` in the 2025 jq 1.8.1), not the user's. For source builds: user's brew. Not an install date. |
| `time` | install epoch (seconds). Use as install time. |
| `source_modified_time` | epoch of the formula source (bottle build time basis) |
| `poured_from_bottle`, `built_as_bottle` | bottle vs source build; `used_options`/`unused_options` = build flags (non-empty => custom build; `[]` for bottles) |
| `installed_on_request` | user asked for it (vs pulled as dependency). The old `installed_as_dependency` key is "long-removed" (ignored by `Tab`): **do not rely on it**; derive "dependency" as `not installed_on_request`. |
| `loaded_from_api`, `loaded_from_internal_api` | formula came from formulae.brew.sh JSON, not a local tap checkout (default since brew 4.x; `homebrew/core` is then not cloned under `Library/Taps`) |
| `source.tap` | `homebrew/core`, `user/tap`...; `source.tap_git_head` (tap commit), `source.path` (the formula path at install time), `source.spec` (`stable`/`head`), `source.versions.{stable,head,version_scheme,compatibility_version}`; `source.scm_revision` (source builds) |
| `runtime_dependencies[]` | `{full_name, version, revision, bottle_rebuild, pkg_version, declared_directly, compatibility_version?}`; recomputed at install. A **dependency-with-version graph**: `curl` records the exact `openssl@4 4.0.3` it was linked against (fixture) |
| `aliases[]`, `compiler`, `stdlib`, `arch` (`arm64`/`x86_64`), `built_on{os,os_version,cpu_family,xcode,clt,...}` | `built_on.os_version` = build host (`macOS 15.7`), **not** the running OS |
| `changed_files`, `linkage_files`, `binary_relocation_files`, `relocated_*`, `built_prefix`, `padded_prefix` | relocation bookkeeping; ignore |
| (cask receipt only) `uninstall_flight_blocks`, `uninstall_artifacts`, `runtime_dependencies{cask:[],formula:[]}`, `source.version` | see Casks |

Receipt vs bottle: the receipt inside the bottle tarball (= registry annotation `sh.brew.tab`) has **no** `time`, `installed_on_request`, `poured_from_bottle`, `loaded_from_*`,
`aliases`, `source.*`; `Utils::Bottles.load_tab` + `FormulaInstaller#pour` add them at install. When the API path is used the receipt is built from the manifest annotation
(`bottle_tab_attributes`), not from the tarball. Very old receipts (pre brew 1.1.6) have no `runtime_dependencies`; a keg without receipt is possible (fall back to directory names, `confidence` lower).
A receipt can be `""`/corrupt (`Tab.from_file` returns an empty tab): tolerate.

## `.brew/<formula>.rb` (offline formula copy)

`FormulaInstaller` stores the formula used for the keg at `<keg>/.brew/<name>.rb` (the `bottle do ... end` block removed); bottles ship it inside the tarball.
It is **plain Ruby text: parse with regex, never execute.** Offline fields (2-space-indented top level): `desc`, `homepage`, `url` (stable source; `stable do ... url` when
there are patches/resources), `sha256`, `mirror`, `license` (SPDX string, `any_of:`/`all_of:` arrays), `head`, `revision`, `version_scheme`, `keg_only`, `deprecate!`/`disable!`,
`livecheck`, `depends_on`, `patch do ... resolves "CVE-..." end`, `resource "x" do url ... end` (vendored language deps; httpie lists 14 PyPI resources with exact versions).
Measured on homebrew-core: homepage 100%, stable url 100% (237 need the `stable do` fallback), license 100%, `deprecate!` 512, `disable!` 511.
Fixtures: `.brew/*.rb` are the real formulas at the bottle's commit.
Caveat: `url` points at the **source tarball**, and the receipt/dir version is the formula version, which is *not always the upstream version string*
(`ca-certificates` `2026-09-25`, `openssl@3` url tag `openssl-3.6.4`, versions with `.dots_to_underscores` in the url).

## Keg SBOM (`sbom.spdx.json`): findings

Source of truth: `Library/Homebrew/sbom.rb`, `formula_installer.rb` (`update_pour_metadata`), `vulns/scanner.rb`, plus the real registry annotation `sh.brew.sbom.supplement`
(see below). **Bottles ship `sbom.spdx.json` inside the keg** (SPDX 2.3, `dataLicense: CC0-1.0`); source installs also write one since brew ~4.3.17 (real prefix, 2026-11-08: 9 of 18 source builds have an SBOM with only the `Archive` + compiler packages), kegs installed by brew <= 4.2 have none (305 of 359 active kegs have one). The bottle's SBOM is created at
bottling time with `bottling: true` (source archive + patches only), and at pour time brew rewrites `creationInfo` (`created` = install time, `creators: ["Tool: https://github.com/Homebrew/brew@<installer version>"]`)
and **appends the supplement** (runtime dependencies, compiler, the bottle itself) taken from the manifest annotation. Evidence from 7 real manifests (jq x2, openssl@3, curl, xz, httpie):

| Observation | Detail |
|---|---|
| purls: **yes**, type `brew` | Runtime deps: `pkg:brew/oniguruma@6.9.10`, `pkg:brew/openssl%404@4.0.3` (`@` percent-encoded); Bottle package: `pkg:brew/jq@1.8.2`, `pkg:brew/openssl%403@3.6.4_1` (**includes `_revision`**). Source `Archive-<name>-src` package: purl built as `pkg:brew/<tap>/<name>@<upstream version>` from code (`pkg:brew/homebrew/core/jq@1.8.2`). **Observed on a real prefix (2026-11-08, brew 6.0.21, 398 SBOMs)**: 354 Archive packages carry **no purl**, 44 (installed by brew >= 5.1.14 or dev) carry only `pkg:brew/homebrew/core/<f>@<v>`; the plain `pkg:brew/<f>@<pkg_version>` purl is on `Bottle-<f>`. |
| purl for the **registry** when the source URL is a registry artifact | `Identify.registry_package(url)` adds a second `externalRefs` purl to the Archive package for PyPI (`files.pythonhosted.org`), npm (`registry.npmjs.org/.../-/`), crates.io, RubyGems, Hackage, Hex, CPAN, Maven, CRAN, NuGet. This is an **OSV-ready identity** for ~920 formulae (pypi 582 + npm 271 + crates 27 + ...). **Never observed** on the real prefix (2026-11-08): no Archive package had a registry purl, not even for PyPI-sourced formulae; read it from code only, derive it from `downloadLocation` instead. |
| CPEs: **none** | no CPE anywhere in the document, the DSL or the API shape |
| Source identity | `SPDXRef-Archive-<name>-src`: `name`, `versionInfo` (upstream version, no revision), `downloadLocation` (the formula `url`), `checksums[SHA256]`, `licenseConcluded` (SPDX), `builtDate`; `files[]` with the tarball file name. `brew vulns` derives `(repo url, tag)` from exactly this package. |
| Patches | external `patch do url ... end` blocks become `SPDXRef-Patch-<name>-<n>` packages (`downloadLocation`, sha256) + `PATCH_APPLIED` relationship. Inline/DATA patches and `resolves` ids are **not** in the SBOM; read `.brew/<name>.rb`. |
| Dependencies | only with the supplement (bottles from ~2026): `RUNTIME_DEPENDENCY_OF` each dep (`name`, `versionInfo`=pkg_version, bottle `downloadLocation` blob URL + sha256, purl), `BUILD_TOOL_OF` compiler (`clang`/`gcc-13`, `versionInfo` = Xcode version or `NOASSERTION`), `DEPENDENCY_OF` stdlib. |
| Older bottles | `jq 1.8.1` (built 2025-07, brew 4.5.8) has **no supplement** annotation: its SBOM only has the source archive. Treat SBOM as optional and per-keg. |
| Absent | `sbom.spdx.json` can be missing (old installs, source installs without `HOMEBREW_SBOM`): `brew vulns` itself warns "no SBOM was written at install time". |

Real supplement (jq 1.8.2, `arm64_sequoia`, from the manifest annotation, trimmed): packages `oniguruma 6.9.10` (purl `pkg:brew/oniguruma@6.9.10`, sha256 of its bottle blob), `clang 26.3`,
`Bottle-jq` (`downloadLocation` = ghcr blob URL, sha256 `ef70e236...`); relationships `RUNTIME_DEPENDENCY_OF`, `BUILD_TOOL_OF`.

## Casks

Sources: `Library/Homebrew/cask/{metadata,caskroom,installer,cask,tab}.rb`, 7,818 real cask files, 3 fixtures (`casks/`).

```
Caskroom/<token>/
   <version>/                       # staging dir. `app "X.app"`: the app is MOVED to /Applications and `<version>/X.app` becomes an
                                    # absolute symlink to it (moved.rb `ln_sf target, source`); `pkg` casks leave the .pkg here
   .metadata/INSTALL_RECEIPT.json   # cask Tab (same AbstractTab keys + uninstall_artifacts, runtime_dependencies{cask,formula})
   .metadata/config.json            # cask config (appdir ...)
   .metadata/<version>/<timestamp>/Casks/<token>.{json|internal.json|rb}   # timestamp = %Y%m%d%H%M%S.%L, UTC
```

- Installed version = directory of the **newest timestamp** (`Caskroom.cask_installed_version`: `max_by basename` of `.metadata/*/*`), which can differ from `<version>/` dirs left over
  from older versions; prefer the metadata one. `version :latest` casks: dir `latest`, so **no usable version in Homebrew**.
- Newer brew writes a **minimal JSON** (`to_installed_json_hash`: only `url_specs`, uninstall/zap `artifacts`, and `version` when it differs from the directory) when the cask has no uninstall
  flight blocks, and the original `.rb` otherwise. Consequence for the existing collector: **`token`/`name`/`homepage`/`artifacts[].app` may be missing from new installs' JSON** (the macOS doc's fixture is the
  old, richer shape). Robust order: token from `Caskroom/<token>`; app names from `Caskroom/<token>/<version>/*.app` symlinks (target = `/Applications/X.app`); `.rb` (regex) when present; the API cask JSON only as optional enrichment.
  **Real prefix (2026-11-08, brew 6.0.21, 9 casks)**: API-installed casks store a minimal `<token>.json` (`{}`, or only `url_specs`/`artifacts`: no `name`,
  `version` or `auto_updates`) - 6 of 9; `.rb` only for untapped casks - 3 of 9. `.metadata/INSTALL_RECEIPT.json` exists on 3 of 9 (installed by brew >= 4.5),
  `.metadata/config.json` on 9 of 9.
- **Version truth is the `.app`**: 2,074 of 7,818 casks (26.5%) declare `auto_updates true` (Chrome, VS Code, Slack, Zoom...): the app updates itself behind Homebrew's back and the cask
  `version` goes stale (and `brew upgrade` skips them). Another 2,157 (27.6%) are `version :latest`. So for ~54% of casks the Info.plist `CFBundleShortVersionString` of the app bundle must be the component version; the cask only gives identity (token, homepage, bundle ids via `uninstall quit:`/`zap`, e.g. `org.videolan.vlc`).
  Existing dedupe rule (app bundle wins, cask token as alias) is right; make it explicit that cask `version` is **never** used for matching when `auto_updates` or `latest`.
- Cask DSL fields (from the real `.rb`): `version`, `sha256` (`:no_check`), `url`, `name`, `desc`, `homepage`, `livecheck`, `auto_updates`, `depends_on macos:`, `app`/`pkg`/`binary`, `uninstall quit:/pkgutil:/launchctl:`, `zap trash:`, `deprecate!` (218), `disable!` (888).
  `uninstall pkgutil:` ids and `uninstall quit:` bundle ids are strong joins to pkgutil receipts and Info.plist.
- Pinned casks: `var/homebrew/pinned_casks/<token>`.

## Taps

`<repository>/Library/Taps/<org>/homebrew-<name>/` (`homebrew/core` and `homebrew/cask` are no longer cloned by default on API installs; third-party taps always are).
Receipt `source.tap` = `org/name` (`homebrew/core`, `hashicorp/tap`); `source.path` shows the file used. Tap formulas have arbitrary URLs and are **not** in the seed/CPE data: identity from `.brew/<f>.rb` url only. Untrusted tap formulae are Ruby: parse only.

## Vendored language dependencies (precise, OSV-matchable)

Homebrew vendors dependencies *inside the keg*, invisible to a name-only brew match but precisely matchable through PyPI/npm OSV:

| Mechanism | Count in homebrew-core | Where | Identity |
|---|---|---|---|
| `virtualenv_install_with_resources` (Python CLIs: httpie, yt-dlp, ansible...) | 655 (594 with PyPI `resource`) | `<keg>/libexec/lib/python3.X/site-packages/<Name>-<ver>.dist-info/METADATA` (+ `homebrew_deps.pth` pointing at dependency formulae's site-packages) | `Name:`/`Version:` -> `pkg:pypi/<pep503-name>@<ver>` (fixture httpie: 14 dists: requests 2.34.2, urllib3 2.8.0, idna 3.20, ...) |
| `std_npm_args` (Node CLIs) | 322 | `<keg>/libexec/lib/node_modules/**/package.json` (nested `node_modules`) | `name`/`version` -> `pkg:npm/...` |
| `std_pip_args` (libs installed into python@3.X) | 72 | `<keg>/lib/python3.X/site-packages` | same as above |
| Go (`std_go_args`) / Rust (`std_cargo_args`) | 1,474 / 1,153 | statically linked in the binary; Go embeds the module list (`go version -m`, buildinfo), Rust has no metadata unless `cargo auditable` | future: parse Go buildinfo from the binary; for Rust the formula version is the only handle |
| global `pip`/`npm` installs into the prefix | n/a | `<prefix>/lib/python3.X/site-packages`, `<prefix>/lib/node_modules` (symlinks into the python@/node kegs' `lib/`) | same collectors as language packages; mark `parent=<python@3.X keg>` |

Note a formula's own version (httpie `3.2.4`) is also `pkg:pypi/httpie@3.2.4` (the `.dist-info` of the app itself is in the same site-packages), so Python CLIs get *two* routes. Dependencies installed as separate formulae (e.g. `certifi`, `openssl@4`) are separate kegs, referenced by `runtime_dependencies`.

## API JSON shape (formulae.brew.sh / `brew info --json=v2`; UNVERIFIED live, shape from brew source)

Endpoints from knowledge, **not reachable here**: `https://formulae.brew.sh/api/formula.json`, `/api/formula/<name>.json`, `/api/cask.json`, `/api/cask/<token>.json`,
`/api/analytics/...`; newer internal JWS bundles (`/api/internal/*.jws.json`); `https://formulae.brew.sh/api/advisories.json` is referenced by `vulns/advisory_database.rb`.
Formula object (`formula.rb#to_hash`): `name, full_name, tap, oldnames[], aliases[], versioned_formulae[], desc, license, homepage, versions{stable,head,bottle}, urls{stable{url,tag,revision,using,checksum},head{url,branch}},
patches[{url,resolves[{type:"security"|"defect",id}]...}], revision, version_scheme, compatibility_version, bottle{...}, keg_only, keg_only_reason, dependencies[], build_dependencies[], uses_from_macos[],
conflicts_with[], caveats, installed[], linked_keg, pinned, outdated, deprecated, deprecation_date/reason, disabled, disable_*, tap_git_head, ruby_source_path, ruby_source_checksum, vulnerabilities{open[],patched[],fixed_count}` (the last
added by `generate-formula-api` from the advisory database). `installed[]` entries mirror the receipt (`version, used_options, built_as_bottle, poured_from_bottle, time, runtime_dependencies, installed_as_dependency?, installed_on_request`).
Cask object (`cask.rb#to_h`): `token, full_token, old_tokens, tap, name[], desc, homepage, url, url_specs, version, installed, installed_time, bundle_version, bundle_short_version, pinned, outdated, artifacts[], depends_on, conflicts_with, auto_updates, deprecated, disabled, ...`.
`bundle_version`/`bundle_short_version` (brew reading the installed app's Info.plist) confirm that Homebrew itself treats the bundle as the truth for `auto_updates` casks.
No CPE/purl/upstream-id field exists in either object (checked in source).

## Bottle registry (ghcr.io)

```
GET https://ghcr.io/v2/homebrew/core/<name>/tags/list                  # '@' -> '/': openssl@3 -> openssl/3 ; header: Authorization: Bearer QQ==
GET .../manifests/<tag>  Accept: application/vnd.oci.image.index.v1+json     # tag = pkg_version[-<rebuild>] e.g. 1.8.2-1, 3.6.4_1
   -> index.manifests[] one per platform; annotations org.opencontainers.image.ref.name = "1.8.2.arm64_sequoia.1"
      platform: darwin "macOS 15.7" arm64 | arm64_tahoe | arm64_sonoma | sonoma (amd64) | arm64_golden_gate (macOS 27) | linux arm64 / amd64 ("Ubuntu 24.04", tags arm64_linux, x86_64_linux)
GET .../manifests/<digest>  Accept: application/vnd.oci.image.manifest.v1+json   # per-platform manifest, 1 gzip layer = the keg
GET .../blobs/sha256:<layer>   -> 307 to pkg-containers.githubusercontent.com    # BLOCKED in the sandbox
```

Annotations are the useful, **fetchable** part (index entry and per-platform manifest): `sh.brew.tab` (the bottle receipt, JSON string), `sh.brew.sbom.supplement` (SPDX fragment), `sh.brew.license`, `sh.brew.bottle.{digest,size,installed_size}`,
`sh.brew.path_exec_files`, `org.opencontainers.image.{version (pkg_version), revision (homebrew-core commit SHA of the formula), created (bottle build time), url (homepage), documentation, source, licenses}`;
the layer title is `jq--1.8.2.arm64_sequoia.bottle.1.tar.gz`. Tag lists are not version-sorted and are paginated (yt-dlp: 100 tags on the first page). The bottle for an older formula state is reachable by tag, and the formula text at that moment via the commit SHA (used for the fixtures).
This gives an **offline-free way to get the exact formula + receipt + SBOM for any published version** (e.g. to back-fill an inventory where `.brew/*.rb` is missing) without downloading the tarball.

## Formula to vulnerability identity

### What upstream provides

| Source | What | Use |
|---|---|---|
| Formula DSL / API / SBOM | **no CPE**; `pkg:brew` purl (SBOM only); registry purl for PyPI/npm/crates/gem/maven/... source URLs (SBOM Archive package, ~920 formulae); forge repo URL (`github.com` etc. in `url`/`head`/`homepage`) | Identity by source URL |
| `Homebrew/brew` `vulns/identify.rb` | `repo_url` (forges: github, codeberg, gitlab.com, gitlab.gnome.org, freedesktop, KDE; lowercase for github), `tag` regexes (`/archive/refs/tags/X.tar.gz`, `/releases/download/X/`...), `registry_purl` | **Copyable rules**; `brew vulns` queries OSV with `ecosystem: GIT, name: <repo url>, version: <tag>`, taking `(url, tag)` from the keg SBOM first (installed truth), else the current formula |
| `Homebrew/advisory-database` | `BREW-<formula>-<CVE>` OSV records, ecosystem `Homebrew`, `pkg:brew/<name>`, ranges `introduced 0 / fixed <pkg_version>`; only CVEs resolved by a formula `patch ... resolves` (17 CVE/GHSA ids in 8 formulae today; 495 formulae carry some `resolves`, 365 have `type :backport`); CC0; **not in osv.dev yet** | Suppress findings fixed by a formula backport (a Homebrew `3.6.4_1` can be fixed although upstream `3.6.4` is "vulnerable"); read the raw repo, no API |
| `advisory-database/data/repology.json` | formula -> distro source package names (Debian, Ubuntu, Alpine, openSUSE, Rocky, Mageia, FreeBSD), **5,524 formulae** | Bridge to OSV distro ecosystems (distro advisories carry upstream CVE aliases); `meta.ambiguous_projects` lists names that need care (binutils, boost, ffmpeg...) |
| `advisory-database/data/overrides.yml` | hand-reviewed `skip`, `registry_package`, per-advisory `range_state`/`upstream_fixed_in` | quality hints |

`brew vulns` itself is "OSV-only, formulae only" (casks and other managers not scanned) and "a complete scan does not guarantee absence of vulnerabilities". It confirms the strategy ranking
Homebrew's maintainers use for authoring (`vulns/match.rb`): `git` (high) > `registry` (high) > `cpansa` (medium) > `distro` (low).

### Measured on real data (experiment)

Data: homebrew-core HEAD `e1aed39` (8,707 formulae parsed by regex), CVE List v5 `cves/2025` (45,479 files, 43,686 PUBLISHED, **20,490 distinct `affected.product` strings**, 21,221 vendor:product pairs,
only **305 distinct forge repos** in `repo`/`collectionURL`, and `packageName` is mostly WordPress/Red Hat RPM names: wordpress.org 5,162, access.redhat.com 2,324, catalog.redhat.com 1,065, github.com 103).
Normalization: lowercase; formula name minus `@N`; aliases added. 2025 only, so "no hit" often means "no CVE in 2025", not "wrong mapping".

Corpus facts (8,707 formulae): stable URL host: github.com **61.9%** (5,390), files.pythonhosted.org 6.7%, sourceforge 4.3%, registry.npmjs.org 3.1%, ftpmirror.gnu.org 1.8%, gitlab.* 1.4%, download.gnome.org 1.2%, apache.org 0.8%, codeberg 0.5%, crates.io 0.3%, other ~19%.
A forge repo is derivable from `url|head|homepage` for **6,504 (74.7%)**; a registry purl for ~920 (10.6%).

| Strategy | All 8,707 | 197 popular formulae | Quality |
|---|---|---|---|
| (a) name == product, exact | **427 (4.9%)** | 66 (33%) | mixed: see next row |
| (a+) (a) AND CVE vendor consistent with homepage/url/head tokens | **298 (3.4%)** | 56 | ~97% correct (spot check: 3 doubtful: `scip`, `surfer`, `distribution`) |
| (a-) (a) without vendor support | 129 | - | **~55-60% false**: `portal` (liferay), `cobalt` (ashlar-vellum), `dex` (teamviewer), `sd` (dahua), `hub` (jetbrains), `gh` (r-lib R package), `protobuf` x4 (stepancheg Rust crate), `lab`/`fabric`/`spin`/`harper` (WordPress themes), `connect`, `cue`... True ones: `assimp`, `glibc`, `qt`, `suricata`, `ncurses`, vendor-less records (`hdf5`, `libtiff`, `postgresql`) |
| (a-pk) via `affected.packageName` only | 63 | 13 | **unsafe**: these are Red Hat RPM names (`bind`, `krb5`, `samba`, `go` -> RHEL's `golang`), their ranges are RHEL builds |
| (b) repo/collectionURL == `url`/`head`/`homepage` forge repo | 69 (1.1% of 6,504) | 9 | high precision, **tiny recall** (305 repos); ~14 spurious products (`kubelet` for kubernetes-cli, `std` for rust, `python-protobuf`, `systemd-coredump`); adds real new ones: `abseil`->abseil-cpp, `erlang`->otp, `docker-buildx`->buildx, `duck`->cyberduck, `virtctl`->kubevirt |
| (c) existing `product_aliases.yaml` (22 brew entries / 30 names) | 28 entries | 15 | product present in 2025 data 14/22, but exact vendor:product only **10/22** (curl: alias `haxx:curl` vs CVE `curl:curl`; python: `python:python` vs `python software foundation:cpython`; `node.js` vs `node`) |
| (d) Repology distro srcname == CVE product | 312 of 4,678 with entries | 191 of 197 have an entry | only **+34 formulae** over (a), but exactly the *variant names*: `imagemagick-full`, `poppler-qt6`, `mupdf-tools`, `jenkins-lts`, `git-svn`, `hdf5-mpi`, `rabbitmq`->rabbitmq-server |
| relaxed (strip `lib`/`gnu-`/`-cli`/version words) | +120 (44 vendor-supported) | - | about half wrong (`gh-ost`->ghost, `librsync`->rsync, `png++`->libpng, every `*-cli` -> server product): use only to *propose* seed rows |

Truth-set evaluation: 144 formulae with a maintainer-known NVD vendor:product; for the 74 whose product string occurs in 2025 CVE `affected.product`: exact-name recall **62/74 (84%)**, 0 product-level false positives;
the 12 misses are all spelling differences: `python@3.x`->`cpython`, `mysql`->`mysql server`, `httpd`->`apache http server`, `bind`->`bind 9`, `expat`->`libexpat`, `krb5`->`kerberos 5`, `kubernetes-cli`->`kubernetes`, `docker-compose`->`compose`.
Vendor-level collisions that a bare `product` match would produce: `xz` (`ulikunitz` Go library vs `tukaani-project`), `protobuf` (`stepancheg` vs `protocolbuffers`), `git` (`git` vs `git-for-windows`), `gh`, `node`/`nodejs`, `libxml2` (3 vendors: `xmlsoft`, `gnome`, `libxml2`).
Generic formula names (`git`, `bind`, `make`, `screen`, `less`, `go`, `rust`, `node`) are the risk class: of the 7 generic-name hits in the corpus (`gh`, `git`, `node`, `node@20/22/24`, `sd`) only `git` and `node` are right, and only because their CVE vendors happen to match.

Best combination (precision first): **seed/alias (curated, vendor:product) -> (a+) name==product with vendor corroboration -> (b)/(d) as vendor-checked extras -> (a-) name-only as `low` confidence, never auto-alert**.
Vendors are soft: CNAs spell vendors differently from NVD (`curl`/`haxx`, `oracle corporation`/`oracle`, `python software foundation`/`python`), so key on **product (+ alias set)** and use the vendor to rank/disambiguate.

### Measured on a real prefix (2026-11-08)

Setup: Apple Silicon, macOS 26.5, `/opt/homebrew` (brew 6.0.21), **361 racks / 465 kegs / 359 active formulae + 9 casks**, plus 2,032 vendored language packages (not part of this
measurement). Mirror `/tmp/mac-seed.db` (never the per-user DB): `sync kev epss` 2 s (1,769 KEV, 401,956 EPSS); `sync cvelist --since 2020` **414 s**, 275,415 records, sparse cache
3.0 GB (`SECMONK_CACHE` pointed at `/tmp`; the per-user `~/.cache` was not writable from the session); `sync nvd` full pull **without API key 1,786 s, 421,174 records**; database **5.4 GB**.
OSV was not synced (brew formulae have no OSV ecosystem). `scan homebrew` takes ~9 s. `sample: real` for this section; asset id, host and user names are omitted.

Identity of the 359 active formulae (`meta.product_source`) and whether any product candidate has a CVE/CPE row in the mirror:

| Source | Before (seed + aliases at 2026-11-07) | After (rows added 2026-11-08) |
|---|---|---|
| `brew-seed` | 84 (78 with rows) | 92 (86 with rows) |
| `alias-table` | 2 (2) | 43 (43) |
| `brew-name-vendor` | 270 (116 with rows) | 221 (81 with rows) |
| `normalized-name` (no identity) | 3 (`cffi`, `gobject-introspection`, `pluto`) | 3 |
| **formulae with no CVE/CPE row** | **162 (45%)** | **148 (41%)** |

The 6 seed formulae without rows (`abseil`, `libassuan`, `libgpg-error`, `libogg`, `libsodium`, `x264`) have correct seed rows: their CVEs carry only `GIT` ranges (`CVE-2025-0838`,
`CVE-2025-69277`) or none since 2020. Most of the 140 remaining misses are libraries and tools with no CVE since 2020 (`qt*` modules, `utf8proc`, `pugixml`...): "no row" is not "wrong identity".
`secmonk inventory unmatched` (normalized-name only: casks and the 3 formulae) went from **12 to 10** (`copilot-cli`, `kopiaui` resolved; `1password-cli`, `Redis Stack`, `RedisInsight`,
`redis-stack-server`, `aws-vault-binary`, `dropstone`, `orbstack` have no CVE spelling in the mirror). The bigger, invisible miss class is `brew-name-vendor` **with a guessed vendor that disagrees
with the CVE vendor**: the matcher lowers those rows to 0.3 and the scan's 0.5 cut drops them (`libx11`/`libxi` hint `x` vs `x.org`, `nomad` hint `nomadproject` vs `hashicorp`, `dbus` hint `dbus` vs
`freedesktop`, `graphite2` hint `silnrsi` vs `sil`); the alias/seed rows above fix 49 formulae of this kind and of the "formula name is not the product" kind (`libnghttp2`->`nghttp2`, `webp`->`libwebp`,
`jpeg-xl`->`libjxl`, `msodbcsql18`->`odbc driver for sql server`, `sdl2`->`simple directmedia layer`).

Findings (open, min confidence 0.5): **979 before -> 1,060 after** (+81: `msodbcsql17` 22, `msodbcsql18` 18, `nomad` 16, `libxi` 9, `mongodb-database-tools` 5, `libx11` 4, `libxtst` 2,
`kopiaui` 2, `libxrender` 1, `copilot-cli` 1, `azure-cli` 1); none removed. Checked: 78 true positives by range, 2 `kopiaui` true by version (KopiaUI bundles the kopia engine), 1 false positive
(`azure-cli` `CVE-2026-69877`: the CNA range itself is inverted, `introduced 2.0.0 / fixed 1.0.7`).

Precision by `product_source` (manual check of version vs the advisory's ranges, `affected` rows of the mirror):

| `product_source` | Findings (after) | Checked | TP | FP | Notes |
|---|---|---|---|---|---|
| `brew-seed` (0.85) | 799 | top-20 share 5 + ranks 21-30 + 20 sampled (`imagemagick`, `unbound`, `traefik`, `postgresql@16`, `ffmpeg@4`, 4 each) | 4 + 5 + 20 | 1 + 5 + 0 | FPs are engine/data classes below, not wrong identities; `zlib 1.2.13` `CVE-2023-45853` is in range but in `contrib/minizip`, which the keg does not ship (scope FP) |
| `alias-table` (0.8) | 124 | top-20 share 15 + the 81 new (`msodbcsql17` via the same NVD rows as `msodbcsql18`) | 15 + 80 | 0 + 1 | `openssl@1.0 1.0.2u` (tap `sidneys/homebrew`) and `node@18 18.20.5` are EOL kegs: every hit real |
| `brew-name-vendor` (0.7) | 137 | 12 sampled (one per formula) | 12 | 0 | identities all vendor-consistent; `cjson` `CVE-2026-16554` is 32-bit only (scope) |
| `normalized-name` (0.4 for formulae) | 0 shown | `pluto` | - | (1) | only candidates are Apache Pluto / plutolang: right to stay under the 0.5 cut |

Systematic false-positive classes (whole run, 1,060 findings; all in `brew-seed` plus the one alias case): **13 inverted ranges** - the generic comparator reads a letter glued to a digit as a
post-release letter (OpenSSL `1.1.1w` rule), so CPython's `introduced 3.13.0a1 / fixed 3.13.0rc2` sorts as "fixed before introduced" and `in_osv_range` leaves every later version affected
(11 findings on `python@3.13 3.13.12` / `python@3.14 3.14.7`: `CVE-2024-3219`, `-6232`, `-6923`, `-7592`, `-8088`...), a release-line floor `3.0` above `last_affected 3.0.0-rc3`
(`traefik` `CVE-2024-28869`), and a CNA typo (`azure-cli` above); **15 unbounded rows** - a CPE row with `introduced 0` and no end next to bounded rows of the same CVE (`ffmpeg 9.0.1`
`CVE-2026-64835`: CNA range 4.4-8.1.2 plus a version-less `cpeApplicability`; `imagemagick 7.1.2-30` `CVE-2017-5506`: NVD `imagemagick:*`). The CNA `versionType: python` is stored but not used for comparison.
Data-driven but correct: NVD lists products that bundle a library (`node 26.8.1` for brotli `CVE-2026-111497`, KEV) and CPEs that differ from the CNA text (`ruby 4.0.1` for GitLab `CVE-2026-97229`: NVD marks `ruby-lang:ruby` vulnerable).

Top 20 findings (ordered as `secmonk findings`): `brotli 1.2.0` `CVE-2026-111497` (KEV) TP; `node 26.8.1` / `node@18 18.20.5` same CVE (NVD CPE) TP; `ruby 4.0.1` `CVE-2026-97229` TP per NVD;
`libssh2 1.11.0` `CVE-2023-48795` TP; 13 x `openssl@1.0 1.0.2u` (`CVE-2022-2068`, `-1292`, `-0778`, `-4304`, `CVE-2023-2650`, `-0286`, `-0215`, `-0464`, `CVE-2021-23840`, `-3712`, `CVE-2024-9143`, `-5535`, `CVE-2026-45447`) TP;
`node@18` `CVE-2026-21710` TP (NVD `<= 20.20.1`); `zlib 1.2.13` `CVE-2023-45853` scope FP. **19/20 TP**. Ranks 21-30: `deno 2.3.3` x2, `traefik 3.6.9` `CVE-2026-85595`, `python@3.11` x2 TP; `python@3.13`/`@3.14` x4 and `imagemagick` `CVE-2017-5506` FP.

Dependency propagation and statically linked binaries (measured only):
- `curl` is not installed on this prefix. Across all 465 receipts, `runtime_dependencies` has 3,458 edges; the most depended-on kegs are `xz` 124, `lz4` 111, `zstd` 109, `ca-certificates` 104,
  `gettext` 101, `openssl@3` 91. `openssl@3` is a runtime dependency of **86 formulae**, but the receipts pin the version **at install time**: 49 record `3.6.3` (the active keg), 37 record 15
  older versions (`3.1.0` .. `3.6.2`). For propagation use the active keg of the dependency (`opt/openssl@3` -> `3.6.3`, also `3.6.2` still in the Cellar), not the receipt's version.
- Mach-O files under `bin`, `sbin`, `libexec` of the 357 active kegs: 1,736. **Go: 27 formulae, 39 binaries, all with readable buildinfo/modules** (`gh`, `hugo`, `traefik`, `prometheus`, `nomad`, `lima`,
  `cloudflared`, `mkcert`, `step`, `kopia`, ...): their embedded modules are invisible to the formula-version match today. **Rust: 13 formulae, 31 binaries, 0 with a `cargo auditable` section**
  (`ripgrep`, `deno`, `rav1e`, `librsvg`, `tree-sitter`, `sqld`; the heuristic also counts Python extension modules in `aws-sam-cli`, `azure-cli`, `cfn-lint` and gccrs strings in `gcc`), so crate versions
  are not recoverable from Rust bottles.

### Seed file: `src/secmonk/data/brew_cpe_seed.csv`

Columns `formula,vendor,product,evidence` (lowercase). 457 rows, 415 distinct formulae (incl. `@N` families: `python@3.10..3.14`, `postgresql@12..18`, `php@8.x`, `node@N`, `openssl@3.x`, `mariadb@N`...).
`evidence`: `cve-affected` 319 (vendor/product spelled exactly as in 2025 CVE `affected`, vendor chosen as the one consistent with the formula's homepage; plus verified spelling variants `bind 9`, `mysql server`, `apache http server`, `libexpat`, `cpython` for `bind`, `mysql*`, `httpd`, `expat`, `python@*`),
`repo-url` 12 (GitHub repo of the formula == CVE `repo`/`collectionURL`), `nvd-cpe` 6 (spelling seen only in NVD CPE data of a cvelist+NVD mirror, added 2026-11-08; ranked after `manual` by the classifier, so a formula's first row is never `nvd-cpe` when it has a CNA spelling), `manual` 120 (NVD CPE spelling from maintainer knowledge, not yet verified against data: **a second row per formula is intentional** when the NVD spelling differs, e.g. `curl,curl,curl,cve-affected` + `curl,haxx,curl,manual`).
Match on `formula` (full brew name incl. `@N`) -> candidate products (all rows) -> test any vendor/product. Rows were derived from 2025 records; 18 rows added 2026-11-08 from a real prefix for formulae whose CVE identity spans several vendor/product spellings (`aria2`, `libx11`, `jpeg-xl`, `webp`, `zeromq`, `little-cms2`, `aom`, `mongodb-database-tools`); single-vendor fixes for brew formulae and casks went to `product_aliases.yaml` (41 entries, each with its evidence CVE id in a comment). Do not add `aomedia:aomedia`: its NVD CPE ranges use dates (`fixed 2021-04-07`) that the generic comparator orders after every `3.x` release (3 false positives on `aom 3.14.1`).

## Recommendations

### Collector (offline, read-only; no `brew` execution)

1. **Prefixes**: probe `opt/homebrew`, `usr/local`, `home/linuxbrew/.linuxbrew`, `~/.linuxbrew` (and `HOMEBREW_PREFIX` if known) for `Cellar/`. Never follow symlinks out of the prefix when scanning an image/tree.
2. **Kegs**: for each real (non-symlink) `Cellar/<name>/<dir>`: `version = dir`, `upstream_version = strip _N` (and `HEAD-*` => head, low confidence). **Active** = `readlink(opt/<name>)` basename (fallback `var/homebrew/linked/<name>`, else newest receipt `time`); emit **all** kegs with `meta.active`, `meta.linked`, `meta.pinned`, `meta.keg_only` and let the engine report only active kegs by default (inactive = "stale keg: removable with `brew cleanup`", finding severity unchanged but flagged).
3. **Receipt** (`INSTALL_RECEIPT.json`): `source.tap`, `source.versions.stable`, `time` (install time), `installed_on_request` (dependency = not on request), `poured_from_bottle`, `runtime_dependencies` (edges `depends_on`, versions), `arch`; keep `homebrew_version` only as "bottle built with". Do **not** use `installed_as_dependency`, `built_on.os_version`, `loaded_from_*` for logic.
4. **Offline formula**: regex `.brew/<name>.rb` for `homepage`, `url` (top-level or first in `stable do`), `head`, `license`, `desc`, `revision`, `deprecate!/disable!` (flag deprecated/disabled formulae as a finding: no more updates), `patch ... resolves "CVE-..."`.
5. **SBOM** (when present): read `packages[SPDXID matches ^SPDXRef-Archive-.*-src$]` -> `downloadLocation`, `versionInfo`, `externalRefs[purl]` (registry purl wins), `checksums`; `packages[...Bottle-*]` purl. Optional; fall back to the `.rb` url + receipt version.
6. **Vendored deps**: for kegs with `libexec/lib/python3.*/site-packages/*.dist-info/METADATA` emit `pkg:pypi/<name>@<ver>` components (`parent` = keg) via the existing Python collector logic; likewise `libexec/lib/node_modules`. These match through OSV precisely. Consider Go buildinfo later (1,474 formulae).
7. **Casks**: Caskroom token + `.app` symlink targets; version from the app bundle Info.plist; use cask `version` only when `auto_updates` is absent and `version != latest`; record `meta.auto_updates` / `meta.cask_version_stale`. Read `INSTALL_RECEIPT.json` + newest `.metadata/<ver>/<ts>/`; tolerate minimal JSON, `.rb` and `.internal.json`.
8. **purl**: keep `pkg:brew/<name>@<pkg_version>` (`@` -> `%40` in the name, matches Homebrew's own encoding; Homebrew writes the tap namespace only in the SBOM Archive package) as the component id; never as an OSV key. Put `upstream_version`, `tap`, `source_url`, `repo_url`, `registry_purl` in `meta`.
9. Treat `brew` CLI JSON (`brew info --json=v2 --installed`) as optional enrichment exactly as today; it has no extra identity data beyond `urls.stable.url`/`homepage`.

### Identity resolver (formula -> vulnerability identity), precedence

| # | Source | Output | Confidence |
|---|---|---|---|
| 1 | SBOM registry purl, or source URL is a registry artifact (`Identify.registry_purl`) | `pkg:pypi|npm|cargo|gem|...@upstream_version` -> OSV ecosystem match | **high** |
| 2 | Vendored `dist-info` / `node_modules` | `pkg:pypi|npm` components | **high** |
| 3 | Forge repo + tag from SBOM Archive `downloadLocation` (else `.rb` url) via Homebrew's `repo_url`/`tag` rules -> OSV `GIT` records (`affected[].ranges[GIT].repo` and `versions[]` tags; the lookup brew does online) and CVE List `affected.repo`/`collectionURL` | CVE/GHSA ids | **high** for OSV-GIT hits, **medium** for cvelist repo match (tiny coverage) |
| 4 | Curated seed + alias table (`brew_cpe_seed.csv`, `product_aliases.yaml`: merge: seed rows, then alias entries override; allow several vendors/products per formula) | vendor:product (product-first; vendor soft) -> cvelist/NVD name matching | **high** for `cve-affected`/`repo-url`, **medium-high** for `manual` |
| 5 | name == `affected.product` AND vendor token present in homepage/url/head (rule used for the 298) | vendor:product | **medium** (~97% precision measured) |
| 6 | Repology distro srcname (`advisory-database/data/repology.json`) == product with vendor corroboration; or distro->upstream CVE aliases | product / CVE ids | **medium-low** (+34 formulae over #5; carries distro ranges, compare *upstream* version only) |
| 7 | name == product without vendor support | vendor unknown | **low**: show as "possible", exclude from alerting/score; this is the 55-60% false class |
| - | `packageName`-only hits (RPM names), relaxed/stripped names | - | **do not use** for matching; use only to propose seed rows |

Rules around it:
- **Version to match**: `upstream_version` (strip `_N`, honor `version_scheme`), not `pkg_version`. Do **not** compare Debian/RPM-style ranges from distro advisories against it; compare the *upstream CVE* ranges.
- **Backports**: a formula with `patch ... resolves "CVE-x"` (or a `BREW-*` advisory) is fixed at that `pkg_version`: mark the finding `fixed_by_formula_patch`, do not alert. Without the advisory-database, a `type :backport` patch (365 formulae) lowers confidence of "vulnerable" for that formula.
- **Dependency propagation**: `runtime_dependencies` pin exact dep versions (curl -> `openssl@4 4.0.3`): a vulnerable `openssl@3` affects every keg that lists it; the SBOM/receipt gives the edge for reporting.
- **Names change**: key identity on the rack name + source URL, not aliases (`openssl` now aliases `openssl@4`); apply `formula_renames.json`/`oldnames` when matching historical receipts. Deprecated/disabled formulae are findings on their own.
- **Cache/refresh**: the seed is derived from one CVE year; regenerate from the full cvelist whenever the mirror refreshes, run strategy #5 on all inventory misses, and review `secmonk inventory unmatched` into the seed. Vendor rows with evidence `manual` should be promoted to `cve-affected` automatically when the data confirms them.
- **Do not execute anything from a scanned tree**: formulae, casks and receipts are parsed as text/JSON only.

## Fixtures and caveats

`tests/fixtures/collectors/homebrew/` (488 KB): 6 kegs (jq 1.8.1 + 1.8.2 with `opt`/`linked` -> 1.8.2; keg-only openssl@3 `3.6.4_1`, curl 8.23.0; xz 5.8.4 pinned; httpie 3.2.4_13 with 14 real `dist-info/METADATA`),
3 real casks. Because bottle blobs are blocked, receipts/SBOMs are **reconstructed from real manifest annotations + brew source** (details and which fields are synthetic: fixture `README.md`).
Validated on a real Apple Silicon prefix (2026-11-08): cask `.metadata` shape, SBOM Archive purl, source-build SBOMs, symlinked racks (`python-certifi` -> `certifi`). Still needed: Intel (`/usr/local`) and Linuxbrew paths.
Experiment limits (the 2026-11-07 corpus experiment; the real-prefix run above used cvelist 2020+ and the full NVD): 2025 CVE records only; "truth" table is maintainer knowledge (NVD spellings) not NVD data (NVD not probed); popular-formula set (197) is hand-picked, not install-weighted (analytics blocked).
