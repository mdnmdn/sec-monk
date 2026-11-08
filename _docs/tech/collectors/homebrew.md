---
title: Homebrew / Linuxbrew collector
summary: Offline Homebrew and Linuxbrew prefix inventory covering active kegs, casks, formula upstream identity, vendored language packages, data layout and limits.
read_when: you change how Homebrew kegs or casks are read, their upstream identity or CPE mapping, or the macOS collector's Homebrew part
type: tech
context: tech
status: implemented
tags: [collector, homebrew, linuxbrew, macos, identity]
updated: 2026-11-08
verified: 2026-11-08
sample: mixed
fixtures: tests/fixtures/collectors/homebrew/
code: src/secmonk/collectors/homebrew.py
related: [references/homebrew.md, tech/collectors/macos.md, tech/engine/classification.md, tech/engine/matching.md, features/inventory-homebrew.md]
---

# Homebrew / Linuxbrew collector

## Summary

Offline, read-only inventory of a Homebrew prefix (macOS Apple Silicon/Intel and Linuxbrew): **active kegs**, casks,
upstream identity (repo, tag, registry purl, formula-patched CVEs) and the language packages Homebrew vendors inside
kegs. Nothing is executed: formulae are Ruby text parsed with regexes, receipts/SBOMs are JSON.
Research and measurements: [references/homebrew.md](../../references/homebrew.md).

- `secmonk scan homebrew [target]` (collector `homebrew`): `target` is a prefix (a dir containing `Cellar/` or
  `Caskroom/`) or a root dir in which `opt/homebrew`, `usr/local`, `home/linuxbrew/.linuxbrew`, `home/*/.linuxbrew`
  (and `~/.linuxbrew` when the root is `/`) are searched. Asset type `server`, one asset per target: a root is
  `homebrew:<host>` (every prefix below it), a single prefix `homebrew:<host>:<resolved prefix path>`, so scanning
  `/opt/homebrew` and then `/usr/local` gives two assets and the second scan never marks the first prefix's
  components removed (`save_inventory` diffs against the asset's previous complete scan). `<host>` is `-o hostname`,
  else the hostname when the target is `/` or a known live prefix such as `/opt/homebrew`, else the target dir name.
  Every prefix found is walked: an Apple Silicon Mac migrated from Intel typically still has an x86_64 `/usr/local`
  prefix next to `/opt/homebrew`.
- `collect_prefixes(root, opts) -> (components, warnings)` is the same walk, called by the macOS collector
  (`macos.py` re-exports `parse_brew_info_json`; `brew info --json` via `use_brew_cli` stays macOS-only).
- Options: `-o all_kegs=true` also emits inactive kegs (a bool from `ops.parse_opts`; `1`/`true`/`yes` strings are
  accepted from direct callers, `homebrew.flag`).
- `parse_brew_info_json(data, all_kegs=False)` (`brew info --json=v2 --installed`) keeps the same active-keg rule:
  `installed[]` lists every keg, the active one is `linked_keg`, else the highest version. A formula's `oldnames` and
  a cask's `old_tokens` go to `meta.brew_oldnames` (used by `merge_brew` on macOS, see
  [macos.md](macos.md)).

## Where the data lives

| Path under the prefix | Use |
|---|---|
| `Cellar/<name>/<pkg_version>/` | keg; dir name = version incl. `_N` revision. Symlinked racks (renames, e.g. `python-certifi -> certifi`) are skipped |
| `opt/<name>` (relative symlink) | **active keg**; only the link's basename is used (and only when its parent is this rack: `opt/sdl2 -> ../Cellar/sdl2-compat/<v>` after a rename is ignored), links are never followed |
| `var/homebrew/linked/<name>` | linked; absent for keg-only formulae **and** for unlinked ones (`brew unlink`, conflicts), so it says nothing about keg-only (only evaluated when the dir exists) |
| `var/homebrew/pinned/<name>`, `pinned_casks/<token>` | `brew pin` |
| `<keg>/INSTALL_RECEIPT.json` | tap, `installed_on_request`, `time`, runtime deps; missing/corrupt tolerated (`meta.no_receipt`, warning) |
| `<keg>/.brew/<name>.rb` | formula text: `desc`, `homepage`, stable `url` (top level or `stable do`), `head`, `license`, top-level `keg_only`, `patch` stanzas, `deprecate!`/`disable!` |
| `<keg>/sbom.spdx.json` | `SPDXRef-Archive-*-src` package: download URL, upstream version, non-`brew` purls (real SBOMs carry none: the Archive has no purl or a `pkg:brew/homebrew/core/...` one; `pkg:brew` is on `SPDXRef-Bottle-<f>`) |
| `<keg>/libexec`, `<keg>/lib/node_modules`, `<keg>/lib/python3.*/site-packages` | vendored language packages |
| `lib/node_modules`, `lib/python3.*/site-packages` | global npm/pip installs |
| `Caskroom/<token>/.metadata/<ver>/<ts>/Casks/<token>.{rb,json,internal.json}` | cask definition; newest `<ts>` = installed version. API-installed casks store a minimal `<token>.json` (only `url_specs`/`artifacts`, often `{}`); `.rb` only for tap/untapped casks. Symlinked token dirs (renamed casks: `aws-vault -> aws-vault-binary`) are skipped |
| `Caskroom/<token>/.metadata/INSTALL_RECEIPT.json` | `source.tap`, `installed_on_request` (written by brew >= ~4.x; absent on older installs) |

## Data format

Formula component (`package`, `purl pkg:brew/[<tap>/]<name>@<pkg_version>`, `@` -> `%40`; `version` = upstream version
with `_N` stripped, used for matching):

| `meta` key | Meaning |
|---|---|
| `brew_name`, `brew_kind=formula`, `brew_version` (raw, e.g. `3.6.4_1`), `tap` | identity |
| `active` / `active_guess` | `opt/<name>` resolves to this keg / no `opt` link nor `linked` entry: highest version guessed |
| `linked`, `pinned`, `installed_on_request` | link state (`linked` only on the active keg, only if `var/homebrew/linked` exists) |
| `keg_only` | `keg_only` stanza in the installed `.brew/<name>.rb` (absent when there is no `.rb`); may differ from `brew info`, which reads the *current* formula |
| `brew_prefix` | the prefix the keg/cask was found in (`/opt/homebrew`, `/usr/local`, ...); for a purl found in several prefixes, the first one (its receipt/link meta is the one kept) |
| `paths`, `brew_prefixes` | only when the same purl exists in several prefixes: every keg location and every prefix (the component is emitted once) |
| `homepage`, `source_url`, `desc`, `license`, `deprecated`, `disabled` | from `.brew/<name>.rb` |
| `upstream_repo` (`github.com/jqlang/jq`), `upstream_tag`, `upstream_version`, `upstream_purls` | SBOM source archive first, then url, head, homepage; forges: github (incl. `*.github.io`, raw/codeload/api), gitlab.com/gnome/freedesktop, invent.kde.org, codeberg, bitbucket, sourceforge |
| `patched_cves` | CVE ids in `patch` stanzas (url, `resolves`, inline text, comments directly above); the matcher suppresses these findings |
| `runtime_dependencies` (count), `runtime_deps` (`name@pkg_version`), `homebrew_version` (brew that *built* the bottle), `installed_at` | receipt |

Library components (`category library`, evidence `installed`, `meta.via_brew=<formula>`, `pkg:pypi|npm/...`):
the vendored packages found by `walk_dir(binaries=False)` over the keg dirs above (same parsers as `scan fs`;
python `dist-info`, `node_modules`), plus, when the SBOM/source URL is a registry artifact (PyPI, npm, crates.io,
RubyGems), a library for the formula itself (`pkg:pypi/<name>@<upstream version>`, evidence `brew-source`). The same
purl found in several kegs is emitted once (`meta.via_brew_all`). Global packages carry `meta.brew_global=true`.
These match with `osv-package` (confidence 1.0).

Cask component (`application`, `pkg:brew/homebrew/cask/<token>@<ver>`): `cask_apps`, `cask_bundle_ids` (`uninstall quit:`),
`auto_updates`, `version_latest` (`version :latest`: component version is empty, never matched), `version_stale_possible`
(`auto_updates` and no app bundle to take the version from), `pinned`, `installed_on_request`, `brew_prefix`.
The `.rb` text is preferred, then the JSON, then `Caskroom/<t>/<v>/*.app` (an absolute symlink into `/Applications`,
never followed). With the minimal API JSON the display name is the token and `auto_updates`/`homepage` are unknown
(the `use_brew_cli` path has them).

## Classification

Formulae go through the brew identity block of [classification](../engine/classification.md)
(`brew-seed` > `alias-table` > `brew-name-vendor` > `normalized-name`). On macOS the cask <-> `.app` dedupe in
`macos.py` is unchanged: the bundle version wins (also recorded as `also_cask`, `cask_auto_updates`); the cask is
matched to a bundle by app name, token, display name or `cask_bundle_ids` == `CFBundleIdentifier`.

## Limitations

*Describes current behaviour. What is still to do (and how to verify it) is tracked in the plan [on-macos.md](../../plans/on-macos.md); measurements and real-data validation are in the [probe log](../../references/probes.md).*

- Validated on a real Apple Silicon prefix on 2026-11-08 (macOS 26.5, brew 6.0.21; fixtures `real/`): the active-keg
  set equals `brew list --formula --versions` (359/359 names, 463/463 kegs with `all_kegs`), `opt` targets agree
  except one renamed formula. Linuxbrew and an Intel-only machine are still unverified.
- API-installed casks (the default since brew 4) lose display name, `homepage` and `auto_updates` in the filesystem
  walk, so `version_stale_possible` is never set for them; the cask <-> app dedupe on macOS then relies on the token,
  the app name from `artifacts` or the `Caskroom/<t>/<v>/*.app` link.
- Formula `url` inside `if OS.mac? && Hardware::CPU.arm?` / `on_macos do` blocks (common in third-party taps, e.g.
  `hashicorp/tap`) is not read: no `source_url`/upstream repo for those formulae.
- Kegs left in a renamed rack (`Cellar/sdl2/2.32.8` after the rename to `sdl2-compat`, `Cellar/mprocs` after
  `mprocs` -> `dekit`) are reported under the old (rack) name (`active_guess` when `opt/` points into the new rack);
  `brew info` lists them under the new name with
  `oldnames`. With `use_brew_cli` `merge_brew` matches the CLI entry to the walked keg through `meta.brew_oldnames`:
  one component, walk name and purl kept, the new name in `meta.brew_current_name`.
- The walk (opt link, then `linked`) and `brew info` (`linked_keg`, else the highest version) can pick different
  active kegs. `merge_brew` then never adds the CLI's keg next to the walked one: it enriches the walked active keg
  with formula-level keys only and records the CLI's choice in `meta.brew_cli_version`.
- Go/Rust statically linked dependencies are not read (formula version only); no `brew` JSON enrichment in the standalone
  collector. The `use_brew_cli` path is not a superset either: on the real Mac `brew info --installed` silently skipped
  20 of 359 formulae (18 from third-party taps that brew no longer loads: untrusted or untapped, `youtube-dl` deleted from core, the `sdl2` leftover);
  renamed formulae are reconciled by `oldnames` (above).
- Dependency propagation (`runtime_dependencies` -> vulnerable `openssl@3`), deprecated/disabled findings and the
  `BREW-*` advisory database are not implemented; only `patched_cves` suppression is.
- `patched_cves` is a union over patch stanzas: a CVE named in a *comment* above a patch is treated as fixed.
- Casks `version`/receipts of non-installed older versions are ignored; only the newest metadata stamp is reported.


## Review fixes (2026-11)

- Formula/cask `.rb` parsing is a single-pass line-based scan (lines cut at 2000 chars, files capped at 1 MB; no backtracking regexes), so a hostile Ruby file cannot make a scan quadratic.
- Receipts/SBOM/cask JSON (<= 16 MB) and `.rb` files are only read when they resolve inside the scanned root (a symlinked `INSTALL_RECEIPT.json` pointing outside is ignored with a warning); vendored language dirs likewise.
- `meta.source_url` has userinfo/query stripped.
