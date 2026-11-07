---
title: Homebrew / Linuxbrew collector
type: tech
context: tech
status: implemented
tags: [collector, homebrew, linuxbrew, macos, identity]
updated: 2026-11-07
sample: real
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
  (and `~/.linuxbrew` when the root is `/`) are searched. Asset `homebrew:<hostname|dir name>`, type `server`.
- `collect_prefixes(root, opts) -> (components, warnings)` is the same walk, called by the macOS collector
  (`macos.py` re-exports `parse_brew_info_json`; `brew info --json` via `use_brew_cli` stays macOS-only).
- Options: `-o all_kegs=true` also emits inactive kegs.

## Where the data lives

| Path under the prefix | Use |
|---|---|
| `Cellar/<name>/<pkg_version>/` | keg; dir name = version incl. `_N` revision. Symlinked racks (renames) are skipped |
| `opt/<name>` (relative symlink) | **active keg**; only the link's basename is used, links are never followed |
| `var/homebrew/linked/<name>` | linked; absent for a keg-only formula (only evaluated when the dir exists) |
| `var/homebrew/pinned/<name>`, `pinned_casks/<token>` | `brew pin` |
| `<keg>/INSTALL_RECEIPT.json` | tap, `installed_on_request`, `time`, runtime deps; missing/corrupt tolerated (`meta.no_receipt`, warning) |
| `<keg>/.brew/<name>.rb` | formula text: `desc`, `homepage`, stable `url` (top level or `stable do`), `head`, `license`, `patch` stanzas, `deprecate!`/`disable!` |
| `<keg>/sbom.spdx.json` | `SPDXRef-Archive-*-src` package: download URL, upstream version, non-`brew` purls |
| `<keg>/libexec`, `<keg>/lib/node_modules`, `<keg>/lib/python3.*/site-packages` | vendored language packages |
| `lib/node_modules`, `lib/python3.*/site-packages` | global npm/pip installs |
| `Caskroom/<token>/.metadata/<ver>/<ts>/Casks/<token>.{rb,json,internal.json}` | cask definition; newest `<ts>` = installed version |

## Data format

Formula component (`package`, `purl pkg:brew/[<tap>/]<name>@<pkg_version>`, `@` -> `%40`; `version` = upstream version
with `_N` stripped, used for matching):

| `meta` key | Meaning |
|---|---|
| `brew_name`, `brew_kind=formula`, `brew_version` (raw, e.g. `3.6.4_1`), `tap` | identity |
| `active` / `active_guess` | `opt/<name>` resolves to this keg / no `opt` link nor `linked` entry: highest version guessed |
| `linked`, `keg_only`, `pinned`, `installed_on_request` | link state (`keg_only` only if `var/homebrew/linked` exists) |
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
(`auto_updates` and no app bundle to take the version from), `pinned`, `installed_on_request`.
Minimal `.json` metadata (new brew) is tolerated; the `.rb` text is preferred, then the JSON, then `Caskroom/<t>/<v>/*.app`.

## Classification

Formulae go through the brew identity block of [classification](../engine/classification.md)
(`brew-seed` > `alias-table` > `brew-name-vendor` > `normalized-name`). On macOS the cask <-> `.app` dedupe in
`macos.py` is unchanged: the bundle version wins (also recorded as `also_cask`, `cask_auto_updates`); the cask is
matched to a bundle by app name, token, display name or `cask_bundle_ids` == `CFBundleIdentifier`.

## Limitations

- Fixture kegs are reconstructed from registry data (see fixture README); real-Mac validation of cask `.metadata`
  shape, source-build receipts and Intel/Linuxbrew paths is still open.
- Go/Rust statically linked dependencies are not read (formula version only); no `brew` JSON enrichment in the standalone
  collector.
- Dependency propagation (`runtime_dependencies` -> vulnerable `openssl@3`), deprecated/disabled findings and the
  `BREW-*` advisory database are not implemented; only `patched_cves` suppression is.
- `patched_cves` is a union over patch stanzas: a CVE named in a *comment* above a patch is treated as fixed.
- Casks `version`/receipts of non-installed older versions are ignored; only the newest metadata stamp is reported.
