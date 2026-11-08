---
title: Homebrew inventory
summary: Homebrew and Linuxbrew inventory without running brew - active kegs, casks, vendored Python and npm packages, identity confidence levels, patched-CVE suppression.
read_when: you change how Homebrew packages are inventoried or matched, or need the confidence values given to formula identities
type: feature
context: features
status: implemented
tags: [cli, homebrew, linuxbrew, macos, linux, collector]
updated: 2026-11-08
verified: 2026-11-08
code: src/secmonk/collectors/homebrew.py
related: [tech/collectors/homebrew.md, references/homebrew.md, features/inventory-macos.md, features/inventory-ssh.md, tech/engine/classification.md, features/README.md]
---

# Homebrew inventory

## What the user gets
What is really installed through Homebrew (macOS and Linuxbrew), without running `brew`: the active version of each
formula (not every leftover keg), casks, the Python/npm packages vendored inside formulae (httpie's `requests`...),
matched precisely against OSV, and formulae matched by curated vendor/product identity with an explicit confidence.
CVEs that a formula patch already fixes are not reported.

## Usage
```bash
secmonk sync cvelist ; secmonk sync osv -e PyPI -e npm
secmonk scan homebrew                       # search /opt/homebrew, /usr/local, linuxbrew prefixes
secmonk scan homebrew /opt/homebrew         # one prefix (its own asset: homebrew:<host>:/opt/homebrew)
secmonk scan homebrew /mnt/disk -o all_kegs=true   # a mounted root; also old kegs (meta.active=false)
secmonk scan macos                          # apps + brew + pkgutil in one asset
secmonk scan ssh me@mac.local -o os=macos   # a remote Mac's Homebrew prefix is harvested too (macOS profile only)
```

## Behaviour & rules
- Active keg = `opt/<name>` link (into the same rack); fallback `linked`, then the highest version (`meta.active_guess`).
  The `brew info --json` path (`secmonk scan macos -o use_brew_cli=true`) keeps the same rule (`linked_keg`, else highest).
- Every prefix found is inventoried (`meta.brew_prefix`): a leftover Intel `/usr/local` next to `/opt/homebrew` too;
  the same formula version in both is one component listing both locations (`meta.paths`, `meta.brew_prefixes`;
  `meta.brew_prefix` and the receipt details are the first prefix's).
- Scanning a root gives the asset `homebrew:<host>`; scanning one prefix gives `homebrew:<host>:<prefix>`, so
  scanning `/opt/homebrew` and `/usr/local` separately never reports the first prefix's formulae as removed.
- `meta.keg_only` comes from the formula's own `keg_only` stanza; an unlinked formula is not keg-only.
- Renamed casks (`Caskroom/<old> -> <new>` symlink) are listed once.
- `version` is the upstream version (`_N` revision stripped), raw in `meta.brew_version`.
- Name-based findings carry a confidence from the identity source: `brew-seed` 0.85, `alias-table` 0.8,
  `brew-name-vendor` 0.7, bare name 0.4; the default `--min-confidence 0.5` hides bare-name guesses.
- A formula `patch ... resolves "CVE-..."` suppresses that CVE for the formula (stat `patched`).
- Casks with `auto_updates`/`version :latest` never use the cask version when an app bundle exists.

## Acceptance criteria
- Fixture prefix: only the active jq keg; openssl@3 keg-only with `3.6.4_1` -> `3.6.4`; xz pinned; httpie yields 14 PyPI libraries with `via_brew`.
- A real CVE List record (jq CVE-2025-48060) produces a `cve-product` finding at confidence 0.85 for jq 1.7.1, none for 1.8.2, none when patched.
- Linuxbrew prefix discovery works from a root dir and from the prefix itself.
- Real Apple Silicon prefix (2026-11-08, brew 6.0.21, 359 formulae / 465 kegs / 10 cask dirs): formula set equals
  `brew list --formula --versions` (359 = 359; with `all_kegs=true` 463 = 463); 9 casks (the renamed `aws-vault` alias
  dropped); purls equal to the `brew info --json=v2` path for every formula both see. Real fixtures in
  `tests/fixtures/collectors/homebrew/real/`.

## Implemented by
[tech/collectors/homebrew.md](../tech/collectors/homebrew.md), [classification](../tech/engine/classification.md), [matching](../tech/engine/matching.md).
