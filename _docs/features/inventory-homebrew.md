---
title: Homebrew inventory
type: feature
context: features
status: implemented
tags: [cli, homebrew, linuxbrew, collector]
updated: 2026-11-07
code: src/secmonk/collectors/homebrew.py
related: [tech/collectors/homebrew.md, references/homebrew.md, features/inventory-macos.md, tech/engine/classification.md]
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
secmonk scan homebrew /opt/homebrew         # one prefix
secmonk scan homebrew /mnt/disk -o all_kegs=true   # a mounted root; also old kegs (meta.active=false)
secmonk scan macos                          # apps + brew + pkgutil in one asset
```

## Behaviour & rules
- Active keg = `opt/<name>` link; fallback `linked`, then the highest version (`meta.active_guess`).
- `version` is the upstream version (`_N` revision stripped), raw in `meta.brew_version`.
- Name-based findings carry a confidence from the identity source: `brew-seed` 0.85, `alias-table` 0.8,
  `brew-name-vendor` 0.7, bare name 0.4; the default `--min-confidence 0.5` hides bare-name guesses.
- A formula `patch ... resolves "CVE-..."` suppresses that CVE for the formula (stat `patched`).
- Casks with `auto_updates`/`version :latest` never use the cask version when an app bundle exists.

## Acceptance criteria
- Fixture prefix: only the active jq keg; openssl@3 keg-only with `3.6.4_1` -> `3.6.4`; xz pinned; httpie yields 14 PyPI libraries with `via_brew`.
- A real CVE List record (jq CVE-2025-48060) produces a `cve-product` finding at confidence 0.85 for jq 1.7.1, none for 1.8.2, none when patched.
- Linuxbrew prefix discovery works from a root dir and from the prefix itself.

## Implemented by
[tech/collectors/homebrew.md](../tech/collectors/homebrew.md), [classification](../tech/engine/classification.md), [matching](../tech/engine/matching.md).
