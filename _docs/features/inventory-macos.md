---
title: macOS inventory
type: feature
context: features
status: implemented
tags: [macos, inventory, homebrew, collector, cli]
updated: 2026-11-07
code: src/secmonk/collectors/macos.py
related: [tech/collectors/macos.md, tech/collectors/homebrew.md, features/inventory-homebrew.md, features/inventory-ssh.md, tech/engine/classification.md, features/README.md]
---

# macOS inventory

## What the user gets

A list of the software on a Mac: the macOS version, installed apps (including Apple's own), Homebrew formulae and casks (delegated to the [Homebrew collector](inventory-homebrew.md): active kegs only, vendored Python/npm packages, curated vendor/product identity), installer (pkg) receipts, and the Electron/Chromium/Sparkle runtimes bundled inside apps. Every item carries what is needed to match vulnerabilities (name, version, bundle id, purl, CPE). No admin rights are needed.

## Usage

```
secmonk collect macos [/]          # inventory this Mac (or any directory laid out like a Mac root)
secmonk scan macos                 # collect, save and match vulnerabilities
secmonk collect macos tests/fixtures/collectors/macos/root --db /tmp/t.db
secmonk scan macos -o use_brew_cli=true          # ask `brew info --json=v2` instead of reading the Cellar
secmonk scan ssh me@mac.local -o os=macos        # a remote Mac, agentless (see inventory-ssh)
secmonk scan homebrew                            # Homebrew only (see inventory-homebrew)
```

## Behaviour & rules

- Apps are read from `/Applications` (nested folders up to 3 levels), `~/Applications` and `/System/Applications`; Apple apps are `system-app`.
- Electron apps additionally list their Electron version, because Chromium CVEs depend on it, not on the app version.
- Homebrew formulae are `package` components matched by product identity (`cve-product`) with an explicit confidence; the Python/npm packages vendored inside formulae are `library` components matched exactly against OSV (see [inventory-homebrew](inventory-homebrew.md)).
- Other collector options: `-o include_system=false` (skip `/System/Applications`), `-o home=<dir>`, `-o hostname=<name>`.
- A Homebrew cask whose app is already found as an `.app` is not listed twice; the app notes the cask.
- Unreadable plists produce warnings, not failures.
- Works on a directory tree, so inventories from a backup or mount can be analysed on Linux.

## Acceptance criteria

- Chrome is found with its version and bundle id, and classified as vendor google / product chrome.
- Slack yields an Electron component `pkg:npm/electron@30.1.2`.
- `openssl@3` yields `pkg:brew/openssl%403@3.3.1`.
- The `visual-studio-code` cask does not duplicate the VS Code app.
- OS version and pkg receipts are listed; one broken bundle does not abort the run.
- `secmonk collect macos <fixture root> --quiet` exits 0.

## Implemented by

[tech/collectors/macos.md](../tech/collectors/macos.md), [tech/collectors/homebrew.md](../tech/collectors/homebrew.md)
