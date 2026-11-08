---
title: ADR-0006 — Per-user state locations (security)
summary: Decision to keep the database and caches in per-user directories (never CWD-relative), with env overrides, 0700/0600 modes, and the git and digest hardening that goes with it.
read_when: you are about to change where the DB or caches live, how paths are resolved or how git and registry digests are handled safely
type: decision
context: decisions
status: accepted
tags: [security, storage, cli]
updated: 2026-11-07
verified: 2026-11-07
related: [decisions/0004-sqlite-schema-v2.md, tech/architecture.md]
code: src/secmonk/paths.py, src/secmonk/db.py
---

# ADR-0006 — Per-user state locations (security)

## Context
The first prototype wrote `./secmonk.db` and `.cache/secmonk/` relative to the current directory. A security scanner is routinely run
inside the thing it scans (a checkout, a mounted rootfs, an unpacked image). That is dangerous:
- the cvelist cache is a git clone; a planted `.cache/secmonk/cvelistV5/.git/config` (`core.fsmonitor`, hooks, `core.pager`) makes
  `git fetch` execute attacker code;
- a planted `secmonk.db` or blob cache would be trusted as the vulnerability mirror (hiding findings) or as digest-verified layers;
- registry digests are used to build cache paths; an unvalidated digest can traverse out of the cache (`../`).

## Decision
- State is **never CWD-relative**. `src/secmonk/paths.py` resolves it per user:
  - database: `$SECMONK_DB` (file) else `$SECMONK_HOME/secmonk.db` else `$XDG_DATA_HOME/secmonk/secmonk.db`, default `~/.local/share/secmonk/`;
    Windows `%LOCALAPPDATA%\secmonk\`;
  - cache (git clone, image blobs): `$SECMONK_CACHE` else `$XDG_CACHE_HOME/secmonk`, default `~/.cache/secmonk`; Windows `%LOCALAPPDATA%\secmonk\cache`.
- Directories are created 0700 and refused if they are symlinks or owned by another user; the database file is created 0600.
- Read-only commands never create a database; they fail with "no database at X — run `secmonk sync ...` first".
- Hardening that goes with it: git is run with `core.fsmonitor=`, `core.hooksPath=/dev/null` and an `origin` URL check; registry digests are
  validated before use as paths and cached blobs are re-verified; `--db` / `SECMONK_DB` stay as explicit overrides chosen by the user.

## Consequences
- Scans from any directory share one mirror; a scanned tree cannot influence it.
- Containers and CI need `SECMONK_HOME` / `SECMONK_CACHE` (or `--db`) on a persistent volume to keep the mirror between runs.
- Docs and examples must not mention `./secmonk.db` or a CWD `.cache/`.
