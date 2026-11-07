---
title: Debian Security Tracker
type: reference
context: references
status: draft
tags: [vuln-source, linux, distro, backports, matching]
updated: 2026-11-07
sample: synthetic
reachable: no
fixtures: tests/fixtures/sources/debian-tracker/
code: src/secmonk/sources/debian_tracker.py
related: [references/vuln-sources/distros.md, tech/engine/matching.md]
---

# Debian Security Tracker

## Summary

The Debian security team's per-release triage database. For each (source package, CVE, release)
it records whether Debian is affected, the fixed version, an **urgency**, and whether the team
decided not to issue an advisory (`no-dsa`, `postponed`, `ignored`). OSV carries the fixed
versions already; the tracker adds what OSV only partly has: not-affected decisions, `no-dsa`
decisions and urgency. The source fills `distro_triage` so the matcher can drop not-affected
findings and downgrade minor ones.

**Everything here is written from documented formats and memory.** The tracker host is blocked
in the dev sandbox, so no real tracker data has been seen. The fixtures are synthetic. See
"Validate from an open network".

## Access

| Input | URL / path | Reachable here |
|---|---|---|
| Tracker JSON (one file, tens of MB; also served gzip-able) | `https://security-tracker.debian.org/tracker/data/json` | No (proxy 403) |
| Tracker git repo | `https://salsa.debian.org/security-tracker-team/security-tracker.git` (`data/CVE/list`, `data/DSA/list`, `data/DLA/list`) | No |
| Debian security pages | `www.debian.org` | No |

No auth, no delta endpoint. The JSON is a whole snapshot, so `sync` replaces all rows. CLI:

```
secmonk sync debian-tracker                          # download the JSON
secmonk sync debian-tracker --path tracker.json[.gz|.bz2|.xz]
secmonk sync debian-tracker --path security-tracker  # repo checkout (dir)
```

`--path` auto-detects: a directory is a repo checkout (the dir containing `data/`, or `data/`
itself); a file is tracker JSON, decompressed by magic bytes. The cursor is the HTTP `ETag`
(else `Last-Modified`) for downloads, otherwise a SHA-256 of the decompressed JSON content (repo
imports: of the row set). Network errors return `SyncResult(status="error")` and leave existing rows.

## Data format

### A. Tracker JSON

```json
{"openssh": {"CVE-2024-6387": {"description": "...", "scope": "remote", "debianbug": 1074000,
  "releases": {"bookworm": {"status": "resolved", "fixed_version": "1:9.2p1-2+deb12u3",
     "urgency": "high", "repositories": {"bookworm-security": "1:9.2p1-2+deb12u3"}}}}}}
```

Sample: `tests/fixtures/sources/debian-tracker/tracker-sample.json` (**synthetic**, format-exact to
the best of our knowledge; several CVE/package/version pairs are real and also appear in the OSV
Debian fixtures, e.g. `389-ds-base` CVE-2024-2199, `apache2` CVE-2001-1534, glibc CVE-2019-1010022).

| Field | Certainty | Notes |
|---|---|---|
| top level: source package -> CVE/TEMP id -> object | certain | `tracker_service.py` `json` handler builds this nesting; keys are **source** packages |
| `description` | certain | not stored |
| `scope` (`local`/`remote`) | fairly certain | not stored |
| `debianbug` (int) | fairly certain | present only if a bug is linked; not stored |
| `releases` -> `<codename>` | certain | codenames include `sid`; older releases appear while still tracked |
| `status`: `resolved`/`open`/`undetermined` | certain for the three values | read from the tracker's own status vocabulary |
| `fixed_version` | certain it exists on resolved entries; `"0"` = not affected | assumption: **absent** (not `""`) on open entries; the code accepts both |
| `urgency` | certain | text from `unimportant`, `low`, `medium`, `high`, `not yet assigned`, `end-of-life` |
| urgency trailing `*` | **assumed** | the brief says it marks a tracker-set urgency; exact semantics unverified. Stripped, noted |
| `nodsa` (text) | fairly certain | free-text reason, present only for no-dsa style decisions |
| `nodsa_reason` (`postponed`/`ignored`/`""`) | **assumed** | name and values from the brief; code tolerates absence |
| `repositories` (`<codename>[-security]` -> version) | certain but unused | versions actually in the archive |

### B. Repo text files

Fixture: `tests/fixtures/sources/debian-tracker/repo/data/{CVE,DSA,DLA}/list` (**synthetic**).

`data/CVE/list`: a header line `CVE-YYYY-NNNN (description)` (or `TEMP-...`), then tab-indented
lines. Handled forms (`<pkg>` = source package, lowercased):

| Line | Meaning | Row |
|---|---|---|
| `\t[bookworm] - pkg 1.2-3~deb12u1` | fixed in that release | `resolved`, `fixed_version` |
| `\t[bookworm] - pkg <not-affected> (reason)` | never affected | `not-affected`, fixed `0`, note=reason |
| `\t[bookworm] - pkg <unfixed>` / `<undetermined>` | not fixed / not triaged | `open` / `undetermined` |
| `\t[bookworm] - pkg <no-dsa> (reason)` | fix deferred to point release | `open`, nodsa `no-dsa`, note=reason |
| `\t[bookworm] - pkg <postponed> (reason)` | fix postponed | `open`, nodsa `postponed` |
| `\t[bookworm] - pkg <ignored> (reason)` | will not fix | `open`, nodsa `ignored` |
| `\t[bookworm] - pkg <end-of-life> (reason)` | release no longer supported | `open`, urgency `end-of-life`, nodsa `ignored` (choice) |
| `\t- pkg <unfixed> (low; bug #N)` | sid line, open | urgency from the parenthesis (`bug #` dropped); see sid policy |
| `\t- pkg 3.0.13-1 (bug #N)` | sid line, fixed | skipped (sid) |
| `NOTE:`, `RESERVED`, `REJECTED`, `NOT-FOR-US`, continuation lines, `<itp>`, `<removed>`, bare `- pkg` | ignored | none |

Urgency for a bracket row: its own parenthesis if it is exactly an urgency word; else inherited
from the sid line of the same package/CVE; else `not yet assigned`. For `<not-affected>` and
`<no-dsa>`-style lines the parenthesis is always the note.

`data/DSA/list`, `data/DLA/list`: `[date] DSA-5724-1 openssh - security update` (date optional in
the parser), a `\t{CVE-... CVE-...}` line (several allowed), then `\t[bookworm] - pkg version`.
Each (release, package, CVE) that already has a row from `CVE/list` gets `advisory`. If several
advisories cover a row, the one whose version equals the row's `fixed_version` wins, else the first
listed. References without a CVE-list row are counted in the sync message, not inserted.
Not handled: `DTSA`/`DSA` entries in other layouts, `[sid]` DSA lines.

## Mapping

| Tracker | `distro_triage` |
|---|---|
| codename | `ecosystem = Debian:<n>`: jessie 8, stretch 9, buster 10, bullseye 11, bookworm 12, trixie 13, forky 14, duke 15 (older codenames kept so old data does not count as unknown) |
| source package | `package` (lowercase) |
| `resolved` + fixed `0` | `not-affected`, `fixed_version='0'` |
| `resolved` / `open` / `undetermined` | same, `fixed_version` as given |
| `nodsa` present | `nodsa` = `nodsa_reason` if `postponed`/`ignored`, else `no-dsa`; `note` = nodsa text |
| `urgency` | lowercase, `*` stripped; `*` recorded in `note` |
| advisory | NULL for JSON; DSA/DLA id for text imports |
| `TEMP-*` | skipped, counted in the sync message |
| `sid`/`unstable` | **skipped**: OSV has no `Debian:sid`, so the matcher cannot look it up |

**Sid policy in text import.** Tracker semantics (assumed): an unbracketed `<unfixed>`,
`<undetermined>` or `<not-affected>` line applies to every release that has no bracket line. The
importer therefore emits rows for bullseye, bookworm, trixie and forky (`IMPLICIT_RELEASES`),
because most unimportant-urgency items (e.g. glibc CVE-2019-1010022) exist only as that one line.
An unbracketed fixed version is **not** propagated (whether stable is affected needs version
comparison against the archive; the JSON has that answer, the text does not). So text imports
are a subset of the JSON; the equivalence test compares the rows both formats state.

How the matcher should read it: `not-affected` -> drop the finding; `open` + `unimportant`/`low`
or any `nodsa` -> downgrade; `resolved` -> compare installed version with `fixed_version`.

## Quirks & pitfalls

1. Keys are source packages; installed packages are binaries. Map binary -> source first.
2. `fixed_version` `0` on a resolved row means "never affected", not "fixed in version 0".
3. Urgency is Debian's, unrelated to CVSS. `unimportant` still shows `open`.
4. The JSON is ~100k CVE x package entries x several releases. Rows are inserted with
   `executemany` in chunks of 5000; the document itself is parsed in memory (tens of MB).
5. `opts.limit` caps packages (sorted by name), not rows.
6. `end-of-life` mapping to nodsa `ignored` is our choice; the JSON route leaves nodsa NULL there.

## TODO

- [ ] Validate everything below against real data and replace synthetic fixtures.
- [ ] Confirm `nodsa_reason` spelling/values, the meaning of the `*` urgency suffix, and whether
      open entries omit `fixed_version`.
- [ ] Check which codenames the real JSON emits (e.g. `bullseye (security)`-style keys).
- [ ] Decide whether sid should be stored as `Debian:sid`.

## Validate from an open network

```
uv run secmonk sync debian-tracker
sqlite3 <db> "select status, count(*) from distro_triage group by 1"
sqlite3 <db> "select * from distro_triage where cve_id='CVE-2019-1010022'"
git clone --depth 1 https://salsa.debian.org/security-tracker-team/security-tracker.git
uv run secmonk sync debian-tracker --path security-tracker
curl -sO https://security-tracker.debian.org/tracker/data/json && \
  python3 -c "import json,sys; d=json.load(open('json')); print({r for p in d.values() for c in p.values() for rel in c['releases'].values() for r in rel})"
```

Check: the key set of a `releases` entry (field names above), the `urgency` values with `*`,
codenames present, `nodsa`/`nodsa_reason` combinations, and that the JSON and repo imports agree
on the rows both state (the repo import is a subset).
