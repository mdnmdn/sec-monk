---
title: Scan, match and findings
summary: CLI contract of scan (one or several targets), host mode (discover + scan-host), engine image reuse, match, findings, inventory and history commands with filters, --format table|json|csv, --min-confidence, --fail-on, exit codes, warnings, run history and finding lifecycle.
read_when: you use or change scan, scan-host, discover, match, findings or history options, output formats, exit codes, multi-target or host-mode scans, image reuse or CI gating with --fail-on
type: feature
context: features
status: implemented
tags: [cli, matching, prioritization, findings]
updated: 2026-11-11
verified: 2026-11-11
code: src/secmonk/cli.py, src/secmonk/ops.py, src/secmonk/engine/match.py, src/secmonk/engine/queries.py, src/secmonk/engine/scoring.py
related: [features/README.md, tech/engine/matching.md, tech/data-model.md, features/vuln-sync.md]
---

# Scan, match and findings

## What the user gets

One command turns a target into a prioritized list of vulnerable components: `secmonk scan <collector> [target]` collects the
inventory, stores it, matches it against the local mirror and prints the findings. The same engine serves every collector
(see [features/README.md](README.md) for the collectors). Matching strategies, canonical ids, distro triage and priority rules
are in [tech/engine/matching.md](../tech/engine/matching.md); this page is the CLI contract.

## Usage

```bash
secmonk scan macos /                                 # (any collector) collect + save + match + print
secmonk scan rootfs ./rootfs --priority P1           # only P1
secmonk scan rootfs ./rootfs --fail-on P2            # CI gate: exit 3 if an open P1/P2 finding exists
secmonk scan docker-image alpine:3.20 -f json > r.json   # {"asset", "stats", "warnings", "partial", "findings"} on stdout
secmonk scan fs . --no-save                          # match in a temporary overlay: no inventory or findings stored (needs a synced mirror)
secmonk scan docker-engine 'web-*,re:^api-[0-9]+$,db' -f json   # several targets: {"targets": [...]} (one entry per target)
secmonk discover [user@host] [-f json]               # host mode: what can be scanned on this machine / an ssh host
secmonk scan-host [user@host] --only macos,process   # ... then scan the chosen candidates in one run (--all, --yes, or a prompt)
secmonk scan docker-engine image:sha256:<id> -o rescan=true   # re-collect an image already inventoried
secmonk history [--kind scan|sync] [-n 20]           # past scan / sync runs (CLI and web UI), newest first
secmonk history show 12 [--log] [-f json]            # one run: parameters, status, stored result
secmonk match <asset-id> --min-confidence 0.7        # re-match a stored asset after `secmonk sync`
secmonk findings [<asset-id>] --fixable --hide-minor # list stored findings
secmonk inventory assets | show <asset> | unmatched  # what was collected; unmatched = alias-table candidates
secmonk vuln show CVE-2024-3094 | vuln search --ecosystem PyPI --package django --version 4.2.1
```

## Behaviour & rules

- **Filters** (`scan` and `findings`): `--priority P1..P4`, `--fixable` (a fixed version is known), `--hide-minor` (distro triage
  `unimportant`, `ignored`, `end-of-life`), `--hide-deferred` (also `no-dsa`, `postponed`), `-n/--limit` (default 200). `findings --all` includes
  `fixed` and `suppressed` findings. Filters only change what is printed; everything is stored.
- **`--format table|json|csv`** (`-f`) on `scan`, `findings`, `status`, `containers`, `inventory assets|show|unmatched`. json and csv go to
  stdout and informational notes and warnings to stderr, so output can be piped; tables are not truncated when piped.
- **`--min-confidence`** (`scan`, `match`; default 0.5) drops name-based matches (`cve-product`, `cpe-product`) below the confidence.
  Package matches (`osv-package`) have confidence 1.0. The engine function `match_asset` itself defaults to 0.0; the CLI is stricter.
- **`--fail-on P1..P4`** (`scan`): after printing, exit 3 if any *open* finding of the asset is at or above that priority (P1 is highest),
  regardless of the display filters.
- **Exit codes**: 0 ok; 1 runtime error (unknown asset, no database, collector failure, a failed `sync` source; a partial sync exits 0 with a note);
  2 usage error (unknown source/collector, bad option, invalid `--fail-on`); 3 `--fail-on` hit.
- **Warnings** from collectors are always shown (`-q` does not hide them). A **partial** inventory (stream aborted, size caps hit) is stored but
  never makes components disappear: see "Partial scans" in [data-model](../tech/data-model.md#partial-scans).
- **No database**: read-only commands exit 1 with "no database at X"; `sync`, `collect` and `scan` create it in the per-user data dir
  ([ADR-0006](../decisions/0006-per-user-state-locations.md)). `scan --no-save` needs an existing mirror and stores no inventory or findings; the run is listed in the history.
- **Several targets**: a collector may expand one target spec into several (`Collector.expand_targets`; docker-engine:
  comma-separated names, globs, `re:<regex>`, `image:<ref>`, see [inventory-docker](inventory-docker.md)). Each target is
  collected, saved and matched in turn; a failing target is reported (stderr, red) and the others still run. `--fail-on`
  counts open findings over every target. Exit code: 1 if any target failed (after all ran), else 3 on a `--fail-on` hit;
  when both happen both messages are printed and 1 wins. Table output has a section per target; CSV is one document (one
  header) with every target's rows; JSON is the stored scan result `{"saved", "targets": [{collector, target, asset, scan_id,
  stats, warnings, partial, findings[], counts, error, reused, reused_scan_id, tags[], requested_refs[]?}], "stats", "counts"}` (findings filtered by the display flags; `scan_id`
  null with `--no-save`). The target spec decides the shape: a selector (a comma, or a docker-engine glob / `re:` pattern)
  gives this document even if one target matched; a plain target (every other collector, a docker-engine name or
  `image:<ref>`) gives the single-target document `{asset, stats, warnings, partial, findings}`. A spec that matches
  nothing (or an unreachable engine) exits 1 before any scan.
- **Host mode**: `secmonk discover [TARGET]` explores this machine (no TARGET) or an ssh host (`[ssh://]user@host[:port]`)
  and lists scan candidates (`{host{kind, target, name, os, os_version, arch}, candidates[{id, collector, target, options[],
  label, description, available, reason, selected, details}], warnings[]}`; candidate ids such as `macos`, `homebrew`,
  `process`, `fs-home`, `rootfs`, `windows`, `ssh`, `docker`, `docker-images`; how they are found:
  [tech/discover](../tech/discover.md)). `-o` passes discovery options (`identity`, `known_hosts`, `connect_timeout`,
  `probe_timeout`, docker `host` / `context`…). `secmonk scan-host [TARGET]` discovers, then scans the chosen candidates
  (each with its own collector, target and options) in **one run**: `--only id,id` (unknown or unavailable id: exit 2),
  `--all` (every available one), `--yes` (the default selection); with none of them it lists the candidates and asks on a
  terminal (numbers or ids, comma separated, no ranges; default: the selected ones), and exits 2 with a hint when stdin is not a terminal. Output, exit codes and
  `--fail-on` are those of a multi-target scan; a failing item (its target matched nothing, the host refused) is an error
  entry and the others still run. The run is one history row with `params = {mode: "host", host ("local" for this machine),
  items[{id (candidate id), collector, target, options}], save, min_confidence}` and the title `scan host <name>: <ids>`. The web UI's host form posts the same items
  (`POST /api/jobs` with `items`, [web-ui](../tech/web-ui.md#api)).
- **Engine images are identified by their Id**: a docker-engine target `image:sha256:<Id>` (what selectors and
  `docker-images` expand to) maps to the asset `image:@sha256:<Id>`. When that asset already has a stored inventory whose
  latest scan is complete and was written by the current image inventory format (asset meta `inventory_version` =
  `docker_engine.IMAGE_INVENTORY_VERSION`) from an export checked against the Id (`id_verified`), the engine still has that image (it answers with the same Id), and the
  inventory was taken through the same engine (and platform), the scan does not export the image again: it refreshes the
  asset's tags and name and re-matches the stored components against the current mirror, so new advisories show up.
  When the engine cannot confirm the image, the scan collects as usual and reports the engine's error; it never reports a
  reused success it could not check (trust rule: [data-model](../tech/data-model.md#reused-image-inventories)).
  Table output notes the reuse on stderr.
  The target entry then has `reused: true` and `reused_scan_id` (= its `scan_id`, the scan whose inventory was matched); no
  new `scan` row is written. The image is collected again with `-o rescan=true`, after a partial scan, when the inventory
  format changed, and always with `--no-save` (the temporary overlay hides stored inventories).
- **Run history**: every `scan` and `sync` run, from the CLI (`origin: cli`) or the web UI (`origin: ui`), is a row of the
  table `job` ([data-model](../tech/data-model.md#run-history)): title, parameters (secrets redacted: values of option keys such as
  `password`, `pass`, `passphrase`, `token`, `secret`, `*key` become `***`, `ssh_option` commands are redacted, URL
  passwords are dropped (user names kept), also from stored errors and log lines; key-file paths such as `identity`, `tls_key`,
  `*_file` are kept), status (`ok`, `partial` = a partial inventory or some targets failed, `error` = every
  target failed or the run failed, `running`), result (the web job result: per-target entries with up to 500 findings, or the
  sync sources) and the log. A run stopped with Ctrl-C or SIGTERM (exit 143), or whose
  process is gone, shows as `error` / `interrupted`. `--no-save` runs are listed too (their inventory and findings are not stored). The last 200
  runs are kept. `secmonk history` lists them (`--kind`, `-n/--limit`, `-f table|json|csv`; JSON rows = `GET /api/jobs`
  items); `secmonk history show ID` prints one (`--log`, `-f table|json`; JSON = `GET /api/jobs/<id>`); unknown id exits 1.
- **Lifecycle**: a re-scan marks findings no longer detected as `fixed`; `suppressed` is sticky. First/last seen are kept.

## Acceptance criteria

- `scan` of an Alpine rootfs with a vulnerable `xz-libs` prints an `osv-package` finding and exits 0; with `--fail-on` at or below its priority it exits 3 (`tests/test_e2e_alpine.py`, `tests/test_cli.py`).
- `-f json` output parses as JSON on stdout with warnings on stderr only; `-f csv` has a header row.
- An unknown asset id for `match` or `findings` exits 1; an invalid `--priority`/`--fail-on` exits 2.
- Matching, version ordering and canonicalization have offline unit tests (`tests/engine/`).
- A multi-target scan with one failing target scans the others, prints `{"targets": [...]}` and exits 1; every run (including
  `--no-save` and failed ones) appears in `secmonk history` with redacted options (`tests/test_history.py`).

## Implemented by

[tech/engine/matching.md](../tech/engine/matching.md), [tech/data-model.md](../tech/data-model.md), `src/secmonk/cli.py`.
