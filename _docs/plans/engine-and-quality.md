---
title: Plan - engine gaps, calibration and test-suite quality
type: plan
context: plans
status: open
platform: any
tags: [plan, engine, matching, versions, prioritization, tests, performance]
updated: 2026-11-07
related: [tech/engine/matching.md, tech/engine/classification.md, references/package-formats/README.md, tech/collectors/dependencies.md]
---

# Plan: engine gaps, calibration, test suite, performance

Platform: **any** (pure Python; developable in the cloud sandbox with the existing fixtures) unless an item says "needs real data" - then run it after
the corresponding source/collector validation in [on-open-network.md](on-open-network.md) / [on-macos.md](on-macos.md) / [on-windows.md](on-windows.md).
Baseline: `uv run pytest -q`; `uv run ruff check .`.

## A. Detection gaps (software that is invisible today)

- [ ] **CPython (and other interpreters) built from source** - `python:*` images keep CPython under `/usr/local`, not detected as a runtime ([dependencies.md](../tech/collectors/dependencies.md) Known gaps).
  ```bash
  uv run secmonk scan docker-image python:3.12-slim --db /tmp/e.db     # needs registry access
  ls /usr/local/lib/libpython3.12.so* /usr/local/bin/python3.12; strings /usr/local/bin/python3.12 | grep -m1 'Python 3'
  ```
  Implement: detect `usr/local/bin/python3.N`, `usr/local/lib/python3.N/` + `include/python3.N/patchlevel.h` (`PY_VERSION`), `usr/local/lib/libpython3.*`; emit runtime `pkg:generic/python/cpython@<ver>` matched via CPE/OSV (`PyPI`-less, product `python:python`). Same for Node (`/usr/local/bin/node` -> `process.version` in `include/node/node_version.h`), Ruby, PHP, OpenJDK
  under `/opt/java`. Test: tiny synthetic rootfs + a real `python:3.12-slim` tar. Update the Known gaps list in dependencies.md and [classification.md](../tech/engine/classification.md).
- [ ] **Go binaries built in GOPATH mode / Go < 1.18** (only stdlib version, or nothing) - [go.md](../references/package-formats/go.md) Pitfalls. Decide: implement the pre-1.18 pointer form via section tables (ELF only first) or document-only. Real binaries needed: build with `GO111MODULE=off go build` and `go1.17.13` (docker `golang:1.17`).
  ```bash
  docker run --rm -v $PWD:/o golang:1.17 sh -c 'cd /tmp && printf "package main\nfunc main(){}" > m.go && go build -o /o/hello117 m.go'
  uv run secmonk collect rootfs ./dir-with-hello117 --db /tmp/e.db
  ```
- [ ] **Non-auditable Rust binaries** (stripped distro-built tools): measure what remains (`rustc` string, registry paths in panic messages, e.g. `/cargo/registry/src/index.crates.io-*/<crate>-<ver>/`). Proof of concept parser for the panic-path form; confidence 0.6; fat/32-bit Mach-O unsupported ([rust.md](../references/package-formats/rust.md)). Needs real stripped binaries (`ripgrep` from apt/brew, `fd`).
- [ ] **Jar group inference** for manifest-only/filename-only jars (no `META-INF/maven/**/pom.properties`) - [java.md](../references/package-formats/java.md) Gaps. Implement engine-side lookup of artifactId among OSV Maven package names (`affected` where ecosystem='Maven' and package like '%:artifactId'); emit confidence 0.5 and `meta.group_inferred=true`. Test with a real `commons-collections-3.2.1.jar` stripped of pom.properties and with a shaded jar (relocated packages) - documented as "not found".
- [ ] **Maven BOM/parent POM resolution and transitive deps from `pom.xml`** (`dependencyManagement`, `import` scope) - [java.md](../references/package-formats/java.md); decide between implementing and "use fat jars / gradle.lockfile".
- [ ] **.NET central package management joined to projects** (`Directory.Packages.props` + csproj `PackageReference` without version; `Directory.Build.props`, MSBuild conditions) - [dotnet.md](../references/package-formats/dotnet.md) Gaps. Fixtures exist (eShop): implement the join (walk up to the nearest `Directory.Packages.props`, honour `VersionOverride`, `GlobalPackageReference`), then test; also `.nuspec`, `.nupkg`, `paket.lock`, assembly versions.
- [ ] **Unpinned manifests are skipped by design** (`requirements.txt` ranges, `package.json` without lock, `pom` ranges): quantify on the 20 most popular GitHub repos and decide whether to emit "range-only" components at low confidence (`vuln_possible`). Record the decision in [dependencies.md](../tech/collectors/dependencies.md).
- [ ] **Homebrew engine gaps** ([homebrew.md](../tech/collectors/homebrew.md) Limitations): dependency propagation (`runtime_dependencies` -> vulnerable `openssl@3` flagged on dependents), `deprecated!`/`disabled!` findings (512/511 formulae), Go/Rust statically linked deps in brew binaries, and the `patched_cves` comment bug (a CVE named in a *comment* above a patch stanza treated as fixed - write a failing test, fix the regex/parse). Advisory-database ingestion itself is in [next-sources.md](next-sources.md).
- [ ] **`GIT` ranges and unparseable CNA versions are stored, not matched** ([matching.md](../tech/engine/matching.md)): implement commit-ancestry-free fallback (match by `versions[]` tag list for GIT records with tags like `v1.2.3`), count how many CVE records are affected on the 2025 set.
- [ ] **Mozilla-style "unaffected-only" CNA records** stored but unused ([matching.md](../tech/engine/matching.md)): handle `status: unaffected` ranges as exclusions.
- [ ] **Vendored/copied source, embedded native libs** (invisible by design; documented in dependencies.md): out of scope; keep as a note.
- [ ] **Language-file ownership by OS packages**: `rootfs` does not drop python/npm files owned by dpkg/rpm (listed "Not done" in [rootfs.md](../tech/collectors/rootfs.md)) -> duplicate findings (OS package + PyPI). Implement ownership via dpkg `.list` / rpm file lists / apk `R:`/`F:` entries; measure duplicates first on `python:3.12-slim` and `ubuntu:24.04` + `apt install python3-requests`. Also egg-info/PKG-INFO, jar/gem inventory ("Not done" list).
- [ ] **Cross-cutting out-of-scope items to keep visible**: reachability analysis (govulncheck-style symbol reachability, JS call graphs) - write an ADR deciding *not now*; Office/M365 build tables live in [next-sources.md](next-sources.md).

## B. Cross-source policy (distro CVE semantics)

- [ ] **Unfixed distro CVEs**: OSV open ranges for `unimportant`/`no-dsa` CVEs flood findings (193 for `python:3.12-slim`). After the tracker import is validated ([on-open-network.md](on-open-network.md) section 1), decide the reporting policy: separate "unfixed" section, default `--fixable`, a stable `triage` vocabulary shared by all distros (see the mapping table in [next-sources.md](next-sources.md) "Distro triage vocabulary"). Document in [matching.md](../tech/engine/matching.md).
- [ ] **VEX ingestion** (OpenVEX / CSAF VEX `not_affected`, `fixed`, `under_investigation`, justification; user-supplied VEX files per asset or per image) -> `finding.suppressed` sticky state (lifecycle in matching.md). Design: `secmonk vex import <file> --asset <id>`; match by purl + CVE; store justification. Sources of VEX (vendor feeds) are in [next-sources.md](next-sources.md).
- [ ] **Alias-graph correctness**: GHSA <-> CVE <-> distro advisory <-> EUVD dedupe (canonical = lowest CVE id). Add property/regression tests with real cases: same GHSA in several OSV ecosystem folders, a GHSA with PYSEC/GO siblings, Rocky/Alma advisories with `upstream[]`.

## C. Calibration with real data (needs real inventories; run after the platform plans)

- [ ] **Confidence calibration of name-based matches** (`brew-seed` 0.85, `alias-table` 0.8, `brew-name-vendor` 0.7, `normalized-name` 0.5/0.4; -0.2 modifiers). Build a labelled set: 200 findings sampled from a real Mac ([on-macos.md](on-macos.md) B), a Windows box ([on-windows.md](on-windows.md) D) and a Linux server; label TP/FP/unknown by hand into `tests/fixtures/calibration/labels.csv` (`asset,component,cve,label`).
  ```bash
  uv run secmonk findings --all --db /tmp/e.db --json > /tmp/findings.json   # if --json is not available, query: sqlite3 -json /tmp/e.db "select ... from finding"
  python scripts/calibrate.py --labels tests/fixtures/calibration/labels.csv   # new script: precision/recall per matched_by and confidence bucket
  ```
  Verify: precision >= 0.9 at the default `--min-confidence 0.5`; reliability diagram per `matched_by`; adjust base values; document in matching.md.
- [ ] **Priority thresholds (P1-P4)** are "deliberately simple" ([scoring.py](../../src/secmonk/engine/scoring.py): KEV -> P1, EPSS >= 0.1 & exposed -> P1, CVSS >= 9 & exposed or EPSS >= 0.1 -> P2, CVSS >= 7 -> P3, modifiers for prod/exposed). On real scans measure the distribution (target: P1 < 1-2 %, P1+P2 < 10 %), the share of findings with no CVSS (NVD April-2026 change) and no EPSS, and the effect of the `EPSS_HIGH=0.1` choice (try 0.05/0.2/percentile).
  ```bash
  sqlite3 /tmp/e.db "select priority,count(*) from finding where status='open' group by 1"
  sqlite3 /tmp/e.db "select count(*) from finding f join vulnerability v on v.id=f.cve_id where v.cvss_score is null"
  ```
  Decide inputs when CVSS missing (use CISA ADP/SSVC from [cvelist-v5.md](../references/vuln-sources/cvelist-v5.md): `Exploitation`/`Automatable`/`Technical Impact`); record in matching.md.
- [ ] **SSVC storage decision** (table vs JSON column) and cross-check CISA ADP KEV hints vs KEV ([cvelist-v5.md](../references/vuln-sources/cvelist-v5.md) TODO list: importer parts, version-expression parser, vendor/product normalization table). Verify which TODO boxes there are stale (importer exists in `sources/cvelist.py`).
- [ ] **Alias table growth** (`src/secmonk/data/product_aliases.yaml`): workflow = `secmonk inventory unmatched` on real assets -> candidate vendor:product from the cvelist mirror -> evidence check -> alias. Build `scripts/suggest_aliases.py` (strategy "Repology/distro srcname == CVE product" and "homepage host == vendor" from [references/homebrew.md](../references/homebrew.md)) and a CI test that every alias key resolves to >= 1 `affected` product in a fixture mirror. Counters before/after in each PR.
- [ ] **Regenerate `brew_cpe_seed.csv` from the full CVE list** (it came from 2025 only): script + diff report; do after `sync cvelist --since 2018` ([on-open-network.md](on-open-network.md) section 3).

## D. Test-suite gaps

Current layout: `tests/collectors/*` (7 files), `tests/sources/*` (8 files), `tests/engine/test_triage.py` (only triage!), `tests/test_e2e_alpine.py`. **No dedicated tests for `engine/versions.py`, `match.py`, `scoring.py`, `classify.py`, `purl.py`, `db.py`, `cli.py`.**

- [ ] **Property tests for version ranges** (`hypothesis` is not a dependency yet: `uv add --dev hypothesis`).
  ```bash
  uv add --dev hypothesis && uv run pytest tests/engine/test_versions_props.py -q
  ```
  Properties: `compare` is a total order per scheme (antisymmetry, transitivity, reflexivity) for deb/rpm/apk/pep440/semver/maven/go/generic; `in_osv_range` agrees with a brute-force evaluation of events over random sorted version lists (introduced/fixed/last_affected/limit, multiple intervals); `first_fixed_after(v)` is the minimum fixed > v and is not in range;
  rpm epoch (`0:` default), Debian `~` and epoch, Alpine `-r`, Maven qualifiers, PEP 440 pre/post/dev/local. Seed the example tests from real OSV records in `tests/fixtures/sources/osv/`.
- [ ] **Unit tests for `scoring.py`** (table-driven over KEV/EPSS/CVSS/exposed/prod/triage; boundaries at 7.0, 9.0, 0.1), `purl.py` (ecosystem/name normalization, `Ubuntu:Pro:18.04:LTS`, `Red Hat:enterprise_linux:9::appstream`, percent-encoded `@`), `classify.py` (vendor/product for apps; false-positive guards), `match.py` (each strategy in the table of [matching.md](../tech/engine/matching.md): dedupe over alias graph, lifecycle fixed/regression/suppressed sticky, `patched_cves`).
- [ ] **Golden-file end-to-end tests**: per collector fixture -> `scan` with a frozen mini-mirror (`tests/fixtures/mirror/mini.db` built from a handful of real OSV/CVE/KEV/EPSS records) -> findings JSON compared to `tests/golden/<case>.json` (stable ordering; regenerate with `pytest --update-golden`). Cases: alpine image (exists as `test_e2e_alpine.py`), Debian image, macOS fixture tree, Homebrew prefix, Windows win11 (older UBR -> findings; patched -> none), shaded jar, Go binary, Rust auditable, Python lockfile, SSH double. Fail on unexpected new findings.
- [ ] **Mutation/negative tests for parsers on hostile input** (path traversal in tar, absolute symlinks, zip bombs, oversized JSON, plist errors, truncated layers): fuzz with `atheris` or hypothesis-generated tar members; assert only warnings, never writes outside tmp.
- [ ] **CLI tests** (`typer.testing.CliRunner`) for `sync --path` per source, `scan`, `findings` filters (`--hide-minor`, `--hide-deferred`, `--fixable`, `--priority`), `inventory unmatched`, `vuln show/search`, exit codes (unknown source -> 2).
- [ ] **CI**: GitHub Actions matrix {ubuntu, macos-14, windows-latest} running `uv run pytest -q` + `ruff check`; this alone validates path/separator/newline portability of the collectors (they are currently run only on Linux). Mark real-machine tests with `@pytest.mark.real_mac/real_windows/network` and skip by default.
- [ ] **Schema/contract tests for sources**: for each importer, assert that unknown fields do not crash (feed the record with extra keys / missing `ranges` / schema versions 1.4.0-1.9.2) - OSV doc says schema versions vary in one dump ([osv.md](../references/vuln-sources/osv.md)).

## E. Performance

Collect one table in this file (or [features/vuln-sync.md](../features/vuln-sync.md)) with real numbers; hardware noted.

- [ ] **DB size and match time with the full mirror** (after [on-open-network.md](on-open-network.md) full OSV sync): `time uv run secmonk scan docker-image python:3.12-slim`, `EXPLAIN QUERY PLAN` for the hot queries in `match.py` (`affected` by ecosystem+package, product lookups); verify indexes (`ix_affected_*`); target: matching 1,000 components < 2 s on a 1 GB DB. Consider storing `raw` compressed or dropping it (osv.md estimate 0.6-1 GB).
- [ ] **Import throughput** (records/s for OSV zip stream, cvelist directory walk with 250k files, NVD JSON): `python -X importtime`, `cProfile`; batch size and `executemany`, `PRAGMA journal_mode=WAL; synchronous=NORMAL` during bulk import; peak RSS of the zip streaming path.
- [ ] **Collector throughput on big inputs** (5 GB image, 1M-file SSH harvest, 20k-package node_modules): see [on-linux-docker.md](on-linux-docker.md) B for the runs; here only the profiling and fixes (stream, avoid reading whole layers into memory, cap per-file sizes).
- [ ] **Regression guard**: a pytest-benchmark (or simple time-bound) test on synthetic 100k-component matching so slowdowns fail CI.
