---
title: Proposal — port sec-monk to a compiled stack (Rust), multi-database, desktop app
type: proposal
context: inbox
status: proposed
tags: [architecture, language, data-model, web-ui, desktop, effort]
updated: 2026-11-08
related: [decisions/0001-language-python-uv-mise.md, decisions/0004-sqlite-schema-v2.md, decisions/0005-prototype-scope-nov-2026.md, decisions/0009-web-ui-vendored-libraries.md, tech/architecture.md, tech/data-model.md, tech/web-ui.md, plans/README.md]
---

# Proposal — port sec-monk to a compiled stack (Rust), multi-database, desktop app

This proposal estimates the effort to rewrite the Python prototype in **Rust**, with three goals:

1. **Separation**: split the single package into components with boundaries the compiler enforces, and ship parts of it on their own (for example a collector-only agent).
2. **Several databases**: SQLite (default, local), PostgreSQL and MySQL/MariaDB.
3. **A desktop app** built with Tauri, or an alternative.

It also compares **other compiled stacks**: Go, C#/.NET and Kotlin/JVM. Read the [summary](#summary) first; the other
sections give the reasoning behind each number.

Inputs are measured from the repository at commit `HEAD` of 2026-11-08. Crate and library names were picked by
knowledge, not by building a prototype. Items marked **(verify)** need a short spike before anyone commits to them.

## Summary

| Question | Answer |
|---|---|
| Size of what we port | 16.9k lines of Python in 64 modules, 581 tests (8.8k lines), 7.6 MB of fixtures. The Vue front end (2.8k lines) and the fixtures can be **reused as they are**. |
| Rust port, same features, SQLite only | **About 40 person-weeks** for one senior Rust developer working the usual way. **About 8–12 calendar weeks** when coding agents do most of the work and one person reviews (that is how this repository was built). |
| Add PostgreSQL and MySQL | **+5–7 person-weeks**, mainly to put a storage layer between the engine and SQL, write migrations for each database and test on all three. |
| Tauri desktop app | **+3–5 person-weeks**, including code signing, notarization and the updater. The current Vue app runs inside Tauri with few changes. |
| Total | **About 48–52 person-weeks** done the usual way; **about 3–4 months** with agents. |
| Hardest part | Replacing `univers`. Version comparison across 8+ schemes must stay exact, because a wrong comparison silently hides a vulnerability. Second: the 7 language parsers and the layered rootfs/tar code, which must give the same results as today. |
| Cheaper compiled alternative | **Go**: **about 30–35 person-weeks**. Version comparison, many extractors, the image registry client and SSH are available as maintained Go libraries (osv-scalibr, go-containerregistry, x/crypto/ssh). Desktop app with Wails using the same Vue app. |
| What you get without porting | Separation and multiple databases **do not need Rust**; both can be done in Python. Only a small, static, signed, single binary (agent and desktop) needs a compiled language. |
| Recommendation | Do not start the full port yet. (1) Freeze the contracts and record reference outputs from Python now. (2) Ship a **Tauri shell with a Python sidecar** to get a desktop app in about 2–3 weeks. (3) Port module by module behind the contracts, **starting with a collector-only agent binary**, once the platform plans in [plans/](../plans/README.md) are mostly done. Choose **Rust** if binary size, memory safety on untrusted input and Tauri matter most; choose **Go** if porting speed and reuse of the scanning ecosystem matter most. |

## 1. What exists today

Measured with `wc -l` on `src/secmonk` (2026-11-08):

| Area | Modules | Python lines | Notes for a port |
|---|---|---:|---|
| Core: `models`, `paths`, `errors`, `db`, `ops`, `reports` | 6 | ~880 | `db.py` holds schema v2 and the migrations: this is the integration contract. |
| Engine: `classify`, `versions`, `purl`, `match`, `scoring`, `inventory`, `queries` | 7 | ~1,370 | `versions.py` delegates to `univers`. Replacing it is the most delicate job. |
| Sources (8 feeds) | 9 | ~3,140 | `cvelist` 877, `osv` 537, `debian_tracker` 422, `nvd` 398. Calls `git` as a subprocess. |
| Language parsers (`collectors/lang`) | 9 | ~2,480 | Go buildinfo and Rust `cargo auditable` binaries, jar/war, .NET deps.json, lockfiles. |
| Rootfs and Docker (`rootfs`, `docker_image`, `docker_engine`) | 3 | ~2,020 | Layered tar view with whiteouts; dpkg/apk/rpm (the rpm database is itself SQLite); registry v2 client; zstd. |
| macOS, Homebrew | 2 | ~1,040 | plists, `.app` bundles, Cellar kegs. |
| SSH, harvest | 2 | ~1,230 | OpenSSH subprocess or `paramiko`; safe tar extraction. |
| Windows | 1 | ~870 | PowerShell JSON, osquery rows, live `winreg`. |
| Process monitor (`collectors/process`, `procmon`) | 7 | ~1,930 | Neutral core + macOS backend (`ps`, `launchctl`, `codesign`). The snapshot format is public. |
| Web (`web/`) | 4 | ~820 | stdlib HTTP server, JSON API, background jobs. |
| CLI | 1 | ~815 | Typer + Rich. |
| **Total** | **64** | **~16,900** | |

Reused without changes in every option:

- `web/static/` (Vue 3 app, CSS, vendored libraries, 2.8k lines) and `_design/`. The API payloads must stay identical, which [web-ui](../tech/web-ui.md) already requires.
- `tests/fixtures/` (7.6 MB) and the fixture READMEs.
- `data/` (`product_aliases.yaml`, `brew_cpe_seed.csv`, the PowerShell inventory script).
- The documentation set. Tech docs need new code paths; feature docs barely change.

Python libraries and how they map to Rust:

| Python | Use | Rust replacement | Risk |
|---|---|---|---|
| `univers` | Version comparison for PyPI, semver, Maven, Go, RubyGems, NuGet, Composer, Debian, RPM, Alpine | `pep440_rs` (PyPI), `semver` / `node-semver` (npm, crates), `debversion` (Debian) **(verify)**. Maven `ComparableVersion`, RPM `rpmvercmp`, apk, RubyGems, NuGet, Composer, Go: **written by us** (~1.5–2k lines). | **High**: security-relevant; see [§6](#6-risks). |
| `packageurl-python` | PURL | `packageurl` crate | Low |
| `httpx` | HTTP with proxy and retries | `reqwest` (rustls, proxy from environment) | Low |
| `typer`, `rich` | CLI and tables | `clap`, `comfy-table`, `indicatif` | Low |
| `paramiko` | Pure-Python SSH | `russh` (pure Rust, async) or `ssh2` (libssh2); `ssh2-config` for `~/.ssh/config`, ProxyCommand written by us | Medium |
| `zstandard` | zstd image layers | `zstd` (C binding) or `ruzstd` (pure Rust) | Low |
| `pyyaml` | `product_aliases.yaml` | `serde_yaml` is no longer maintained. Either use a maintained fork or turn the file into TOML/JSON when building | Low |
| `sqlite3` | State and the rpmdb on targets | `rusqlite` for the target rpmdb; see [§3](#3-goal-2--several-databases) for state | Medium |
| `tarfile`, `zipfile`, `gzip` | Layers, jars, OSV bulk data | `tar`, `zip`, `flate2` | Low (the safety wrappers must be ported, not dropped) |
| `plistlib` | macOS | `plist` | Low |
| `winreg` | Windows live inventory | `winreg` / `windows` crates | Low |
| ELF/Mach-O/PE readers (written by us) | Go and Rust binary identity | `object` or `goblin`; `auditable-info` for Rust binaries; Go buildinfo written by us (~400 lines, same as today) | Medium |
| `http.server` | Web UI | `axum` (or `tiny_http` for a synchronous design), static files embedded with `rust-embed` | Low |

## 2. Goal 1 — separation

### 2.1 Cargo workspace

```
crates/
  secmonk-model       Inventory, Asset, Component, Snapshot, API payload types (serde). No I/O.
  secmonk-versions    version schemes + OSV range evaluation. No I/O. Tested against univers.
  secmonk-purl        PURL <-> OSV ecosystem, name normalization
  secmonk-safeio      read_within / resolve_within, size caps, safe tar/zip readers, redaction
  secmonk-lang        7 language parsers + walk_dir / LangAccumulator          (model, safeio)
  secmonk-collect     collectors: fs, rootfs, docker-image, docker-engine, macos,
                      homebrew, windows, ssh, process  (cfg/feature-gated per OS)  (model, lang, safeio)
  secmonk-store       Store trait + sqlite / postgres / mysql backends (features)  (model)
  secmonk-sources     8 feeds -> Store                                              (store, versions)
  secmonk-engine      classify, match, scoring, finding lifecycle                  (model, store, versions, purl)
  secmonk-ops         reports, jobs, collect/save/match, sync orchestration
bins/
  secmonk             CLI (clap)                 — everything
  secmonk-agent       collector only: target -> inventory JSON / snapshot JSON; no database, no vulnerability data
  secmonk-server      HTTP API + static UI       — what `secmonk ui` does today, plus remote use
  secmonk-desktop     Tauri app                  — same API in-process
```

What this gives:

- **AGENTS.md rules become compile-time rules.** `secmonk-collect` has no dependency on `secmonk-store`, so "collectors
  never touch the DB" is enforced by the compiler instead of by review. Likewise the engine can only reach SQL through the
  `Store` trait.
- **A collector-only agent binary** of about 5–10 MB, static on Linux (musl), with no Python runtime. It can be copied to
  a host over SSH, run, and send back the inventory, replacing the fixed `find | tar` harvest. Today the SSH collector
  copies files back because it cannot run Python on the target. Of everything in this proposal, the agent is the
  biggest *architectural* gain.
- **Features per platform**: a Linux build leaves out the macOS backend unless asked (`cfg(target_os)`), and a
  server build leaves out Tauri.

### 2.2 Contracts to freeze first

These become versioned JSON Schemas and are checked by both implementations during the transition:

- `Inventory` JSON (`collect -O`)
- `secmonk-process-snapshot/1`
- The web/CLI JSON payloads (`reports.*`, `procmon.snapshot_payload`, `event_dict`)
- Database schema v2 (already documented in [data-model](../tech/data-model.md))

The same separation can be done in Python with packages and import linting (`import-linter`), at about 10% of the
cost. The agent binary is the part that really needs a compiled language.

## 3. Goal 2 — several databases

### 3.1 What in today's SQL is SQLite-only

There are about 99 `execute` calls, mostly in `engine/queries.py` (19), `engine/match.py` (17), `db.py` (16), `sources/cvelist.py` (10),
`sources/osv.py` (8) and `sources/base.py` (8). SQLite-only features in use:

| Feature | Where | PostgreSQL | MySQL / MariaDB |
|---|---|---|---|
| `INSERT OR REPLACE` / `OR IGNORE` | `sources/base.py`, `kev`, `epss`, `debian_tracker` | `ON CONFLICT DO UPDATE / NOTHING` | `ON DUPLICATE KEY UPDATE`, `INSERT IGNORE` |
| `ON CONFLICT … excluded.` | `engine/inventory.py`, `match.py`, `euvd.py`, `db.py` | same syntax | `VALUES(col)` / row alias |
| `json_extract(meta,'$.x')` | `queries.py`, `inventory.py`, `msrc.py` (5 places) | `meta->>'x'` (jsonb) | `meta->>'$.x'` |
| `IS ?` (null-safe equality) | `msrc.py` | `IS NOT DISTINCT FROM` | `<=>` |
| `PRAGMA user_version`, `table_info`, WAL | `db.py`, `match.py` | migrations table, `information_schema` | same |
| `?` placeholders | everywhere | `$1` | `?` |
| `TEXT PRIMARY KEY` (vuln ids, component keys) | schema | fine | needs `VARCHAR(n)`: InnoDB caps index keys at 3072 bytes in utf8mb4 |

The rpmdb read in `collectors/rootfs.py` is the **target's** SQLite file. It stays `rusqlite` whatever the state backend.

### 3.2 Design

- A **`Store` trait** that works in domain terms (`upsert_vulnerabilities(batch)`, `affected_for(ecosystem, name)`,
  `save_inventory`, `open_findings(asset)`, `close_missing_findings(...)`). The engine and sources never write SQL.
  This is the real work, and most of it is design, not typing.
- **sea-query** builds statements for each dialect (it handles `ON CONFLICT` and `ON DUPLICATE KEY` for us); **sqlx** provides the
  pools (`sqlite`, `postgres`, `mysql` features). Avoid sqlx's `Any` driver, which supports only the types all three share. Diesel works
  with several backends, but code generic over its `Backend` type is awkward; SeaORM is an option if an ORM is wanted.
- **Migrations**: one ordered set per dialect (sea-orm-migration or `refinery`), with a `schema_migrations` table in
  place of `PRAGMA user_version`. The additive-migration rule of [ADR-0004](../decisions/0004-sqlite-schema-v2.md) stays.
- **JSON columns**: `TEXT` on SQLite, `jsonb` on PostgreSQL, `JSON` on MySQL. The few fields queried through JSON (`product_source`,
  `partial`, `product`, `bundle_id`) should become real columns, which also removes the dialect differences.
- **Bulk sync**: OSV and the CVE List write hundreds of thousands of rows. Give the trait batch methods: one transaction
  on SQLite, `COPY` or multi-row `INSERT` on PostgreSQL, batched `INSERT` on MySQL.
- **Concurrency**: SQLite's single writer hides races that PostgreSQL will show when several agents report at once
  (finding lifecycle: open, fixed, re-opened). These paths need explicit transactions and `SELECT … FOR UPDATE`.
- **Split the vulnerability mirror from the inventory.** The mirror can be rebuilt and is read-heavy, so it can stay a
  local SQLite file even when inventory and findings live in a shared PostgreSQL. Allowing different backends for the two
  halves avoids copying a multi-GB mirror into every server database. **Recommended.**
- **Tests**: SQLite in memory by default (offline, as today); PostgreSQL and MySQL through testcontainers in CI, running
  the same `Store` conformance suite.

Effort: **+5–7 person-weeks** on top of a SQLite-only port. Done in Python with SQLAlchemy Core, the same work costs
about the same; the effort comes from the design, not the language.

## 4. Goal 3 — desktop app

### 4.1 Tauri v2 (recommended for Rust)

- **The front end stays as it is.** Tauri can serve a plain directory (`frontendDist` → `web/static`), and
  `withGlobalTauri` exposes its API without a bundler. The "no build step, no network" rule of
  [ADR-0009](../decisions/0009-web-ui-vendored-libraries.md) still holds.
- **API transport**: register a custom URI scheme (for example `secmonk://api/...`) whose handler calls the **same router**
  as `secmonk-server`. In `secmonk-views.js` only `base` changes. The desktop app opens no TCP port, so the `Host`
  check and DNS-rebinding concerns do not apply there; the browser UI (`secmonk ui`) keeps them.
- Jobs and `--watch` can push Tauri events instead of being polled (optional).
- Tray icon, notifications (new P1 finding, new process), start at login and auto-update come with Tauri plugins.
- CSP: Tauri adds nonces to its own scripts; our pages have no inline scripts or styles, so they fit.
- **Distribution**: macOS needs a Developer ID, hardened runtime and notarization. The app cannot be sandboxed for the Mac
  App Store, because the process monitor runs `ps`/`launchctl`/`codesign` and reads `/Applications` and other apps' bundles.
  Windows needs signing (WebView2 ships with Windows 11). Linux uses WebKitGTK, whose version differs between distributions,
  so test the AppImage/deb/rpm packages.
- Size: about 10–20 MB, against 100+ MB for Electron.

Effort: **3–5 person-weeks** (protocol handler 1, packaging and signing for 3 OSes 1–2, tray/notifications/updater 1,
CI release matrix 1).

### 4.2 Desktop app without porting first: Tauri shell + Python sidecar

Tauri can start a sidecar binary. Package today's `secmonk ui` with PyInstaller or Nuitka (one 40–70 MB executable per
OS) and point the webview at it on a random loopback port, passing a token. This gives a signed desktop app in **2–3 weeks**
and keeps every bit of the Tauri work (configuration, signing, updater, icons) for the Rust version later. **Recommended
as the first step.**

### 4.3 Alternatives

| Option | Language | Reuses the Vue app | Note |
|---|---|---|---|
| **Tauri v2** | Rust (any backend as a sidecar) | yes | Best fit for Rust; small; mature on all three OSes. |
| **Wails v2/v3** | Go | yes | The Go equivalent of Tauri; same system webviews. |
| Electron | Node | yes | Heavy; brings an npm toolchain, against ADR-0009. |
| Dioxus / Slint / egui / iced | Rust native | **no** | The UI would be rewritten. Not worth it: the design system and storybook already exist. |
| Avalonia / .NET MAUI | C# | no (MAUI Blazor Hybrid partly) | Only if the stack becomes .NET. |
| Flutter | Dart | no | Rewrite; adds a fourth language. |

## 5. Effort breakdown (Rust)

"Person-weeks" means one senior developer fluent in Rust and new to this codebase, including tests and docs. The "with
agents" column assumes coding agents write the code and port the tests, while one person reviews, runs the
differential checks and takes the decisions. It is the method this repository was built with (39 commits since
2026-11-07). The review and validation work does not shrink.

| # | Work package | Python lines | Person-weeks | With agents (calendar) |
|---|---|---:|---:|---:|
| 0 | Contracts: JSON Schemas, reference outputs recorded from Python on every fixture, differential runner | — | 1.5 | 0.5 |
| 1 | Workspace, model, paths, errors, purl, safeio, redaction | ~600 | 1.5 | 0.5 |
| 2 | **Version schemes** (univers replacement) + OSV ranges + differential and property tests against univers | 213 (+ library) | 4 | 1.5 |
| 3 | Store trait + SQLite backend + schema v2 migration from existing databases | 346 + ~99 calls | 2.5 | 1 |
| 4 | Engine: classify, match, scoring, lifecycle, queries | ~1,150 | 3 | 1 |
| 5 | Sources (8), including `git` for cvelist and bulk loaders | ~3,140 | 5 | 1.5 |
| 6 | Language parsers (7 ecosystems, binaries, walk) | ~2,480 | 4 | 1.5 |
| 7 | rootfs, docker-image (registry, tarball, OCI), docker-engine | ~2,020 | 4 | 1.5 |
| 8 | macOS + Homebrew | ~1,040 | 2 | 0.5 |
| 9 | SSH (OpenSSH + russh), harvest, safe extraction | ~1,230 | 3 | 1 |
| 10 | Windows (script JSON, osquery, live registry) | ~870 | 2 | 0.5 |
| 11 | Process monitor (core, macOS backend, watch, procmon views) | ~1,930 | 3 | 1 |
| 12 | Reports, ops, jobs, CLI (exit codes, formats, `_t`/`_e` escaping) | ~1,160 | 2.5 | 1 |
| 13 | Web server (routes, Host check, CSRF header, static embed) | ~820 | 1.5 | 0.5 |
| 14 | Tests: port the 581 tests (most become table-driven fixture tests) | 8,800 | 4 | 1.5 |
| 15 | CI matrix (3 OS), release (musl static, macOS universal, Windows), docs rewrite | — | 2 | 1 |
| | **Subtotal: same features, SQLite** | **~16,900** | **~45** (range 38–50) | **~15** of work, in parallel streams **8–12 weeks** |
| 16 | PostgreSQL + MySQL backends, migrations, conformance suite, concurrency hardening | | 5–7 | 2–3 |
| 17 | Tauri desktop app | | 3–5 | 1.5–2 |
| | **Total** | | **~53–57** (range 46–62) | **~3–4 months** |

The numbers assume a feature freeze on the Python side during the port, or that every Python change is mirrored.
Without a freeze, add about 20%.

## 6. Risks

| Risk | Effect | How to reduce it |
|---|---|---|
| Version comparison differs from univers | **False negatives** (missed vulnerabilities) that look like normal output | Differential tests on every version pair in a synced OSV mirror (millions of `(version, range)` checks against Python univers), plus property tests (ordering is transitive and antisymmetric). Block the release until there are 0 differences, or every difference is explained. |
| Parser drift (lockfiles, binaries, dpkg/rpm/apk) | Missing or wrong components | Golden tests: Python and Rust run on every fixture, and the inventory JSON must match after normalization. |
| Safety helpers lost in translation | Path escape or decompression bombs from untrusted targets | Port `read_within`/`resolve_within` first as `secmonk-safeio`; fuzz the tar/zip/plist/lockfile parsers with `cargo-fuzz`. |
| The prototype is still moving | Porting a moving target doubles the work | 138 open items in [plans/](../plans/README.md) are still unverified on real macOS, Windows and Docker. Port each module after its platform plan is mostly done. |
| Async spreads through the code | Harder code, slower port | Keep the core synchronous (`rayon` for parallel parsing). Use `tokio` only in the HTTP client, server and russh, behind small adapters. |
| Few contributors know Rust | Bus factor, slower review | Rust is harder to review than Python or Go. Factor this into the stack choice ([§7](#7-other-compiled-stacks)). |
| Three databases | Every query tested three times; MySQL quirks (index length, collation, JSON) | Support PostgreSQL first; add MySQL only if a user asks for it. |

## 7. Other compiled stacks

| | **Rust** | **Go** | **C# / .NET 9 (Native AOT)** | **Kotlin/Java + GraalVM native** |
|---|---|---|---|---|
| Port effort, same features + 3 DBs + desktop | ~53–57 pw | **~30–35 pw** | ~42–48 pw | ~48–55 pw |
| Version schemes | Mostly written by us | **osv-scalibr `semantic`**: OSV-maintained, every OSV ecosystem | Written by us | Maven exact (`ComparableVersion`); rest written by us |
| Ecosystem extractors to reuse | some (`auditable-info`, `cargo-lock`) | **osv-scalibr** extractors (lockfiles, dpkg/rpm/apk, Go/Java binaries), `packageurl-go`, Syft as a library | few | few (CycloneDX libraries) |
| Images / registry | written by us on `reqwest` (`oci-client` exists) **(verify)** | **go-containerregistry** | written by us | jib-core |
| SSH | russh / libssh2 | **x/crypto/ssh** + `ssh_config` libraries | SSH.NET | sshj / Apache MINA |
| Several DBs | sqlx + sea-query (good) | database/sql + sqlc or goqu (good); pure-Go SQLite (modernc) | **EF Core** (best of all) | jOOQ / Exposed (very good) |
| Desktop app with the Vue front end | **Tauri** | **Wails** | Photino / WebView2 (Windows first) | JCEF / webview bindings (weak) |
| Static single binary, cross-compiling | good (musl; macOS signing) | **best** (`CGO_ENABLED=0`) | good, but AOT limits reflection and serializers | slow builds, reflection configuration |
| Memory safety on untrusted input | **best** (no nil, strict types, fuzzing tools) | good (GC, bounds checks; nil and races are possible) | good | good |
| Size / memory | **smallest** | small | medium | medium-large |
| Speed of writing, ease of hiring | slowest | **fastest** | fast | medium |
| Matches the existing tools | — | **Syft, Grype, Trivy, osv-scanner, osv-scalibr are all Go** ([ADR-0001](../decisions/0001-language-python-uv-mise.md) already named Go as the fallback) | — | Dependency-Track is Java |

Reading the table:

- **Go is the cheapest and lowest-risk compiled target** for a vulnerability scanner. The hardest parts of this port
  (version semantics, extractors, registry, SSH) already exist as maintained Apache-2.0 libraries that OSV's own scanner
  uses, so the univers risk largely goes away. Wails keeps the Vue app. Cost: a bigger binary than Rust, fewer
  compile-time guarantees, and a weaker desktop story than Tauri.
- **Rust** is the right choice if the product's centre of gravity is the **desktop app plus an agent running on
  untrusted hosts**, where a small footprint and memory safety come first, and if the team can write and review
  Rust for the long term.
- **.NET** is worth a look only if Windows endpoints and enterprise databases are the main market (EF Core, WMI and registry
  APIs, MSI packaging). Otherwise it brings neither ecosystem reuse nor desktop advantages.
- **JVM/GraalVM**: not recommended (native-image friction, weak desktop webview).
- **Mixed (Rust core via PyO3, Python on top)**: the hot paths gain speed but nothing becomes easier to distribute and
  the build gets more complex. Not recommended; the scanner is I/O bound today.

## 8. Recommended path

1. **Now (1–2 weeks): freeze the contracts.** Write JSON Schemas for inventory, snapshot and payloads, record reference
   outputs from the Python code on every fixture, and split the mirror from the inventory in `db.py`. All of this
   is useful whatever the language.
2. **Desktop now (2–3 weeks): Tauri + Python sidecar** ([§4.2](#42-desktop-app-without-porting-first-tauri-shell--python-sidecar)). Users get a signed app; the Tauri work is kept.
3. **Decide Rust or Go with a two-week spike.** Port only `versions` + OSV range evaluation + the `osv-package` matcher in
   both languages and run the differential check against a full OSV mirror. Compare the differences found, the effort
   and how readable the code is. This turns the biggest risk and the language choice into data.
4. **Agent first.** Port `model`, `safeio`, `lang`, `rootfs` and `fs` as the collector-only `secmonk-agent`. The Python
   engine consumes its inventory JSON unchanged, so it can be shipped on its own.
5. **Engine + Store** with SQLite, checked against the Python reference outputs; then the sources; then the CLI and
   server; then the Tauri app without the sidecar.
6. **PostgreSQL**, then **MySQL** if someone asks for it.

At each step the Python and compiled implementations share the database schema and the JSON contracts, so the port can
stop at any step and still leave something that works.

## Open questions

- Who are the target users: a single analyst's laptop (SQLite + desktop) or a team with a central server
  (PostgreSQL + agents)? The answer sets the order of steps 2, 4 and 6.
- Is MySQL a real requirement, or would PostgreSQL be enough? MySQL support costs about 2 of the 5–7 database weeks.
- Who will maintain the code long term, and in which language? This weighs more than any line in [§7](#7-other-compiled-stacks).
- Licensing: osv-scalibr and go-containerregistry are Apache-2.0. Confirm this fits the planned distribution.

If accepted: write an ADR that supersedes [ADR-0001](../decisions/0001-language-python-uv-mise.md) for the chosen
language, an ADR for the storage abstraction (amending [ADR-0004](../decisions/0004-sqlite-schema-v2.md)), an ADR for
the desktop app, and a `plans/port-*.md` checklist per step of [§8](#8-recommended-path).
