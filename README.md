# sec-monk

Prototype of a **holistic vulnerability scanner**: one local vulnerability mirror, many
inventory collectors, one shared matching engine.
Vision and design notes: [`_docs/`](_docs/INDEX.md) (start with [`_docs/_meta/README.md`](_docs/_meta/README.md)).

## Setup

```bash
mise install          # python 3.13 + uv (see mise.toml)
uv sync               # create .venv and install deps
uv run secmonk --help
```

Without mise: any Python ≥ 3.12 plus `uv` works.

## Quick start

```bash
# 1. Mirror vulnerability data. SQLite lives in the per-user data dir
#    ($XDG_DATA_HOME/secmonk/secmonk.db, ~/.local/share/secmonk/secmonk.db, %LOCALAPPDATA%\secmonk on Windows),
#    never in the current directory (downloads: $SECMONK_CACHE or ~/.cache/secmonk); override with $SECMONK_DB, $SECMONK_HOME or --db. Read-only commands refuse to
#    create an empty database ("no database at X — run `secmonk sync …` first").
uv run secmonk sources                             # cvelist debian-tracker epss euvd kev msrc nvd osv
uv run secmonk sync kev epss
uv run secmonk sync osv -e Alpine -e Debian -e PyPI -e npm
uv run secmonk sync cvelist --since 2024          # CNA data for desktop apps / brew / Windows
uv run secmonk sync debian-tracker                # Debian triage (no-dsa, not-affected, urgency)
uv run secmonk sync nvd --since 2026-10-01 ; uv run secmonk sync euvd ; uv run secmonk sync msrc
uv run secmonk status                              # `sync all` = every source (kev epss osv cvelist nvd euvd msrc debian-tracker)

# 2. Inventory + match (collectors: uv run secmonk collectors)
uv run secmonk scan macos /                        # this Mac: apps, Homebrew, pkgutil, macOS
uv run secmonk scan homebrew                       # Homebrew/Linuxbrew: active kegs, casks, vendored libs
uv run secmonk scan docker-image alpine:3.20       # pull from a registry, no daemon needed
uv run secmonk scan docker-image ./image.tar       # `docker save` tarball / OCI layout
uv run secmonk scan docker-engine <container>      # live container via the Docker/Podman socket
uv run secmonk scan rootfs /path/to/rootfs
uv run secmonk scan fs ./my-service                # language deps: lockfiles, manifests, installed pkgs, binaries
uv run secmonk scan ssh admin@10.0.0.5             # agentless Linux/macOS/Windows host over SSH
uv run secmonk windows-script > secmonk-inventory.ps1   # run on Windows -> inv.json
uv run secmonk scan windows inv.json               # (or -o osquery=results.json; live on Windows: no target)
uv run secmonk procs                               # running processes (macOS): launch origin, version, findings, provenance
uv run secmonk procs --watch 10 --suspicious       # monitor: report new executables / launch items
uv run secmonk ui                                  # local web interface: dashboard, findings, scans, syncs (http://127.0.0.1:8765)

# 3. Explore
uv run secmonk findings --priority P1
uv run secmonk findings --format json            # table | json | csv (also status, inventory, scan)
uv run secmonk scan rootfs ./rootfs --fail-on P2  # CI gate: exit 3 if an open P1/P2 finding exists
uv run secmonk findings <asset-id> --fixable --hide-minor     # fix available, without distro-triaged minor issues
uv run secmonk findings <asset-id> --hide-deferred            # also hide no-dsa / postponed
uv run secmonk inventory assets
uv run secmonk inventory show <asset-id> --category application
uv run secmonk inventory unmatched                 # apps needing an alias-table entry
uv run secmonk vuln show CVE-2024-3094
uv run secmonk vuln search --ecosystem PyPI --package django --version 4.2.1
```

Exit codes: 0 ok, 1 runtime error (unknown asset, no database, collector failure, a failed `sync` source; a *partial* sync exits 0 with a note), 2 usage error (unknown source/collector, bad option), 3 `scan --fail-on` hit. `-v` shows debug logs and tracebacks, `-q` hides informational output (collector warnings are always shown).

Collector options are passed as `-o key=value` (e.g. `-o binaries=false`, `-o all_kegs=true`, `-o sudo=true`, `-o platform=linux/arm64`).
Every command and option: [`_docs/features/README.md`](_docs/features/README.md#cli-at-a-glance); how it fits together:
[`_docs/tech/architecture.md`](_docs/tech/architecture.md); what has been validated on real data and which endpoints are reachable:
[`_docs/references/probes.md`](_docs/references/probes.md).

## Development

```bash
uv run pytest -q                         # tests run offline on fixtures in tests/fixtures/
uv run ruff check src tests scripts
uv run python scripts/docs_index.py      # regenerate _docs/INDEX.md from frontmatter (--check: also validates frontmatter values, referenced paths and markdown links/anchors)
scripts/probe_sources.sh                 # read-only reachability probe of every external endpoint
```

| Path | What |
|---|---|
| `src/secmonk/sources/` | Vulnerability feeds → SQLite |
| `src/secmonk/collectors/` | Targets → inventory (components); `lang/` = shared language-dependency parsers |
| `src/secmonk/engine/` | Classification, versions, matching, scoring |
| `src/secmonk/web/` | Local web interface: stdlib server + JSON API, static Vue app (`static/`: shared CSS / components) |
| `_design/` | Interface design: sample pages, [storybook](_design/storybook/index.html), screenshots ([README](_design/README.md)) |
| `src/secmonk/data/` | `product_aliases.yaml` (curated name → vendor/product), `brew_cpe_seed.csv` (Homebrew identity seed), `windows/secmonk-inventory.ps1` |
| `_docs/` | Documentation, organized by context with YAML frontmatter |
| `tests/fixtures/` | Trimmed real samples where the source was reachable, otherwise synthetic or reconstructed ones (each doc's `sample:` frontmatter says which) |
