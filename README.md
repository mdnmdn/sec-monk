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
# 1. Mirror vulnerability data (SQLite at ./secmonk.db, or $SECMONK_DB / --db)
uv run secmonk sync kev epss
uv run secmonk sync osv -e Alpine -e Debian -e PyPI -e npm
uv run secmonk sync cvelist --since 2024          # CNA data for desktop apps / brew
uv run secmonk status

# 2. Inventory + match
uv run secmonk scan macos /                        # this Mac: apps, Homebrew, pkgutil, macOS
uv run secmonk scan docker-image alpine:3.20       # pull from a registry, no daemon needed
uv run secmonk scan docker-image ./image.tar       # `docker save` tarball / OCI layout
uv run secmonk scan docker-engine <container>      # live container via the Docker socket
uv run secmonk scan rootfs /path/to/rootfs

# 3. Explore
uv run secmonk findings --priority P1
uv run secmonk inventory assets
uv run secmonk inventory show <asset-id> --category application
uv run secmonk inventory unmatched                 # apps needing an alias-table entry
uv run secmonk vuln show CVE-2024-3094
```

## Development

```bash
uv run pytest -q                         # tests run offline on fixtures in tests/fixtures/
uv run ruff check src tests
uv run python scripts/docs_index.py      # regenerate _docs/INDEX.md from frontmatter
```

| Path | What |
|---|---|
| `src/secmonk/sources/` | Vulnerability feeds → SQLite |
| `src/secmonk/collectors/` | Targets → inventory (components) |
| `src/secmonk/engine/` | Classification, versions, matching, scoring |
| `src/secmonk/data/product_aliases.yaml` | Curated name → vendor/product table |
| `_docs/` | Documentation, organized by context with YAML frontmatter |
| `tests/fixtures/` | Trimmed real samples of every source and collector input |
