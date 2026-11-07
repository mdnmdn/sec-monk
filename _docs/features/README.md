---
title: Feature catalogue
type: feature
context: features
status: implemented
tags: [cli, index, features]
updated: 2026-11-07
code: src/secmonk/cli.py
related: [tech/architecture.md, references/vuln-sources/README.md, references/probes.md, _meta/README.md]
---

# Feature catalogue

One row per feature doc. "Platforms" = where the feature runs / what it inspects. Validation caveats are the honest ones: see the
[probe log](../references/probes.md) for what was exercised on real data.

| Feature | Doc | Status | Platforms | CLI entry point | Validation caveat |
|---|---|---|---|---|---|
| Vulnerability data sync (8 sources) | [vuln-sync.md](vuln-sync.md) | implemented | any (needs network per source, or `--path` import) | `secmonk sync <source>`, `sources`, `status`, `vuln show/search` | osv, cvelist, kev run on real data; epss, nvd, euvd, msrc, debian-tracker only on fixtures (hosts blocked in the dev sandbox) |
| macOS inventory | [inventory-macos.md](inventory-macos.md) | implemented | macOS host or a copied Mac directory tree (analysed on any OS) | `secmonk collect\|scan macos [/]` | fixtures synthetic; not run on a real Mac |
| Homebrew inventory | [inventory-homebrew.md](inventory-homebrew.md) | implemented | macOS and Linuxbrew prefixes (any OS can read a mounted prefix) | `secmonk collect\|scan homebrew [prefix]` | fixtures built from real registry manifests and formulae; real-prefix scan not done |
| Containers and Linux filesystems | [inventory-docker.md](inventory-docker.md) | implemented | any OS for images (registry, tarball, OCI dir, no daemon); Linux/macOS host with a Docker/Podman socket for live containers; any rootfs directory | `secmonk collect\|scan docker-image`, `docker-engine`, `rootfs`; `secmonk containers` | real images alpine, debian-slim, python-slim, registry:2 scanned; engine only against a fake socket |
| Language dependencies | [inventory-dependencies.md](inventory-dependencies.md) | implemented | any (folders, repos; also inside images, containers, SSH hosts, Homebrew) | `secmonk scan fs <dir>` (+ the collectors above) | tool-generated real fixtures; verified end to end on real OSV data |
| Agentless SSH inventory | [inventory-ssh.md](inventory-ssh.md) | implemented | target Linux, macOS, Windows (OpenSSH); analyst machine any | `secmonk collect\|scan ssh user@host[:port]` | fixture trees + in-process sshd only; no real sshd, no real macOS/Windows host |
| Windows inventory | [inventory-windows.md](inventory-windows.md) | implemented | target Windows (script, osquery, live); analyst machine any | `secmonk windows-script`, `secmonk collect\|scan windows [inv.json]` | script never run on real Windows; fixtures synthetic, Microsoft CNA records real |

Scanning and findings commands (`scan`, `match`, `findings`, `inventory ...`) are shared by all inventory features; priorities and
distro triage are described in [matching](../tech/engine/matching.md). There is no separate feature doc for them yet.

## CLI at a glance

Taken from `uv run secmonk --help` and each `<command> --help` (2026-11-07). Root options: `-v/--verbose` (debug logging + tracebacks), `-q/--quiet`. Every data command accepts `--db PATH` (env `SECMONK_DB`; default `<per-user data dir>/secmonk.db`, never the CWD). Read-only commands (status, findings, inventory *, vuln *, match) exit 1 with "no database at X — run `secmonk sync …` first" instead of creating one; sync/collect/scan create it. Exit codes: 0 ok, 1 runtime error (incl. any sync source with status error; partial exits 0 with a note), 2 usage error, 3 `scan --fail-on` hit. `--format table|json|csv` on status, findings, containers, inventory assets/show/unmatched and scan (json/csv go to stdout, notes to stderr; tables are not truncated when piped).

```text
secmonk status                          freshness + table sizes
secmonk sources                         list vulnerability sources (cvelist debian-tracker epss euvd kev msrc nvd osv)
secmonk sync NAMES... | all             fetch into the mirror
    --path PATH         import from local file/dir instead of downloading
    -e, --ecosystem E   OSV ecosystems (repeatable)
    --id ID             specific record ids ('@referenced' for cvelist)
    --since S           only records modified since (ISO date / year)
    --full              ignore the stored delta cursor
    -n, --limit N       max records (debug)
    --api-key K         NVD API key (env NVD_API_KEY)
    (`all` = every registered source, in order kev epss osv cvelist nvd euvd msrc debian-tracker; a source with `in_all = False` is skipped)

secmonk collectors                      list collectors (docker-engine docker-image fs homebrew macos rootfs ssh windows)
secmonk collect COLLECTOR [TARGET]      discover installed software, no matching
    --save/--no-save    store the inventory in the DB (default: save)
    -O, --output PATH   write inventory JSON (--json is a deprecated alias)
    -q, --quiet         don't print the component table (warnings are always shown)
    -o, --opt KEY=VAL   collector option (repeatable), e.g. -o use_brew_cli=true -o platform=linux/arm64
secmonk scan COLLECTOR [TARGET]         collect + save + match, then print findings
    --min-confidence F  drop name-based matches below F (default 0.5)
    --fail-on P1..P4    exit 3 if any open finding is at or above this priority
    --priority/--fixable/--hide-minor/--hide-deferred/-n   same filters as `findings`
    --save/--no-save    --no-save matches in a temporary overlay and writes nothing (needs an existing mirror)
    -f, --format table|json|csv   -q, --quiet
    -o, --opt KEY=VAL
secmonk match ASSET                     (re)match a stored asset against the current mirror
    --min-confidence F  (default 0.5)
secmonk windows-script [--compact]      print the read-only PowerShell inventory script (`secmonk windows-script > secmonk-inventory.ps1`)
secmonk containers [--socket PATH] [--all] [-f FMT]   list containers of the local Docker/Podman engine (table)

secmonk findings [ASSET]                list findings ordered by priority
    --priority P1..P4
    --all               include fixed/suppressed
    --fixable           only findings with a known fixed version
    --hide-minor        hide distro-triaged minor issues (unimportant, ignored, end-of-life)
    --hide-deferred     also hide no-dsa / postponed
    -n, --limit N       (default 200)
    -f, --format table|json|csv

secmonk vuln show VULN_ID [--raw]       everything known about an id across sources
secmonk vuln search                     advisories for a package or product
    --package P  --ecosystem E  --product P  --version V  -n/--limit N (default 50)
secmonk inventory assets [-f FMT]       list assets
secmonk inventory show ASSET [--category C] [-f FMT]   components of the latest scan
secmonk inventory unmatched             apps whose identity is only a normalized name (alias-table candidates)
```

### Collector options (`-o key=value`)

Values stay strings, except `true/false/yes/no` for the boolean keys (binaries, sudo, all_kegs, use_brew_cli, include_system, insecure_host_key, xdev, no_cache, lang, verbose) and comma lists for `exclude`, `home`, `ecosystems`. A repeated key becomes a list (`-o ssh_option=A=1 -o ssh_option=B=2`).

| Collector | Target | Options (from the feature docs and code) |
|---|---|---|
| `macos` | `/` or a Mac root dir | `use_brew_cli`, `include_system`, `home`, `hostname`, `system_profiler` |
| `homebrew` | prefix or root (default: search known prefixes) | `all_kegs`, `hostname` |
| `rootfs` | directory | none |
| `docker-image` | registry ref, `docker save` tar, OCI dir | `platform` (default `linux/amd64`), `username`, `password` (or `SECMONK_REGISTRY_PASSWORD`), `no_cache`, `cache_dir`, `max_layer_bytes` |
| `docker-engine` | container name/id or `image:<ref>` | `socket` (or `$DOCKER_HOST`) |
| `fs` | folder or repo (default `.`) | `binaries` (default true), `max_files` (default 200000), `asset_id` |
| `ssh` | `user@host[:port]` or `ssh://` | `transport` (auto/openssh/paramiko), `identity`, `ssh_option`, `insecure_host_key`, `sudo`, `binaries`, `lang`, `root`, `exclude`, `xdev`, `max_files`, `max_mb`, `max_binary_mb`, `os` (`macos`/`windows`), `verbose`, `connect_timeout`, `timeout`; `SECMONK_SSH_PASSWORD` |
| `windows` | `inv.json` (script output), none = live on Windows | `osquery=<file>`, `hostname`, `include_system` |

## Adding a feature doc

Copy [`_meta/templates/feature.md`](../_meta/templates/feature.md), set `status` truthfully (`draft` until tests exist, `implemented` once
code and tests exist) and add a row above.
