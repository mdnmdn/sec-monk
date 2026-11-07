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

Taken from `uv run secmonk --help` and each `<command> --help` (2026-11-07). Every command also accepts `--db PATH` (env `SECMONK_DB`, default `./secmonk.db`).

```text
secmonk status                          freshness + table sizes
secmonk sources                         list vulnerability sources (cvelist debian-tracker epss euvd kev msrc nvd osv)
secmonk sync NAMES... | all             fetch into the mirror
    --path PATH         import from local file/dir instead of downloading
    -e, --ecosystem E   OSV ecosystems (repeatable)
    --id ID             specific record ids ('@referenced' for cvelist)
    --since S           only records modified since (ISO date / year)
    --full              ignore the stored delta cursor
    --limit N           max records (debug)
    --api-key K         NVD API key (env NVD_API_KEY)
    (`all` = kev epss osv cvelist nvd euvd; msrc and debian-tracker must be named)

secmonk collectors                      list collectors (docker-engine docker-image fs homebrew macos rootfs ssh windows)
secmonk collect COLLECTOR [TARGET]      discover installed software, no matching
    --save/--no-save    store the inventory in the DB (default: save)
    --json PATH         write inventory JSON
    --quiet
    -o, --opt KEY=VAL   collector option (repeatable), e.g. -o use_brew_cli=true -o platform=linux/arm64
secmonk scan COLLECTOR [TARGET]         collect + save + match, then print findings
    --min-confidence F  drop name-based matches below F (default 0.5)
    -o, --opt KEY=VAL
secmonk match ASSET                     (re)match a stored asset against the current mirror
    --min-confidence F  (default 0.5)
secmonk windows-script [--compact]      print the read-only PowerShell inventory script
secmonk containers [--socket PATH]      list containers of the local Docker/Podman engine

secmonk findings [ASSET]                list findings ordered by priority
    --priority P1..P4
    --all               include fixed/suppressed
    --fixable           only findings with a known fixed version
    --hide-minor        hide distro-triaged minor issues (unimportant, ignored, end-of-life)
    --hide-deferred     also hide no-dsa / postponed
    --limit N           (default 200)

secmonk vuln show VULN_ID [--raw]       everything known about an id across sources
secmonk vuln search                     advisories for a package or product
    --package P  --ecosystem E  --product P  --version V  --limit N (default 50)
secmonk inventory assets                list assets
secmonk inventory show ASSET [--category C]   components of the latest scan
secmonk inventory unmatched             apps whose identity is only a normalized name (alias-table candidates)
```

### Collector options (`-o key=value`)

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
