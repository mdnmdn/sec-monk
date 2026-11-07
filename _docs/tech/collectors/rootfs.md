---
title: Rootfs collector
type: tech
context: tech
status: implemented
tags: [collector, rootfs, dpkg, apk, rpm, python, npm]
updated: 2026-11-07
sample: real
fixtures: tests/fixtures/collectors/docker/
code: src/secmonk/collectors/rootfs.py
related: [tech/collectors/docker-image.md, tech/collectors/docker-engine.md, features/inventory-docker.md, tech/engine/classification.md]
---

# Rootfs collector

## Summary

Shared engine that turns *any Linux filesystem view* into components: OS, distro packages (dpkg / apk / rpm sqlite) and
language packages (all seven ecosystems through the shared [lang parser registry](dependencies.md): directories via `walk_dir`, image layers via `LangAccumulator`). The `rootfs` collector (`secmonk collect rootfs <dir>`) applies it to a
directory (extracted image, chroot, mounted disk, `/` of a host); `docker-image` and `docker-engine` apply it to a `LayeredTarView`
built from layer tars. Never executes anything and never extracts to disk. Fixtures: real alpine-3.20 / debian-12 (trimmed) / rocky-9 (rpmdb trimmed to 7 packages).

## Where the data lives

`etc/os-release` -> `usr/lib/os-release` -> `etc/alpine-release` -> `etc/redhat-release` -> `etc/debian_version` (OS);
`var/lib/dpkg/status` and `var/lib/dpkg/status.d/*` (distroless); `lib/apk/db/installed`; `var/lib/rpm/rpmdb.sqlite` (+ `-wal`) or
`usr/lib/sysimage/rpm/rpmdb.sqlite`; `**/site-packages|dist-packages/*.dist-info/METADATA`; `**/node_modules/<pkg>/package.json`, `**/node_modules/@scope/<pkg>/package.json` (cap 20k files).

`FsView` (abstract): `resolve()` follows symlinks *inside* the view (absolute targets are re-rooted, `..` past the root is clamped, 40 hops max),
`read / read_text / exists / listdir / iter_lang_files`.
- `DirView(root)`: real directory; prunes `/proc /sys /dev /run` and `.git`, and inside a `node_modules/<pkg>` only descends into nested `node_modules`.
- `LayeredTarView`: `add_layer(path|stream)` bottom layer first (gzip/zstd/plain sniffed). Keeps only whitelisted files + all symlinks in memory; applies `.wh.<name>` and `.wh..wh..opq` against *older* layers only; hard links to kept files are copied.

## Data format

Parsers (pure python, unit-tested): `parse_os_release`, `parse_dpkg_status` (Status must end in `installed`; `Source: name (version)`; `source_version` defaults to `Version`),
`parse_apk_installed` (`P V A o L U m`), `parse_rpmdb_sqlite` (header blob: `il,dl` + 16-byte entries `>IIiI`; tags NAME/VERSION/RELEASE/EPOCH/ARCH/SOURCERPM/VENDOR/LICENSE;
db and `-wal` are copied to a temp dir and opened with `file:...?mode=ro`; `gpg-pubkey` skipped), `parse_python_metadata`, `parse_package_json`.

## Classification

| Item | category | purl | ecosystem |
|---|---|---|---|
| OS | `os` | `pkg:generic/<id>@<VERSION_ID>` | none (matched by product); `meta.osv_ecosystem` holds it |
| deb | `os-package` | `pkg:deb/<id>/<name>@<ver>?arch&distro=<id>-<VERSION_ID>[&upstream=<source>]` | `Debian:12`, `Ubuntu:22.04` |
| apk | `os-package` | `pkg:apk/alpine/<name>@<ver>?arch&distro=alpine-<VERSION_ID>[&upstream=<origin>]` | `Alpine:v3.20` |
| rpm | `os-package` | `pkg:rpm/<id>/<name>@<ver>-<rel>?arch&epoch&distro=<id>-<VERSION_ID>[&upstream=<srpm name>]` (`rhel` -> `redhat`) | `Rocky Linux:9`, `Red Hat:9` ... |
| pypi / npm | `library` | `pkg:pypi/<normalized>@v`, `pkg:npm/%40scope/name@v` | `PyPI`, `npm` |

Ecosystem = `purl.osv_distro_ecosystem(ID, VERSION_ID)`, falling back to the first mappable `ID_LIKE` token.
`meta.source_package` / `source_version` feed `engine/match._match_package`: dpkg Source name/version, apk origin / own version, rpm SOURCERPM name / own version.

**rpm versions always carry an epoch**: `Component.version = "<epoch or 0>:<version>-<release>"` (e.g. `1:3.0.7-24.el9`, `0:9.3-1.1.el9`) because OSV/RHSA/RLSA
fixed versions are written `0:3.23.12-10.el10_2.5`; a uniform epoch prefix keeps rpm vercmp consistent. The purl keeps the spec form (version-release, `epoch` qualifier only when the header has one).

## Implementation notes

Warnings: BerkeleyDB/NDB rpm DB (`var/lib/rpm/Packages`, `Packages.db`) is detected but unsupported; OS without any package DB (distroless/scratch); no os-release; truncated (size/count limits).
Smoke tests on real images: alpine:3.20 = OS + 14 apk; debian:12-slim = OS + 88 deb; python:3.12-slim = OS + 87 deb + pip 25.0.1 (pypi).
Language files are handled by `collectors/lang` (npm, PyPI, Go, Rust, Java, .NET, PHP incl. Go/Rust binaries and jars; see [dependencies.md](dependencies.md)). Not done: gem, dropping language files owned by OS packages, `Packages` BDB parsing, Debian `.list`-based ownership.
Tests: `tests/collectors/test_rootfs.py`.

## Limitations

Whiteout/hardlink logic is spec-based (base images have a single layer); layers whose directories are replaced by regular files are not purged from the view.
