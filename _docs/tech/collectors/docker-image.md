---
title: Docker image collector
type: tech
context: tech
status: implemented
tags: [collector, docker, oci, registry, dpkg, apk, rpm, sbom]
updated: 2026-11-07
sample: mixed
fixtures: tests/fixtures/collectors/docker/
code: src/secmonk/collectors/docker_image.py (+ collectors/rootfs.py)
related: [tech/collectors/docker-engine.md, features/inventory-docker.md, tech/engine/classification.md]
---

# Docker image collector

## Summary

Builds an inventory from a container image **without a Docker daemon and without executing anything**: obtain the image
(registry pull via HTTP, `docker save` tarball, OCI layout dir, or a rootfs from the engine collector), apply layers in order
(honouring whiteouts) - or, cheaper, read only the whitelisted files from each layer - identify the OS, parse the package DB
(dpkg / apk / rpm) and language package metadata.

**Fixtures (2026-11-07)**: **real** = `alpine-3.20/rootfs/` (complete apk DB, os-release), `debian-12/rootfs/` (trimmed dpkg status, 17 stanzas, os-release),
`rocky-9/rootfs/` (real rpmdb.sqlite **trimmed to 7 of 118 packages**, os-release), `registry/alpine-3.20.{index,manifest,config}.json` (verbatim registry responses).
**Synthetic (assembled from real files)** = `alpine-mini.tar` (docker save style; config/manifest hand-generated, files real, layer gzip'd - real Docker emits uncompressed layers).
Images pulled: `alpine:3.20` (3.20.10), `debian:12-slim` (bookworm), `rockylinux:9-minimal` (Rocky 9.3; the mirror's tag was stale, created 2023-11-28).
Language parsing (npm, PyPI, Go, Rust, Java, .NET, PHP) now lives in [dependencies.md](dependencies.md) with its own real fixtures (`tests/fixtures/lang/`); real image smoke tests are listed in the implementation notes.

## Where the data lives

### A. Registry v2 API (verified from the sandbox)

Flow (all HTTPS GET; Python stdlib `urllib` was enough):

1. `GET https://registry-1.docker.io/v2/` -> `401` with `WWW-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`. Always parse this header (realm/service/scope) rather than hard-coding.
2. Token (anonymous, no credentials): `GET https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull` -> `{"token": "<JWT>", "access_token": ..., "expires_in": 300}`. Official images live under `library/` (`alpine` -> `library/alpine`). Send `Authorization: Bearer <token>`. Token is valid ~5 min and scoped to the repo.
3. Manifest: `GET /v2/<repo>/manifests/<tag|digest>` with
   `Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json`
   (**must list all four**; otherwise the registry may down-convert or return 404/406). Response `Content-Type` tells which; header `Docker-Content-Digest` = manifest digest.
4. If it is an **index / manifest list** (`manifests[]` each with `platform.{os,architecture,variant}`): choose `linux/amd64` (or host arch; arm64 variant `v8` may be present or absent; `arm/v7`, `arm/v6` have variants). Fetch `GET /v2/<repo>/manifests/<digest>` for that entry (same Accept). Fixture: `registry/alpine-3.20.index.json` (16 entries).
   **Gotcha**: since buildkit attestations, indexes also contain entries with `platform: {os:"unknown",architecture:"unknown"}` and annotation `vnd.docker.reference.type: attestation-manifest` (these are SBOM/provenance attestations; skip - or later use the SBOM in-toto attestation!). Select by `os`+`architecture` equality only.
5. Image manifest (fixture `registry/alpine-3.20.manifest.json`, mediaType `application/vnd.oci.image.manifest.v1+json`; Docker schema2 variant is `application/vnd.docker.distribution.manifest.v2+json` with `layers[].mediaType = application/vnd.docker.image.rootfs.diff.tar.gzip`): `config.digest`, `layers[].{mediaType,digest,size}`, annotations (`org.opencontainers.image.version`, `.revision`, `.base.name`).
6. Config blob: `GET /v2/<repo>/blobs/<config digest>` (fixture `registry/alpine-3.20.config.json`): `architecture`, `os`, `config.{Env,Cmd,Entrypoint,User,WorkingDir,Labels,ExposedPorts}`, `created`, `history[]` (`created_by` Dockerfile commands, `empty_layer`), `rootfs.diff_ids[]` (sha256 of *uncompressed* layer tar; the manifest digests are of the compressed blob). `history` entries with `empty_layer:true` do not map to layers.
7. Layer blobs: `GET /v2/<repo>/blobs/<digest>` -> **307 redirect to a CDN** (Docker Hub: Cloudflare/`production.cloudflare.docker.com`); **drop the `Authorization` header when following** (urllib does this automatically across hosts; `requests` too). Verify `sha256(body) == digest` (done: all layers matched). Layer media types: `...layer.v1.tar+gzip` / `...rootfs.diff.tar.gzip`, `...layer.v1.tar` (uncompressed), `...layer.v1.tar+zstd`, and legacy `...foreign.diff.tar.gzip` (Windows, has `urls`; skip). **Detect compression by magic bytes** (gzip `1f 8b`, zstd `28 b5 2f fd`, xz `fd 37 7a 58 5a 00` - rocky's source used xz internally but the OCI layer is gzip), not only by mediaType. zstd needs a 3rd-party lib (`zstandard`; Python 3.14 has `compression.zstd`).
8. Reference parsing: `alpine` -> `docker.io/library/alpine:latest`; `ghcr.io/owner/img:tag`; `repo@sha256:...` digest pins. Default registry host for Docker Hub is `registry-1.docker.io`.

**Observed in this sandbox (2026-11-07)**

| Registry | Result |
|---|---|
| `registry-1.docker.io` | 401 -> anonymous token works. Manifest GETs started returning **`429 TOOMANYREQUESTS`** ("unauthenticated pull rate limit": 100 pulls/6h per IP, shared egress IP here) after 3 images; implement retry with backoff and surface the message. `HEAD` requests do not count toward the limit - use `HEAD` to resolve digests when possible. |
| `mirror.gcr.io` | **Anonymous, no token needed**; serves Docker Hub official images (`mirror.gcr.io/library/rockylinux:9-minimal`), blobs 302 to `artifact-registry` URLs - worked, and was used to fetch rocky. Good fallback for official images. |
| `ghcr.io` | `/v2/` 401 with `Bearer realm="https://ghcr.io/token",service="ghcr.io"`; anonymous `GET https://ghcr.io/token?scope=repository:anchore/syft:pull` returned a token (public repos). Blob pull not exercised. |
| `public.ecr.aws` | Token `GET https://public.ecr.aws/token/?scope=repository:docker/library/rockylinux:pull` OK and manifests OK, but **blob redirect goes to `*.cloudfront.net` which the sandbox proxy blocks (403)** (environment-specific). |
| `quay.io`, `registry.access.redhat.com`, `docker.io` | blocked by sandbox proxy (CONNECT 403). |

Private registries: Basic credentials from `~/.docker/config.json` (`auths.<host>.auth` base64 `user:pass`; `credsStore`/`credHelpers` need helper binaries - out of scope) sent to the token realm as `Authorization: Basic`. Prototype: anonymous + optional `--username/--password-env`.

### B. `docker save` tarball / OCI layout (fixture `alpine-mini.tar`)

Docker < 25 (classic): `manifest.json` (`[{"Config":"<id>.json","RepoTags":["alpine:3.20"],"Layers":["<id>/layer.tar"]}]`), `repositories`, `<id>/{json,VERSION,layer.tar}`, `<config sha>.json`.
Docker >= 25 (containerd image store / newer save): OCI-layout style **plus** legacy manifest: `oci-layout` (`{"imageLayoutVersion":"1.0.0"}`), `index.json`, `manifest.json`, `repositories`, `blobs/sha256/<hex>` (manifest, config, uncompressed layer tars). `manifest.json` `Config`/`Layers` point at `blobs/sha256/...`.
OCI image layout directory (`skopeo copy docker://x oci:dir`, `crane pull --format oci`): `oci-layout`, `index.json` (-> manifests with annotations `org.opencontainers.image.ref.name`; may point to an *index* needing a second hop), `blobs/<alg>/<hex>`.
Algorithm: if `manifest.json` exists use it (single or list - multiple images possible, one entry per tag); else walk `index.json` -> (index ->) manifest -> layers. **Layer order = manifest order, bottom first.** Read members lazily with `tarfile` (not `extractall`).
The fixture follows this layout with one gzip'd layer containing only `etc/os-release` and `lib/apk/db/installed` (first 5 packages).

### C. Applying layers & whiteouts

For each layer in order, for each tar member: path normalization (strip leading `./` and `/`; reject `..`); basename starting with `.wh..wh..opq` = **opaque dir**: remove all entries previously seen under that dir (from lower layers), keep those from this layer; basename `.wh.<name>` = **delete** `<dir>/<name>` (and everything below). Whiteout members themselves are not files. Hard links/symlinks: record only; resolve targets within the layer view (important: `/etc/os-release` is often a **symlink** to `../usr/lib/os-release`, true for debian and rocky - see fixtures where `etc/os-release` is a symlink). Optimization: instead of a full rootfs, keep a `dict[path] -> (layer_idx, member)` for a **whitelist of interesting paths** and process whiteouts against it (a layer deleting `/var/lib/dpkg/status` or a whole dir must remove the entry). Only the whitelisted file contents are read into memory (status files <= a few MB; rpmdb.sqlite ~5 MB).
Checked: the alpine and debian-slim base layers contain no whiteouts (single layer), so whiteout logic is **spec-based, not fixture-verified**.

## Data format

### OS identification

Order: `etc/os-release` (follow symlink) -> `usr/lib/os-release` -> `etc/alpine-release` (`3.20.10`), `etc/debian_version` (`12.x`), `etc/redhat-release`/`etc/rocky-release` (`Rocky Linux release 9.3 (Blue Onyx)`), `etc/lsb-release`. Shell-style `KEY=value` with optional quotes. Fields: `ID`, `ID_LIKE`, `VERSION_ID`, `VERSION_CODENAME`, `PRETTY_NAME`, `CPE_NAME`.
Real values: alpine `ID=alpine VERSION_ID=3.20.10` (**patch version: for the distro qualifier / OSV ecosystem use `Alpine:v3.20` = major.minor**); debian `ID=debian VERSION_ID="12" VERSION_CODENAME=bookworm` (`/etc/debian_version` holds the point release, e.g. `12.15` in the fixture); rocky `ID=rocky VERSION_ID="9.3"`, `CPE_NAME=cpe:/o:rocky:rocky:9::baseos`. Ubuntu: `ID=ubuntu VERSION_ID="22.04"`. Distroless debian: os-release present, no `/etc/debian_version` guarantee. `scratch`/`FROM scratch` apps: no OS -> only language packages/binaries.
The OS itself becomes a component (`category=os`, e.g. `cpe:2.3:o:debian:debian_linux:12`).

### dpkg - `var/lib/dpkg/status` (fixture `debian-12/rootfs/var/lib/dpkg/status`, real, trimmed)

RFC822-style stanzas separated by blank lines; continuation lines start with space/tab (Description, Conffiles). Fields used: `Package`, `Status` (`install ok installed` - **skip anything not ending in `installed`**, e.g. `deinstall ok config-files`), `Version` (full, incl. epoch `1:`, revision, `+bN` binNMU, `~deb12uN` security), `Source`, `Architecture` (`amd64`, `all`, `arm64`), `Maintainer`, `Provides`, `Depends` (ignored), `Multi-Arch`.
**`Source:` forms** (all seen in the fixture): absent (source == package name, e.g. `coreutils`, `tar`); `Source: glibc` (name only, binary package `libc6`; source version == binary `Version`); **`Source: bash (5.2.15-2)`** (name **and source version when it differs from binary version**, here binNMU `5.2.15-2+b13`); `Source: shadow` for `login` with epoch `1:4.13+dfsg1-1+deb12u2`. Parse with `^(\S+)(?: \((\S+)\))?$`. **CVE matching must use the source package name** (Debian security tracker is keyed by source: `libssl3` -> source `openssl`) and the source version (binary `+bN` suffix stripped if no explicit version).
Distroless (and `gcr.io/distroless/*`): no single `status` file; one file per package in `var/lib/dpkg/status.d/<pkg>` (older: `<pkg>.md5sums` alongside) - read all files in that dir as stanzas.
`debian-12-slim` has `libssl3`? **No** - this slim image ships without openssl (not in trimmed fixture because it is not in the real DB; `libgnutls30`, `libc6`, `zlib1g`, `tzdata`, `apt` are). Full status = 88 packages.
PURL: `pkg:deb/debian/libc6@2.36-9%2Bdeb12u14?arch=amd64&distro=debian-12&upstream=glibc` (vendor namespace from os-release `ID`; Ubuntu: `pkg:deb/ubuntu/...?distro=ubuntu-22.04`; `+` percent-encoded; `upstream=` carries source name (and `@version` if distinct - Syft style `upstream=bash@5.2.15-2`)). Version compare: dpkg algorithm (epoch, `~` sorts before everything).

### apk - `lib/apk/db/installed` (fixture `alpine-3.20/rootfs/lib/apk/db/installed`, real & complete, 14 packages)

Blocks separated by blank line; each line `<letter>:<value>`. Keys: `P` name, `V` version (`3.6.5-r0`), `A` arch (`x86_64`), `S` size, `I` installed size, `T` description, `U` url, `L` license (SPDX), `o` **origin** (source package: e.g. `musl` for `musl-utils`, **match CVEs on origin**), `m` maintainer, `t` build timestamp, `c` commit, `D` depends, `p` provides, `C` checksum, repeated `F:` dir / `R:` file / `Z:` file checksum / `a:` perms lines (file lists - skip). Parse until blank line. Also `etc/apk/world` (explicitly installed) and `etc/apk/repositories` (release branch hint `v3.20`).
PURL: `pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=alpine-3.20.10&upstream=musl` (`distro` pattern per purl-spec: `alpine-<VERSION_ID>`; the OSV ecosystem string is `Alpine:v3.20`). Version compare: apk (`1.2.5-r0`, letters suffix, `_rc`, `_p`).

### rpm - `var/lib/rpm/rpmdb.sqlite` (fixture `rocky-9/rootfs/var/lib/rpm/rpmdb.sqlite`, real rows, trimmed to 7 packages, 127 KB)

Locations: RHEL 9+/Fedora 33+/Rocky/Alma 9/Amazon Linux 2023/openEuler: `/var/lib/rpm/rpmdb.sqlite` (on Fedora 36+/RHEL 9 hosts the real dir is `/usr/lib/sysimage/rpm/` with `/var/lib/rpm` a symlink to it: **check both**; the minimal Rocky image has it directly in `/var/lib/rpm/`). RHEL 7/8, CentOS 7/8, Amazon Linux 2, older Fedora: BerkeleyDB `/var/lib/rpm/Packages` (hash DB; needs a BDB hash parser - not feasible in stdlib quickly; defer). SUSE/openSUSE: `Packages.db` (NDB format, `/usr/lib/sysimage/rpm/`; defer). Fallback for all: **run `rpm --root`** is rejected (executes tooling).
rpmdb.sqlite schema (real): `Packages(hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)` plus index tables (`Name`, `Basenames`, `Providename`, ... `key,hnum,idx`) that we can ignore. Real full DB in rockylinux:9-minimal: 118 rows, 4.9 MB (+`-shm`, empty `-wal`: open with `mode=ro` URI; if a non-empty `-wal` is present copy db+wal to a temp dir so SQLite can replay - `immutable=1` would ignore the WAL).

**Header blob format - confirmed by a working prototype** (scratchpad `scripts/rpmhdr.py`, parsed all 118 rows):
- No magic bytes (unlike `.rpm` files' `8e ad e8 01`): blob = `il` (uint32 BE, number of index entries) + `dl` (uint32 BE, data store length) + `il` x 16-byte entries + `dl` bytes data store.
- Entry = `tag` uint32, `type` uint32, `offset` int32 (into the data store), `count` uint32; all big-endian (`>IIiI`). First blob example: `0000004E 00005C28` -> 78 entries, 23592 bytes of data.
- Types: 0 NULL, 1 CHAR, 2 INT8, 3 INT16, 4 INT32, 5 INT64, 6 STRING (NUL-terminated at offset), 7 BIN (`count` bytes), 8 STRING_ARRAY (`count` NUL-terminated strings), 9 I18N_STRING (read first string like STRING).
- Tags needed: NAME 1000 (string), VERSION 1001, RELEASE 1002, EPOCH 1003 (INT32 array; **absent when no epoch**: in fixture only `openssl-libs` and `gdbm-libs` have `[1]`), SUMMARY 1004, VENDOR 1011, LICENSE 1014, ARCH 1022, SOURCERPM 1044 (`openssl-3.0.7-24.el9.src.rpm` -> source name `openssl` by stripping `-<version>-<release>.src.rpm`, or `(.+)-[^-]+-[^-]+\.src\.rpm`), URL 1020. Region/immutable tags (62/63, 100) and signature entries are present; ignore. Alignment is handled by offsets (INT32 data are aligned inside the store).
- Therefore **a pure-Python parser is feasible** (~25 lines, stdlib `sqlite3`+`struct`). Per-row output e.g. `openssl-libs 3.0.7-24.el9 epoch 1 x86_64 vendor "Rocky Enterprise Software Foundation" src openssl-3.0.7-24.el9.src.rpm`.
- `gpg-pubkey` pseudo-packages (NAME `gpg-pubkey`, ARCH absent) appear in many images - skip. Not present in this image.
PURL: `pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?arch=x86_64&epoch=1&distro=rocky-9.3&upstream=openssl-3.0.7-24.el9.src.rpm` (namespace = os-release `ID`; for RHEL `redhat`; `epoch` as qualifier, not in version; Fedora/Amazon: `fedora`/`amzn`). RHEL/Rocky/Alma advisories (OSV ecosystems "Rocky Linux", "AlmaLinux", "Red Hat") match on source name + NEVRA with **rpm vercmp** (epoch, then `~`, `^` rules).

### Language packages (in-image)

| Ecosystem | File | Fields | Prototype? |
|---|---|---|---|
| Python | `**/site-packages/*.dist-info/METADATA` (or `*.egg-info/PKG-INFO`, `*.egg-info` file) in `usr/lib/python3*/site-packages`, `usr/local/lib/python3*/site-packages`, `dist-packages` (Debian) | `Name:`, `Version:`, `License`, `Home-page`; PURL `pkg:pypi/<normalized-name>@<ver>` (lowercase, `_`/`.` -> `-`) | **yes** |
| Node | `**/node_modules/**/package.json` (+ `usr/lib/node_modules`, `usr/local/lib/node_modules`) | `name`, `version`, `license`; skip files with no version / `private:true` app roots; PURL `pkg:npm/%40scope/name@ver` | **yes** |
| Java | `*.jar`/`war`: `META-INF/MANIFEST.MF` (`Implementation-Title/Version`), `META-INF/maven/<g>/<a>/pom.properties` (`groupId`, `artifactId`, `version`) -> `pkg:maven/g/a@v`; nested jars (fat jars) need recursion | later |
| Go | binaries with buildinfo (`runtime/debug.BuildInfo`, magic `\xff Go buildinf:` + module list) | later |
| Also later | Ruby gemspecs, Rust `cargo-auditable`, .NET deps.json, PHP composer.lock, language runtime itself (python/node/java from binary names, versions) |

To avoid double counting, drop python/node components whose files are owned by an OS package when the DB provides file lists (dpkg `.list`, apk `F:/R:`; rpm `Basenames`) - future.

## Classification

| Item | category | PURL | CPE hint / match key |
|---|---|---|---|
| OS | `os` | `pkg:generic/debian@12`/`alpine@3.20.10` | `cpe:2.3:o:debian:debian_linux:12`, `...:alpine:alpine_linux:3.20.10` |
| deb pkg | `package` | `pkg:deb/<id>/<name>@<ver>?arch=&distro=&upstream=` | OSV `Debian:12` by **source** name |
| apk pkg | `package` | `pkg:apk/alpine/<name>@<ver>?arch=&distro=` | OSV `Alpine:v3.20` by **origin** |
| rpm pkg | `package` | `pkg:rpm/<id>/<name>@<ver-rel>?arch=&epoch=&distro=` | OSV `Rocky Linux:9` / `Red Hat`; by source rpm name |
| pypi/npm | `library` | `pkg:pypi/..`, `pkg:npm/..` | OSV PyPI/npm |
Layer provenance: record which layer (index + `created_by` from `history`) introduced/changed each DB (nice for "fix in base image" advice).
Image-level asset properties: reference, digest (manifest), platform, `created`, `Labels`, `Env`, `User` (root = prioritization input), `ExposedPorts`.

## Limitations / gotchas

- Docker Hub anonymous rate limit (429); mirror.gcr.io workaround; need retries and `--offline` tarball path for tests.
- Attestation manifests inside indexes (`unknown/unknown`); multi-arch selection.
- `etc/os-release` symlink inside the layer; symlinks must be resolved *within the image view*, never on the host. Never extract to disk blindly: path traversal, absolute symlinks, device files.
- DB can be in a different layer than the OS files; later layers may delete/replace it (whiteouts); take the final view.
- Distro versions: Alpine patch vs branch; Debian `VERSION_ID` absent on `sid`/`testing`; RHEL-like `9.3` vs `9`.
- Files `*-shm`/`-wal` for rpmdb; BDB/NDB rpm DBs unsupported (report "rpm DB format unsupported" rather than silently empty!).
- Binaries installed outside package managers (curl'd, `/usr/local/bin`, Go/Rust static binaries) are invisible.
- Large layers: stream; set per-layer and total size caps; prefer ranged/lazy reading of the tar index (tar+gzip has no index, so a full layer pass is needed).

## Implementation notes

Implemented in `src/secmonk/collectors/docker_image.py`; OS/package/language parsing lives in [rootfs.md](rootfs.md) (`LayeredTarView`).
Tests: `tests/collectors/test_docker.py` (tarball, OCI dir, whiteouts, mocked registry), `tests/test_e2e_alpine.py`.

- Targets: file -> `docker save`/OCI tar (`manifest.json` preferred, else `index.json` walk incl. nested indexes); directory with `index.json` -> OCI layout; anything else -> registry reference. A directory without `index.json`/`manifest.json` is rejected with a hint to use `rootfs`.
- Options (`collect(target, **opts)`): `platform` (default `linux/amd64`), `no_cache`, `cache_dir`, `username`/`password` (or `SECMONK_REGISTRY_PASSWORD`; else inline `auths` of `~/.docker/config.json`), `max_layer_bytes` (4 GiB), `client` (inject an `httpx.Client`, used by tests), `sleep`.
- Registry client: anonymous Bearer token from the `WWW-Authenticate` challenge (realm/service/scope), Basic fallback, retries with backoff on 429/5xx (honours `Retry-After`, max 4), then a `RegistryError` that suggests `mirror.gcr.io`. Redirects are followed **manually** and `Authorization` is dropped on any cross-host hop (httpx >= 0.20 also strips it - `_client.py` `_redirect_headers` - but we do not depend on it). Blob digests are verified (sha256) before the blob enters the cache.
- Layer blobs stream to `.cache/secmonk/blobs/sha256/<hex>` (written as `.part`, renamed after verification); `no_cache` uses a temp dir deleted after each layer. Layers are gzip / plain / zstd (sniffed by magic; zstd needs `compression.zstd` (py3.14) or `zstandard`, else the layer is skipped with a warning). Foreign layers are skipped with a warning.
- Asset: `id = image:<registry>/<repo>@<manifest digest>` (registry pull; `docker.io/library/alpine`), for archives the manifest digest from `index.json` when exactly one manifest, else the sha256 of the canonical config JSON (image id); `type=container-image`; `platform` from the config (`linux/arm64/v8`); meta `ref, digest, config_digest, layers, labels, created, user, exposed_ports, env_names, entrypoint, cmd`. **Only env variable *names* are stored** (values often contain secrets).
- Smoke test 2026-11-07 (real registries): `alpine:3.20` -> 15 components (OS + 14 apk); `mirror.gcr.io/library/debian:12-slim` -> 89 (OS + 88 dpkg); `mirror.gcr.io/library/python:3.12-slim` -> OS + 87 dpkg + `pip 25.0.1` (pypi).
- Not done: layer provenance (`history` -> component), SBOM attestations, credential helpers, `--platform` autodetect from host arch, dedupe of python/npm files owned by OS packages.
