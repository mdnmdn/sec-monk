---
title: Proposal — probe / engine / ui architecture on a compiled stack (Rust), standalone or distributed
summary: Probe/engine/ui split, standalone or across hosts (topologies, protocol, transports, security); Rust host with Python modules over stdio (strangler); databases, Tauri; versus Go, .NET, JVM; effort, path.
read_when: you decide whether or how to split sec-monk into probe, engine and ui, run it across hosts, choose a wire protocol or transport, decide what stays in Python, port it to a compiled language, add database backends or build a desktop app
type: proposal
context: inbox
status: proposed
tags: [architecture, language, data-model, web-ui, desktop, effort, distributed, probe, transport, security, python]
updated: 2026-11-11
verified: 2026-11-11
related: [decisions/0001-language-python-uv-mise.md, decisions/0004-sqlite-schema-v2.md, decisions/0005-prototype-scope-nov-2026.md, decisions/0006-per-user-state-locations.md, decisions/0007-process-monitor.md, decisions/0009-web-ui-vendored-libraries.md, tech/architecture.md, tech/data-model.md, tech/web-ui.md, tech/discover.md, tech/collectors/ssh.md, tech/collectors/process.md, plans/README.md]
---

# Proposal — probe / engine / ui architecture on a compiled stack (Rust), standalone or distributed

This proposal describes a target architecture of **three components** and estimates the effort to build it in
**Rust**:

- **probe**: collects from a host. It runs on the target, or next to an engine and reaches the target over SSH.
- **engine**: vulnerability mirror, store, matching, scoring, jobs. It can serve a web interface itself.
- **ui**: a desktop frontend (later also a web one), the same Vue app as today.

The same three run in **one process** (standalone desktop app, offline, today's single-user use) or **across many
hosts** (distributed: one frontend connected to several engines on different networks, each engine driving several
probes, local or remote). The goals:

1. **Three components, two contracts.** Probe↔engine and engine↔ui are defined once and work over any transport:
   in-process, SSH, HTTPS/gRPC, RDP channels, Tailscale-like overlays.
2. **Separation the compiler enforces**, and binaries shipped on their own (probe only, engine server, desktop app).
3. **Several databases**: SQLite (default, local), PostgreSQL and MySQL/MariaDB.
4. **A desktop app** built with Tauri, or an alternative.
5. **Python as the fast lane.** New features and spikes are built in Python first and moved to Rust behind the same
   interface: Rust modules in-process, Python modules as child processes over stdio ([§9](#9-mixed-rustpython-python-as-the-fast-lane)).

It also compares **other compiled stacks**: Go, C#/.NET and Kotlin/JVM. Read the [summary](#summary) first; the other
sections give the reasoning behind each number.

Inputs are measured from the repository at commit `d03f38f` (2026-11-11). Crate and library names were picked by
knowledge, not by building a prototype. Items marked **(verify)** need a short spike before anyone commits to them.

## Summary

| Question | Answer |
|---|---|
| Target architecture | **probe / engine / ui**, one binary each plus a desktop app that holds all three in one process. Two contracts (probe↔engine, engine↔ui), both reusing today's JSON payloads ([§2](#2-target-architecture-probe-engine-ui), [§4](#4-contracts-and-protocol)). |
| Size of what we port | 20.3k lines of Python in 64 modules, 739 test functions (966 test cases, 12.3k lines), about 6–7 MB of fixtures. The Vue front end (3.3k lines) and the fixtures can be **reused as they are**. |
| Rust port, same features, SQLite only | **About 49 person-weeks** for one senior Rust developer working the usual way. **About 9–13 calendar weeks** when coding agents do most of the work and one person reviews (that is how this repository was built). |
| Add PostgreSQL and MySQL | **+5–7 person-weeks**, mainly to put a storage layer between the engine and SQL, write migrations for each database and test on all three. |
| Tauri desktop app (all three in one process) | **+3–5 person-weeks**, including code signing, notarization and the updater. The current Vue app runs inside Tauri with few changes. |
| Distributed mode, core | **+19 person-weeks**: wire protocol, probe binary, engine service (probe registry, routed and cancellable jobs), SSH-stdio and TLS transports, enrollment and roles, federation in the desktop UI, probe packaging. |
| Overlay and RDP transports | Overlay through the OS client (Tailscale, WireGuard): **~0.5 pw**, it is plain TCP. Embedded overlay: **+2 pw** and a Go library inside a Rust build. RDP dynamic virtual channels: **+3–4 pw**, highest risk. |
| Total, full port | Single node: **about 57–61 person-weeks**; with the distributed core **about 76–80**; with embedded overlay and RDP **about 80–87**. With agents: **3.5–4.5 months**, **5–6 months**, **6–7 months**. |
| Mixed Rust/Python (strangler) | Rust host early (engine core, store, probe binary, transports, Tauri); today's collectors and sources run under it as **Python modules over stdio**, launched through a **pinned uv**, and move to Rust by value. **About 50–54 person-weeks (3.5–4 months with agents) to the first distributed release**, about 25 fewer; ~78–84 if everything is eventually ported, plus an ongoing two-language cost ([§12](#12-effort-breakdown)). |
| Hardest part | Replacing `univers`: version comparison across 8+ schemes must stay exact, because a wrong comparison silently hides a vulnerability. New with the distributed mode: the probe protocol becomes a **long-lived public contract**, and remote collection needs a **security model** (enrollment, what a compromised component can do). |
| Cheaper compiled alternative | **Go**: **about 50–56 person-weeks** with the distributed core. Version comparison, extractors, registry client, SSH client and server, gRPC and an **embeddable Tailscale (`tsnet`)** are maintained Go libraries. Desktop app with Wails using the same Vue app. |
| What you get without porting | The component split, the contracts, the engine API and federation **do not need Rust**; all can be done in Python. Only the **probe binary** (pushed over SSH or installed as a daemon: small, static, signed) and a lean desktop app need a compiled language. |
| Recommendation | **Strangler, not a full port.** (1) Make the boundaries real **in Python now** (`collect -O` writes an inventory but nothing reads it back), with the protocol and a Python module server. (2) Spike Rust against Go. (3) **Rust host** with every collector and source as a Python module, and the Tauri app on it. (4) **Probe binary** over **SSH stdio**, harvest as fallback. (5) **TLS dial-out** probes with enrollment, headless server, **federation**. (6) Port modules by value; new features always start in Python. Overlay via the OS client from day one; embedded overlay and **RDP last**. Choose **Rust** if the probe on untrusted hosts and Tauri matter most (the strangler tilts this way); **Go** if the networking ecosystem matters most. |

## 1. What exists today

Measured with `wc -l` on the tracked files of `src/secmonk` (2026-11-11, commit `d03f38f`; module counts include
`__init__.py`). The SBOM work committed just after (`0b73e45`: `sbom.py`, `collectors/sbom.py`, ~430 lines) is not counted.

| Area | Modules | Python lines | Notes for a port |
|---|---|---:|---|
| Core: `models`, `paths`, `errors`, `db`, `ops`, `reports`, `discover` | 7 | ~2,010 | `db.py` holds schema v2 and the migrations: the integration contract. `ops.py` also runs SQL (`_reuse_image`). |
| Engine: `classify`, `versions`, `purl`, `match`, `scoring`, `inventory`, `queries` | 8 | ~1,430 | `versions.py` delegates to `univers`. Replacing it is the most delicate job. |
| Sources (8 feeds) | 10 | ~3,150 | `cvelist`, `osv`, `debian_tracker`, `nvd` are the largest. Calls `git` as a subprocess. |
| Language parsers (`collectors/lang`) | 10 | ~2,480 | Go buildinfo and Rust `cargo auditable` binaries, jar/war, .NET deps.json, lockfiles. |
| Rootfs and Docker (`rootfs`, `docker_image`, `docker_engine`, `docker_transport`) | 4 | ~3,010 | Layered tar view with whiteouts; dpkg/apk/rpm (the rpm database is itself SQLite); registry v2 client; engine over socket, TLS or `ssh … docker system dial-stdio`. |
| macOS, Homebrew | 2 | ~1,210 | plists, `.app` bundles, Cellar kegs. |
| SSH, harvest | 2 | ~1,250 | OpenSSH subprocess or `paramiko` behind one `Transport.stream(cmd, timeout, stdin)` interface; safe tar extraction. |
| Windows | 1 | ~870 | PowerShell JSON, osquery rows, live `winreg`. |
| Process monitor (`collectors/process`, `procmon`) | 8 | ~2,280 | Neutral core + macOS backend (`ps`, `launchctl`, `codesign`). The snapshot format is public. |
| Web (`web/`) | 5 | ~1,020 | stdlib HTTP server, JSON API, background jobs. |
| CLI | 1 | ~1,190 | Typer + Rich. |
| Rest (`collectors/base`, `fs`, package init) | 6 | ~360 | `collectors/base.py` holds `read_within`, `resolve_within` and the redaction helpers. |
| **Total** | **64** | **~20,260** | |

Reused without changes in every option:

- `web/static/` (Vue 3 app, CSS; 3.3k lines without the vendored libraries) and `_design/`. The API payloads must stay identical, which [web-ui](../tech/web-ui.md) already requires.
- `tests/fixtures/` and the fixture READMEs.
- `data/` (`product_aliases.yaml`, `brew_cpe_seed.csv`, the PowerShell inventory script).
- The documentation set. Tech docs need new code paths; feature docs barely change.

Facts about today's code that shape the split:

- **Collection and matching already meet at one object.** `ops.collect` runs a collector and returns an `Inventory`;
  `ops.save_and_match` persists and matches it; `ops.scan_target` / `ops.scan_items` chain the two, and the CLI and the
  web jobs (`web/jobs.py` `JobRunner._scan`) call the same functions.
- **`collect -O` writes the inventory as JSON** (`dataclasses.asdict`), but **nothing reads it back**: there is no
  `Inventory` loader and no ingest command. `ops.collect` also runs `engine/classify.py` on every component before the
  JSON is written, so today's "collector output" already contains engine work.
- **Three hand-off formats are already loaded as untrusted input**: `secmonk-process-snapshot/1` (`snapshot.from_dict`:
  type-checked, capped, re-redacted; `executables[path].identity` lets an agent hand over identities computed on the
  target), the Windows inventory JSON, and SBOM files (`collectors/sbom.py`).
- **Remote work already flows over byte streams**: the SSH collector streams a `tar` over the exec channel of
  `ssh … sh -s`; docker-engine speaks HTTP/1.1 over the stdin/stdout of `ssh … docker system dial-stdio`. A probe
  binary spoken to over SSH stdio is the same pattern.
- **Jobs**: one at a time, no cancel (Python threads cannot be interrupted); every run is a row of the `job` table.
  The process watch is client-driven polling, one tick per request.

Python libraries and how they map to Rust:

| Python | Use | Rust replacement | Risk |
|---|---|---|---|
| `univers` | Version comparison for PyPI, semver, Maven, Go, RubyGems, NuGet, Composer, Debian, RPM, Alpine | `pep440_rs` (PyPI), `semver` / `node-semver` (npm, crates), `debversion` (Debian) **(verify)**. Maven `ComparableVersion`, RPM `rpmvercmp`, apk, RubyGems, NuGet, Composer, Go: **written by us** (~1.5–2k lines). | **High**: security-relevant; see [§13](#13-risks). |
| `packageurl-python` | PURL | `packageurl` crate | Low |
| `httpx` | HTTP with proxy and retries | `reqwest` (rustls, proxy from environment) | Low |
| `typer`, `rich` | CLI and tables | `clap`, `comfy-table`, `indicatif` | Low |
| `paramiko` | Pure-Python SSH | `russh` (pure Rust, async) or `ssh2` (libssh2); `ssh2-config` for `~/.ssh/config`, ProxyCommand written by us | Medium |
| `zstandard` | zstd image layers | `zstd` (C binding) or `ruzstd` (pure Rust) | Low |
| `pyyaml` | `product_aliases.yaml` | `serde_yaml` is no longer maintained. Either use a maintained fork or turn the file into TOML/JSON when building | Low |
| `sqlite3` | State and the rpmdb on targets | `rusqlite` for the target rpmdb; see [§10](#10-several-databases) for state | Medium |
| `tarfile`, `zipfile`, `gzip` | Layers, jars, OSV bulk data | `tar`, `zip`, `flate2` | Low (the safety wrappers must be ported, not dropped) |
| `plistlib` | macOS | `plist` | Low |
| `winreg` | Windows live inventory | `winreg` / `windows` crates | Low |
| ELF/Mach-O/PE readers (written by us) | Go and Rust binary identity | `object` or `goblin`; `auditable-info` for Rust binaries; Go buildinfo written by us (~400 lines, same as today) | Medium |
| `http.server` | Web UI | `axum` (or `tiny_http` for a synchronous design), static files embedded with `rust-embed` | Low |

## 2. Target architecture: probe, engine, ui

### 2.1 Roles and boundaries

| Component | Owns | Must never |
|---|---|---|
| **probe** | Reading one host: collectors, language parsers, process snapshots and identity resolution, host discovery, docker-engine listings, image pulls when the image is the target. Redaction before anything leaves the host. A local spool when it runs as a daemon. | Open the store or the mirror; hold vulnerability data; classify, match or score; call any vulnerability API; run a command that is not fixed, read-only and documented; offer an "execute this" method; extract archives blindly or follow symlinks out of the scanned tree (`read_within` / `resolve_within`, size caps). |
| **engine** | The store (inventory, findings, run history) and the mirror; sync; classification, matching, scoring, finding lifecycle; jobs and their routing to probes; the probe registry and enrollment; the engine↔ui payloads (`reports.*`, `procmon.snapshot_payload`, `event_dict`); optionally an HTTP server with the web UI. | Read a target itself: every target access goes through a probe, even the local machine (in-process probe). Call external vulnerability APIs during a scan (only `sync` uses the network). Trust probe output: it is validated, capped and re-redacted on ingest, as `snapshot.from_dict` does today. |
| **ui** | Rendering engine payloads; navigation; the list of engines it is connected to and their credentials (federation). | Hold business logic (no re-scoring, no matching, no SQL); talk to a probe directly; render with `v-html` or inline scripts (today's web UI rules stay). |

Two consequences:

- **Classification moves to the engine.** `ops.collect` classifies today; in the split the probe returns unclassified
  components (identity evidence: PURL, bundle id, hints) and the engine classifies on ingest. Alias table and brew seed
  updates then reach old probes without a probe upgrade.
- **The process monitor splits at the snapshot.** Identity resolution reads the target's files (bundles, kegs,
  codesign), so it stays in the probe; the probe returns a `secmonk-process-snapshot/1` with `executables[path]`
  facts and `identity` filled. Launch classification, views, matching and watch events can then run anywhere.

### 2.2 Today's modules, mapped

| Python today | Component | Note |
|---|---|---|
| `collectors/*` (all), `collectors/lang`, `collectors/process` (backends, `snapshot.py`), `harvest.py`, `docker_transport.py` | probe | Unchanged code, new caller. |
| `collectors/base.py` (`read_within`, `resolve_within`, `redact_command`, `strip_url_secrets`, `redact_labels`, `scrub_text`) | probe, reused by the engine | The engine re-applies redaction on ingest. |
| `discover.py` | probe | Host discovery is a probe method: the probe reports what it can collect on its host. |
| `collectors/ssh.py` | engine-side transport + probe | Its `Transport` (OpenSSH / paramiko) becomes the SSH adapter; the harvest stays as a fallback "probe without a binary" ([§3](#3-deployment-topologies), topology b). |
| `models.py` | shared (protocol types) | |
| `engine/*`, `db.py`, `sources/*` | engine | `classify` is called on ingest, not in `collect`. |
| `ops.py` | split | `collect`, `expand_targets`, `docker_contexts`, `docker_containers`, `discover_host` become probe calls; `save_and_match`, `scan_target` / `scan_items`, `_reuse_image` (its engine check `image_meta` becomes a probe call), the run history stay in the engine. |
| `reports.py`, `procmon.py` | engine | `procmon.Watcher` diffing can run in the probe (stream of events) or in the engine (diff of snapshots). |
| `web/server.py`, `data.py`, `jobs.py`, `api.py` | engine (HTTP binding, jobs) | |
| `web/static/`, `_design/` | ui | |
| `cli.py` | client of both | Probe commands (`collect -O`, `procs --snapshot-out`) and engine commands; standalone runs all three in-process. |

Naming: "probe" also means the read-only commands of `discover.py` ("discovery probes") and the
[probe log](../references/probes.md); the component is always "the probe".

## 3. Deployment topologies

**(a) Standalone desktop: one process, offline.** Today's single-user use. No socket is opened.

```
+--------------------------- secmonk-desktop (one process) ---------------------------+
|  ui (webview) --in-process--> engine --in-process--> probe --> this machine          |
|                                 | store + mirror: SQLite in the per-user state dir   |
+---------------------------------------------------------------------------------------+
```

**(b) Desktop + engine + hosts reached over SSH (agentless).** The engine opens an SSH exec channel and speaks the
probe protocol over its stdin/stdout. Three modes, chosen per host:

```
 analyst machine                                        remote hosts (nothing installed)
+--------------------------------------+   ssh exec    +-------------------------------------------+
| ui -> engine -+-> probe (local)      |=============> | A: probe binary pushed to a 0700 temp dir,  |
|               +-> ssh adapter -------+ stdio frames  |    `serve --stdio`, removed on exit         |
|                                      |=============> | B: preinstalled probe, forced command       |
|                                      |=============> | C: no binary allowed: today's find|tar      |
+--------------------------------------+   tar stream  |    harvest, parsed by the local probe       |
                                                       +-------------------------------------------+
```

- **Push** (A): detect OS and architecture with the existing detect script, pick the matching signed static binary,
  send it on stdin into `mktemp -d` (umask 077), check its sha256 on the host, run it, `trap` removes it. This **writes
  to the target**, which today's SSH collector promises not to do ("no agent, no writes"): it must be opt-in and decided
  in an ADR. Windows: Defender, AppLocker or WDAC may block an unsigned executable; sign it (Authenticode).
- **Installed** (B): `authorized_keys` with `command="secmonk-probe serve --stdio",no-pty,no-port-forwarding`: the key
  can do nothing else. This extends the "safer sudo" setup of [the SSH collector](../tech/collectors/ssh.md).
- **Harvest** (C): unchanged; the local probe runs the collectors on the extracted tree. It remains the default until
  push is accepted.

**(c) Installed probe daemons.** Probes behind NAT or firewalls **dial out** to the engine over TLS with mTLS and keep
the connection open; the engine sends requests down that connection (the protocol is symmetric, [§4](#4-contracts-and-protocol)).
No inbound port on the host. A probe can collect on a schedule while disconnected and upload later ([§7](#7-operations-across-hops)).

```
 host D (NAT)  secmonk-probe (service) ---wss + mTLS, dials out--->  engine :8443 (probe listener)
 host E        secmonk-probe (service) ---wss + mTLS, dials out--------^       |
 the engine calls probe.collect / probe.watch on the connections the probes opened
```

**(d) Headless engine server with its own web UI.** `secmonk-server` = engine + HTTP binding of the engine↔ui
contract + the static Vue app + the probe listener. Today's `secmonk ui` is this topology on loopback without
authentication; on a network it needs authentication and roles ([§6](#6-security-model)).

```
 browser --https (login, role)--> secmonk-server [engine + web UI + probe listener] <-- probes (c)
                                        | inventory/findings: SQLite or PostgreSQL; mirror: SQLite
```

**(e) One UI, several engines on different networks (federation).** The desktop app keeps a list of engines; each
engine keeps its own probes, store and mirror.

```
               +--https + mTLS / token------> engine "office" --- local probe, ssh hosts, daemons
 desktop ui ---+--tcp over tailnet (overlay)-> engine "lab"    --- probes
               +--ssh stdio (or ssh -L)------> engine "dmz"    --- probes
               +--in-process-----------------> engine "local"  --- this machine
```

Who dials whom:

| Link | Dials | Why |
|---|---|---|
| ui → engine | the UI | Engines are servers; the desktop is often offline or behind NAT. An engine on a closed network is reached through an overlay or an SSH hop, never by having it dial a laptop. |
| engine → probe over SSH | the engine | Agentless: the host only runs sshd. |
| probe daemon → engine | the probe | NAT and firewalls allow outbound 443; the host exposes nothing. |
| engine → probe daemon (listening) | the engine | Only on flat networks, opt-in; the default is dial-out. |
| RDP channel | the analyst's RDP client dials the host; the probe inside the session opens the channel | The channel lives inside a session someone already opened. |

## 4. Contracts and protocol

### 4.1 Two interfaces, defined once

| Interface | Methods (from today's code) | Payloads reused |
|---|---|---|
| **probe ↔ engine** | `hello`; `discover` (`discover.discover_host`); `expand_targets`; `collect(collector, target, options)` → inventory stream; `snapshot` (process); `watch` → event stream; `docker.contexts`, `docker.containers`, `docker.image_meta` (for image reuse); `cancel` | `Inventory` JSON (what `collect -O` writes, without classification), `secmonk-process-snapshot/1`, `reports.discover_payload`, `procmon.event_dict` |
| **engine ↔ ui** | One method per route of today's `/api/` ([web-ui](../tech/web-ui.md#api)): `meta`, `overview`, `assets.*`, `findings`, `vulns.*`, `sources`, `collectors`, `jobs.start/list/get`, `discover`, `docker.*`, `processes.*`; new: `jobs.cancel`, `events.subscribe`, `probes.list/enroll/revoke`, `engine.info` | `reports.*`, `procmon.snapshot_payload`, `event_dict`, `job_payload`, the error shape `{error, hint, code}` of `ApiError` |

Each method is declared once (name, parameter schema, result schema, `read` or `action`, minimum role). From that
catalog come the **HTTP binding** (GET for reads, POST for actions: today's routes, so the Vue app and `MockSource`
do not change), the **stream binding** (frames, below) and the **in-process binding** (a Rust trait call).
In-process skips serialization; a conformance suite runs every method through the in-process and the serialized
bindings and compares the JSON.

### 4.2 Encoding and IDL

The decisive constraints: the Vue app, the CLI's `--format json`, the design mocks and the fixtures all consume JSON
today; the probe must be reachable over byte streams that are not HTTP (SSH stdio, RDP channels); and a probe that
dialed out must still *receive* calls.

| Option | Browser / Vue app | Non-TCP byte streams | Calls toward the side that dialed | Today's payloads | Rust | Go |
|---|---|---|---|---|---|---|
| protobuf + gRPC | needs gRPC-Web or Connect and a proxy | HTTP/2 over a custom IO is possible (tonic custom connector, `serve_with_incoming`) **(verify)**, but adds h2 over stdio or a channel | server/client roles follow the connection: needs a reverse tunnel | must be remodelled (`meta` dicts → `Struct`, proto3 JSON renames fields unless `json_name`) | `tonic`, mature | `grpc-go`, mature |
| protobuf or JSON + Connect | yes (JSON over HTTP/1.1) | HTTP only | same as gRPC | JSON mode keeps shapes only with care | young **(verify)** | `connect-go`, mature |
| **JSON envelope over framed streams** (recommended) | the HTTP binding is today's API | any byte stream | symmetric: both peers send requests | identical | written by us (~1–1.5k lines) + `serde`, `schemars` for JSON Schema **(verify)** | same |
| Cap'n Proto RPC | no | any stream, symmetric | yes | remodelled | `capnp-rpc` **(verify)** | `capnproto-go` |

**Recommendation: JSON messages, JSON Schema as the IDL, a small framed envelope over any byte stream.**

- Frame = 4-byte big-endian length + one JSON message, at most 16 MiB; bulk results (inventories of tens of
  thousands of components, snapshots) are **streamed in chunks**, never one frame. Frames above 64 KiB may be
  zstd-compressed (flag in the frame header).
- Messages: `req {id, method, params}`, `res {id, result}`, `err {id, error, hint, code}`, `event {id, data}` (one
  item of a stream), `end {id}`, `cancel {id}`. Both peers may send `req`, so a dialed-out probe receives calls.
- The codec is negotiated in `hello` (`json` now; CBOR or protobuf later, only if measured volume asks for it).
- gRPC is offered as a **transport**, not as the IDL: one bidirectional method carrying the same frames, for
  networks that mandate gRPC (service meshes, gRPC-aware proxies). About 0.5 pw.

### 4.3 Versioning and capability negotiation

The first message on every connection is `hello`, from both sides:

```json
{"type": "hello", "protocol": "secmonk-wire/1.0", "role": "probe", "id": "probe:3f9c…", "version": "0.9.0",
 "os": "linux", "arch": "aarch64", "collectors": ["rootfs", "fs", "docker-engine", "process"],
 "capabilities": ["watch", "spool", "sudo-helper", "push-binary"], "codecs": ["json"], "limits": {"max_frame": 16777216}}
```

- `protocol` major must match; minors are additive (new optional fields, new methods). Unknown fields are ignored;
  unknown methods answer `err code=unknown-method`. The engine supports the current and the previous probe major.
- Payload formats keep their own versions: `secmonk-process-snapshot/1` (already validated on load), an
  `inventory_version` on `Inventory` (the docker-engine image inventory already carries one), the schema version of the
  store.
- The engine shows a probe's missing capability as an unavailable action with a reason, as discovery candidates do
  today (`available`, `reason`).

## 5. Transports

Design rule: a transport is **anything that yields a bidirectional byte stream** (`AsyncRead + AsyncWrite`); framing,
`hello`, authentication of the peer and the RPC layer sit above it. A new transport is an adapter of a few hundred
lines.

| Transport | Direction | Peer authentication | NAT traversal | Rust crates | Maturity | Risk |
|---|---|---|---|---|---|---|
| **In-process** | n/a | none (same process) | n/a | trait call; `tokio::io::duplex` for serialized tests | high | none |
| **Child process stdio** (elevated helper, local probe in its own process) | engine spawns | OS user / launchd or service manager | n/a | `tokio::process` | high | low |
| **SSH exec + stdio** (push, forced command, harvest fallback) | engine → host | SSH keys or agent, `known_hosts` | needs a route to sshd; `ProxyJump` / bastions | system `ssh` subprocess (keeps `~/.ssh/config`, `ProxyJump`, agent, as today's `OpenSSHTransport`) or `russh` (config support partial **(verify)**) | high (OpenSSH), medium (russh) | push writes to the target; AV on Windows |
| **TLS stream** (WebSocket over TLS, or raw TLS) with mTLS | probe → engine (default), ui → engine | mTLS with certificates from enrollment; engine certificate pinned | outbound 443 passes most NATs and HTTP CONNECT proxies | `rustls`, `tokio-rustls`, `tokio-tungstenite` or `axum` WebSocket, `rcgen` (engine CA) | high | PKI operations |
| **gRPC** (same frames, one bidi method) | as TLS | mTLS | as TLS | `tonic` | high | low (optional adapter) |
| **RDP dynamic virtual channel** | probe inside the Windows session opens the channel; the analyst's RDP client hosts the other end | the RDP session (NLA, RD Gateway) + a pairing code shown by the probe | whatever reaches RDP (RD Gateway) | host side: `windows` crate (`WTSVirtualChannelOpenEx` with `WTS_CHANNEL_OPTION_DYNAMIC`); client side: an `mstsc` plugin (COM `IWTSPlugin` DLL), a FreeRDP channel plugin, or IronRDP's DVC support **(verify)** | low | high: a plugin to install on every analyst machine, policies can disable custom channels, message-size and chunking limits **(verify)** |
| **Overlay via the OS client** (Tailscale, WireGuard, Headscale) | any | overlay identity + our mTLS on top (never the overlay alone) | excellent (relays) | none: it is the TLS transport over the tailnet address | high | depends on a client installed on both ends |
| **Embedded overlay** | any | node key + our mTLS | excellent | Tailscale `tsnet` is **Go only**; `libtailscale` is a C library built from Go (links the Go runtime, cgo, harder cross-builds) **(verify)**; userspace WireGuard via `boringtun` **(verify maintenance)** plus a coordination service we would have to build or borrow (Headscale) | low in Rust | Go toolchain inside a Rust build; a third-party control plane |

Reading the table:

- **First**: in-process (free with the trait design), SSH stdio (covers today's agentless use and topology b), TLS
  dial-out (topologies c, d, e). Child-process stdio comes with the desktop app's privileged helper.
- **Overlay**: document "use the OS Tailscale / WireGuard client" from day one; it costs no code. Embed only if a user
  cannot install a client. This is where **Go is clearly ahead**: `tsnet` makes an engine or probe a tailnet node in a
  few lines, while Rust needs the Go runtime through `libtailscale` or a sidecar.
- **RDP last**, and only on request: neither Rust nor Go has a ready RDP stack for this; the Windows side is plain
  Win32 in both.

## 6. Security model

Today's model ([web-ui](../tech/web-ui.md#security-local-no-authentication)) is local and unauthenticated: loopback
bind, `Host` check, `X-SecMonk-Request: 1` on every `/api/` call, actions refused on a non-loopback bind unless
`--allow-actions`. **All of it stays** for the HTTP binding. The distributed mode adds:

| Topic | Design |
|---|---|
| Identities | Every probe and engine has a key pair generated on first start and a stable id (`probe:<hash of key>`). Keys live in the per-user state directory ([ADR-0006](../decisions/0006-per-user-state-locations.md)) or, for services, a root-owned directory (needs an amendment of ADR-0006). |
| Probe enrollment | The engine is a small CA for its probes. An admin creates a one-time token (single use, short TTL) bound to an expected name; the probe runs `secmonk-probe enroll https://engine:8443 --token … --pin sha256:<engine cert>`, sends a CSR + token, receives a client certificate. Revocation = a list kept by the engine, checked on every `hello`. |
| SSH-reached probes | No enrollment: the peer identity is the SSH host key (`known_hosts`, as today); the probe is ephemeral and gets no certificate. |
| Engine ↔ UI | Standalone: in-process, no credentials. Remote: pairing the desktop with an engine yields a client certificate or an API token per user (bearer header, never a cookie); OIDC later. **Roles**: `viewer` (reads), `operator` (scans, syncs, discovery: today's `--allow-actions`), `admin` (probes, enrollment, users). Every action is written to the run history with the user. |
| Probe hardening | Collector **allowlist in the probe's own config** (the engine cannot widen it); the fixed command list stays in the binary; no method runs an arbitrary command; runs unprivileged, with an optional privileged helper for what needs root; dial-out mode opens no port. |
| Data minimization | Redaction runs **in the probe** (`redact_command`, `strip_url_secrets`, `redact_labels`, `scrub_text`), so secrets never leave the host; the engine re-redacts on ingest. Option values with secret-looking names stay redacted in the history (`ops.redact_opt_items`). Browser-sent scans keep refusing `ssh_bin`, `transport`, `ssh_option`. |
| Signed binaries | Release key signs every probe build (minisign or Sigstore **(verify)**); Developer ID + notarization on macOS, Authenticode on Windows; the engine refuses to push a binary whose signature does not verify; installed probes verify self-updates against the release key, not the engine key. Each release ships the probe's own CycloneDX SBOM. |

What a compromised component can do:

| Compromised | Can | Cannot (by design) |
|---|---|---|
| probe | Lie about its host (hide components, invent findings); flood the engine. | Write other probes' assets (assets are bound to the probe id); read the mirror, findings or other hosts; get a wider allowlist. Mitigation: ingest limits as in `snapshot.from_dict`, per-probe quotas. |
| engine | Read everything its probes report; run **allowlisted** collectors on reachable targets; use the SSH credentials it holds; push a probe binary. | Run arbitrary commands through a probe; push a binary that is not release-signed; reach other engines' probes. Mitigation: scoped SSH keys with forced commands, audit log. |
| ui (desktop) | Everything its user's roles allow on every engine it holds credentials for. | Reach probes directly; bypass engine roles. Mitigation: per-engine credentials in the OS keychain, short-lived tokens. |

## 7. Operations across hops

- **Offline and buffered probes.** A daemon probe can collect on a schedule into a bounded local spool (files `0600`,
  oldest dropped first, a warning recorded) and upload when connected. Each result carries probe id, run id and
  `collected_at`; the engine ingests idempotently by `(probe id, run id)`. A spooled result older than the asset's
  latest scan is stored as history, not as the current inventory.
- **Streaming.** `watch` becomes a server-push stream: the probe diffs snapshots (`procmon.Watcher` logic) and sends
  events; the engine matches the new executables and forwards `event_dict` to subscribed UIs (server-sent events or a
  WebSocket on the HTTP binding, Tauri events on the desktop). Flow control: a window of unacknowledged events; on
  overflow the probe drops events and sends a fresh baseline, as a refresh during a watch does today.
- **Long jobs and cancellation.** A job is a request id at every hop: `cancel` travels ui → engine → probe, and the
  probe aborts the collector (the harvest already supports `finish(abort=True)`). Job states gain `queued` and
  `cancelled` next to today's `running`, `ok`, `partial`, `error`, `interrupted`. The engine runs several jobs (a limit
  per probe and one SQLite writer, or several on PostgreSQL), which lifts today's one-job limit.
- **Version skew.** Probe and engine negotiate in `hello` ([§4.3](#43-versioning-and-capability-negotiation)); UI and
  engine read `engine.info` (today's `/api/meta` `features`) and hide what the engine lacks. Engines upgrade first,
  probes follow; an engine never requires a probe minor newer than its own.
- **Where the mirror lives.** One mirror per engine, synced by that engine (`sync` is the only step that uses the
  network for vulnerability data). Air-gapped engines import with today's `--path` options; a later option is an
  engine exporting its mirror for another. The federated UI shows each engine's mirror freshness (`status` payload)
  next to its findings, because two engines can disagree only through their mirrors.
- **Federation.** Asset ids are namespaced by engine in the UI (`<engine>/<asset id>`); overviews are merged in the
  UI from per-engine payloads (counts are added, nothing is re-scored). An unreachable engine shows as stale, not as
  zero findings.

## 8. Crate and binary layout

```
crates/
  secmonk-model       Inventory, Asset, Component, Snapshot, payload types (serde). No I/O.
  secmonk-proto       method catalogs (probe, engine), envelope, hello/capabilities, JSON Schemas.   (model)
  secmonk-transport   byte-stream adapters: inproc, child stdio, ssh (OpenSSH | russh), tls/wss,
                      grpc, rdp-dvc (windows), overlay (feature-gated). No domain types.
  secmonk-rpc         framing, sessions, request/stream/cancel over any transport               (proto, transport)
  secmonk-versions    version schemes + OSV range evaluation. No I/O. Tested against univers.
  secmonk-purl        PURL <-> OSV ecosystem, name normalization
  secmonk-safeio      read_within / resolve_within, size caps, safe tar/zip readers, redaction
  secmonk-lang        7 language parsers + walk_dir / LangAccumulator                         (model, safeio)
  secmonk-collect     collectors: fs, rootfs, docker-image, docker-engine, macos, homebrew,
                      windows, ssh harvest, process  (cfg/feature-gated per OS)                (model, lang, safeio)
  secmonk-probe-core  probe service: dispatch, allowlist, discovery, watch, spool              (collect, proto, rpc)
  secmonk-store       Store trait + sqlite / postgres / mysql backends (features)              (model)
  secmonk-sources     8 feeds -> Store                                                         (store, versions)
  secmonk-engine      classify, match, scoring, finding lifecycle                              (model, store, versions, purl)
  secmonk-engine-svc  jobs, probe registry, enrollment CA, reports, engine method catalog      (engine, store, sources, proto, rpc)
  secmonk-http        HTTP binding of the engine catalog, Host/CSRF/auth checks, static UI     (engine-svc)
  secmonk-ui-core     engine connections, credentials, federation merge (desktop)              (proto, rpc)
bins/
  secmonk-probe       probe only: static, signed; serve --stdio | connect wss://… | enroll     (probe-core, transport)
  secmonk-server      engine + HTTP + web UI + probe listener                                  (engine-svc, http)
  secmonk             CLI: probe and engine commands, standalone                               (all)
  secmonk-desktop     Tauri: ui-core + engine-svc + probe-core in one process
```

Rules the compiler (and one CI check) enforces:

- `secmonk-collect` and `secmonk-probe-core` do not depend on `secmonk-store`, `secmonk-sources` or `secmonk-engine`:
  "collectors never touch the DB" and "the probe holds no vulnerability data" become compile errors. A CI step fails if
  `cargo tree -p secmonk-probe` lists any of them (transitive dependencies are not caught by the compiler alone).
- `secmonk-ui-core` depends on `proto` and `rpc` only: even in the desktop process the UI reaches the engine through the
  catalog, never through the store.
- `secmonk-proto` and `secmonk-model` have no I/O and no async runtime.
- The engine reaches SQL only through the `Store` trait, and targets only through `secmonk-proto` probe calls.

The biggest *architectural* gain, and the main reason for a compiled language, is **a probe binary** of about 5–10 MB,
static on Linux (musl), with no Python runtime. Builds are per platform: a Linux probe leaves out the macOS backend
(`cfg(target_os)`), a server build leaves out Tauri, the RDP adapter exists only on Windows builds.

### 8.1 Contracts to freeze first

These become versioned JSON Schemas and are checked by both implementations during the transition:

- `Inventory` JSON (`collect -O`, made unclassified, with a reader on the engine side)
- `secmonk-process-snapshot/1`
- The web/CLI JSON payloads (`reports.*`, `procmon.snapshot_payload`, `event_dict`)
- The probe and engine method catalogs and the envelope (`secmonk-wire/1`)
- Database schema v2 (already documented in [data-model](../tech/data-model.md))

The same separation can be done in Python with packages and import linting (`import-linter`), at about 10% of the
cost, and the protocol can be implemented in Python first ([§15](#15-recommended-path)). The probe binary is the part
that really needs a compiled language.

## 9. Mixed Rust/Python: Python as the fast lane

Python is faster to write and is how this repository was built. The roadmap therefore keeps Python as the language
for spikes and new features, working end to end from the first day, and moves a module to Rust only once it has proved
its worth. Both run behind **one component interface**.

### 9.1 One interface, two bindings

- **Rust module**: implements the trait (`Collector`, `LangParser`, `Source`, `Tool`), is linked in and called in-process.
- **Python module**: a child process speaking the **same framed protocol** of [§4](#4-contracts-and-protocol) on
  stdin/stdout (stderr = log lines). A host adapter implements the same trait on top of it, so the engine and the probe
  cannot tell the two apart. One Python entry point (`secmonk module serve <name> --stdio`) serves every module of the
  `secmonk` package; a standalone spike is a single PEP 723 script.
- **Module registry**: one manifest per module: `name`, `kind` (`collector`, `lang-parser`, `source`, `tool`),
  `runtime` (`rust` or `python`), `version`, `protocol`, `capabilities`, `entry`, bundle `sha256`. `hello` carries the
  same facts, so a probe reports its modules and their runtime to the engine.

| Interface | Pluggable | Why |
|---|---|---|
| Collectors (probe modules) | yes | Already a registry (`@register`) returning an `Inventory`; one call per target, so a process boundary costs nothing. |
| Language parsers | yes, in batches | `collectors/lang` registry; called per file, thousands of times: a Python parser receives a batch of files per call. |
| Vulnerability sources | yes, reshaped | Today a `Source` writes SQL through `sources/base.py` (`upsert_vulnerability`, `add_affected`, …). As a module it streams normalized records and the engine writes them; no module gets a database handle. |
| Tools and exports (SBOM export, report formats, discovery) | yes | Functions over payloads. |
| Versions, OSV ranges, classify, match, scoring | **no** | Hot and security-critical: one implementation, differential-tested against `univers` once. |
| Store, migrations | **no** | The integration contract; one writer. |
| safeio, redaction, protocol, transports | **no** (host) | They enforce the rules on the modules. |

### 9.2 uv inside the engine and the probe

| Option | How | Verdict |
|---|---|---|
| **(a) Pinned `uv` binary** next to the engine / probe | Subprocess: `uv run --script --locked --offline`; version and sha256 pinned in the release | **Recommended**: uv's command line is its stable interface; upgrades are a file swap. |
| (b) uv's Rust crates linked in | `uv-resolver`, `uv-installer`, … from uv's workspace | Not a stable public API and a large dependency tree **(verify)**; every uv upgrade can break the build. |
| (c) The host's Python | Whatever is on PATH | Only as a fallback: version and packages are unknown. |

- Scripts declare `requires-python` and `dependencies` in **PEP 723** inline metadata; releases ship a lock per
  script (`uv lock --script` **(verify)**) with hashes, and production runs use `--locked` / `--frozen` and `--offline`
  against a **cache shipped in the module bundle** (wheels + lock, signed). No resolution or download at run time.
- **Interpreter**: python-build-standalone, installed by `uv python install` into a directory owned by the engine or
  probe (`UV_PYTHON_INSTALL_DIR`), downloads disabled (`UV_PYTHON_DOWNLOADS=never`) once the bundle is in place.
  Footprint: uv + interpreter + wheels is on the order of 100 MB on disk **(verify)**, against 5–10 MB for the Rust probe.
- **Remote probes**: a Python module on a target means writing uv, an interpreter and a cache there, and network
  unless the bundle is pushed. That breaks the SSH promise of no writes even more than the binary push
  ([§3](#3-deployment-topologies), mode A): **opt-in under the same ADR**. The default for agentless hosts is to run
  Python modules **on the engine side over harvested data** (mode C), as the SSH collector does today; live facts
  (processes, signatures) come from the Rust probe or from fixed scripts such as the remote Linux process snapshot being
  added in `collectors/process/remote.py` (uncommitted at the time of writing).

### 9.3 Security of Python modules

- **Modules are code execution.** Only modules from release-signed bundles or pinned by sha256 in the engine or probe
  configuration run; the allowlist names them. The UI chooses among installed modules and can never upload a script or
  name a path, the same policy that refuses `ssh_bin` and `transport` from the browser today.
- **Same untrusted-target rules.** Python modules read targets through a small Python `safeio` package extracted from
  today's `collectors/base.py` (`read_within`, `resolve_within`, redaction): it is the reference that the Rust
  `secmonk-safeio` must pass. The host treats module output as probe output (validated, capped, re-redacted).
- **Isolation comes free with the process boundary**: a crash, a hang (timeout, then kill) or a memory blow-up
  (rlimits on Linux and macOS, Job Objects on Windows) costs one module run, not the engine. No network for collector
  modules where the OS allows it **(verify per OS)**.

### 9.4 Lifecycle of a module

1. **Spike** in Python as a stdio module, end to end through engine and UI.
2. **Freeze** its parameter and result schemas and record golden outputs on its fixtures (package 0).
3. **Port** to Rust, in-process.
4. **Differential test**: both bindings on the shared fixtures, normalized JSON equal; the harness of package 0, also
   used for `versions` against `univers`.
5. **Flip** `runtime` in the manifest.
6. **Keep** the Python binding as the test reference for one release, then retire it, or keep it as a fallback for a
   platform without a Rust build. No module keeps two production bindings for longer.

### 9.5 Why a subprocess and not embedded CPython

[§14](#14-other-compiled-stacks) rejects "Rust via PyO3 under Python" because nothing gets easier to distribute.
Embedding the other way round (CPython inside the Rust host) has the same flaw and more: the host links libpython and is
no longer a static single binary; a module crash or leak takes the engine down; the GIL serializes modules (free-threaded
CPython is still young **(verify)**); modules' dependencies collide in one interpreter. A subprocess costs a process start
(kept alive for the length of a job) and JSON serialization, negligible at collector granularity and batched for
parsers. PyO3 stays an option only for a hot pure function, if profiling ever asks; the scanner is I/O bound.

### 9.6 Strangler migration

The Rust host (engine core, store, probe shell, transports, Tauri) comes **early**, with today's collectors and sources
running under it as Python modules. Modules are then ported by value: the engine core first (not pluggable), then what
the static probe binary needs and what parses untrusted input on targets (`safeio`, `lang`, `rootfs`, `fs`, the process
backends), then hot paths (image layers). Sources run on the engine host, where Python is available and the work is
network-bound: they can stay Python for a long time, possibly for good. Effort and sequencing: [§12](#12-effort-breakdown),
[§15](#15-recommended-path).

## 10. Several databases

### 10.1 What in today's SQL is SQLite-only

There are about 106 `execute` calls, mostly in `db.py` (21), `engine/queries.py` (19), `engine/match.py` (17),
`sources/cvelist.py` (10), `sources/osv.py` (8) and `sources/base.py` (8); `ops.py` has 3 (`_reuse_image`). SQLite-only
features in use:

| Feature | Where | PostgreSQL | MySQL / MariaDB |
|---|---|---|---|
| `INSERT OR REPLACE` / `OR IGNORE` | `sources/base.py`, `kev`, `epss`, `debian_tracker` | `ON CONFLICT DO UPDATE / NOTHING` | `ON DUPLICATE KEY UPDATE`, `INSERT IGNORE` |
| `ON CONFLICT … excluded.` | `engine/inventory.py`, `match.py`, `euvd.py`, `db.py` | same syntax | `VALUES(col)` / row alias |
| `json_extract(meta,'$.x')` | `queries.py`, `inventory.py`, `msrc.py` (5 places) | `meta->>'x'` (jsonb) | `meta->>'$.x'` |
| `IS ?` (null-safe equality) | `msrc.py` | `IS NOT DISTINCT FROM` | `<=>` |
| `PRAGMA user_version`, `table_info`, WAL | `db.py`, `match.py` | migrations table, `information_schema` | same |
| `?` placeholders | everywhere | `$1` | `?` |
| `TEXT PRIMARY KEY` (vuln ids, component keys) | schema | fine | needs `VARCHAR(n)`: InnoDB caps index keys at 3072 bytes in utf8mb4 |

The rpmdb read in `collectors/rootfs.py` is the **target's** SQLite file. It stays `rusqlite`, in the probe, whatever
the state backend.

### 10.2 Design

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
- **Concurrency**: SQLite's single writer hides races that PostgreSQL will show when several probes report at once
  (finding lifecycle: open, fixed, re-opened). These paths need explicit transactions and `SELECT … FOR UPDATE`. A
  headless engine with many daemon probes (topologies c, d) is where PostgreSQL first pays off.
- **Split the vulnerability mirror from the inventory.** The mirror can be rebuilt and is read-heavy, so it can stay a
  local SQLite file even when inventory and findings live in a shared PostgreSQL. Allowing different backends for the two
  halves avoids copying a multi-GB mirror into every server database, and matches "one mirror per engine". **Recommended.**
- **Tests**: SQLite in memory by default (offline, as today); PostgreSQL and MySQL through testcontainers in CI, running
  the same `Store` conformance suite.

Effort: **+5–7 person-weeks** on top of a SQLite-only port. Done in Python with SQLAlchemy Core, the same work costs
about the same; the effort comes from the design, not the language.

## 11. Desktop app

### 11.1 Tauri v2 (recommended for Rust)

- **One process, three components.** The Tauri core links `probe-core`, `engine-svc` and `ui-core`: topology (a) with
  no socket. The same app adds remote engines (topology e) through `ui-core`.
- **The front end stays as it is.** Tauri can serve a plain directory (`frontendDist` → `web/static`), and
  `withGlobalTauri` exposes its API without a bundler. The "no build step, no network" rule of
  [ADR-0009](../decisions/0009-web-ui-vendored-libraries.md) still holds.
- **API transport**: a custom URI scheme (for example `secmonk://api/<engine>/...`) whose handler calls the engine
  catalog: in-process for the local engine, through `ui-core` for a remote one. In `secmonk-views.js` only `base` and an
  engine selector change. The desktop app opens no TCP port, so the `Host` check and DNS-rebinding concerns do not apply
  there; the browser UI keeps them.
- **Privileged helper**: the app runs as the user; the process monitor as root (other users' launchd domains) needs a
  helper (a launchd daemon registered with SMAppService on macOS, a service on Windows) reached over child-process or
  local-socket stdio with the probe protocol.
- Jobs and `--watch` push Tauri events instead of being polled.
- Tray icon, notifications (new P1 finding, new process), start at login and auto-update come with Tauri plugins.
- CSP: Tauri adds nonces to its own scripts; our pages have no inline scripts or styles, so they fit.
- **Distribution**: macOS needs a Developer ID, hardened runtime and notarization. The app cannot be sandboxed for the Mac
  App Store, because the process monitor runs `ps`/`launchctl`/`codesign` and reads `/Applications` and other apps' bundles.
  Windows needs signing (WebView2 ships with Windows 11). Linux uses WebKitGTK, whose version differs between distributions,
  so test the AppImage/deb/rpm packages.
- Size: about 10–20 MB, against 100+ MB for Electron.

Effort: **3–5 person-weeks** (protocol handler 1, packaging and signing for 3 OSes 1–2, tray/notifications/updater 1,
CI release matrix 1). Federation and the privileged helper are counted in [§12](#12-effort-breakdown) (packages 19, 23).

### 11.2 Desktop app without porting first: Tauri shell + Python sidecar

Tauri can start a sidecar binary. Package today's `secmonk ui` with PyInstaller or Nuitka (one 40–70 MB executable per
OS) and point the webview at it on a random loopback port, passing a token. This gives a signed desktop app in **2–3 weeks**
and keeps every bit of the Tauri work (configuration, signing, updater, icons) for the Rust version later. With the strangler
([§9.6](#96-strangler-migration)) the Rust host arrives early and runs the same Python code as modules through a bundled
uv, so the sidecar is only worth it if a signed app is needed before that. Either way, the packaging is too large and too
libc-dependent to push over SSH as a probe.

### 11.3 Alternatives

| Option | Language | Reuses the Vue app | Note |
|---|---|---|---|
| **Tauri v2** | Rust (any backend as a sidecar) | yes | Best fit for Rust; small; mature on all three OSes. |
| **Wails v2/v3** | Go | yes | The Go equivalent of Tauri; same system webviews. |
| Electron | Node | yes | Heavy; brings an npm toolchain, against ADR-0009. |
| Dioxus / Slint / egui / iced | Rust native | **no** | The UI would be rewritten. Not worth it: the design system and storybook already exist. |
| Avalonia / .NET MAUI | C# | no (MAUI Blazor Hybrid partly) | Only if the stack becomes .NET. |
| Flutter | Dart | no | Rewrite; adds a fourth language. |

## 12. Effort breakdown

"Person-weeks" means one senior developer fluent in Rust and new to this codebase, including tests and docs. The "with
agents" column assumes coding agents write the code and port the tests, while one person reviews, runs the
differential checks and takes the decisions. It is the method this repository was built with (55 commits since
2026-11-07). The review and validation work does not shrink.

| # | Work package | Python lines | Person-weeks | With agents (calendar) |
|---|---|---:|---:|---:|
| 0 | Contracts: JSON Schemas, reference outputs recorded from Python on every fixture, differential runner | — | 1.5 | 0.5 |
| 1 | Workspace, model, paths, errors, purl, safeio, redaction | ~460 | 1.5 | 0.5 |
| 2 | **Version schemes** (univers replacement) + OSV ranges + differential and property tests against univers | 213 (+ library) | 4 | 1.5 |
| 3 | Store trait + SQLite backend + schema v2 migration from existing databases | 453 + ~106 calls | 2.5 | 1 |
| 4 | Engine: classify, match, scoring, lifecycle, queries | ~1,080 | 3 | 1 |
| 5 | Sources (8), including `git` for cvelist and bulk loaders | ~3,150 | 5 | 1.5 |
| 6 | Language parsers (7 ecosystems, binaries, walk) | ~2,480 | 4 | 1.5 |
| 7 | rootfs, docker-image (registry, tarball, OCI), docker-engine and its transports | ~3,010 | 5 | 2 |
| 8 | macOS + Homebrew | ~1,210 | 2 | 0.5 |
| 9 | SSH (OpenSSH + russh), harvest, safe extraction | ~1,250 | 3 | 1 |
| 10 | Windows (script JSON, osquery, live registry) | ~870 | 2 | 0.5 |
| 11 | Process monitor (core, macOS backend, watch, procmon views) | ~2,280 | 3.5 | 1 |
| 12 | Reports, ops, discover, CLI (exit codes, formats, `_t`/`_e` escaping) | ~2,600 | 3.5 | 1.5 |
| 13 | Web server (routes, Host check, CSRF header, static embed) | ~1,020 | 1.5 | 0.5 |
| 14 | Tests: port the 739 test functions (most become table-driven fixture tests) | 12,300 | 5 | 2 |
| 15 | CI matrix (3 OS), release (musl static, macOS universal, Windows), docs rewrite | — | 2 | 1 |
| | **Subtotal: same features, SQLite** | **~20,300** | **~49** (range 42–55) | **~17.5** of work, in parallel streams **9–13 weeks** |
| 16 | PostgreSQL + MySQL backends, migrations, conformance suite, concurrency hardening | | 5–7 | 2–3 |
| 17 | Tauri desktop app (all three in one process) | | 3–5 | 1.5–2 |
| | **Total, single node** | | **~57–61** (range 50–67) | **~3.5–4.5 months** |
| 18 | Protocol: envelope, framing, both method catalogs, JSON Schemas, `hello` and capabilities, conformance suite over every binding | | 2.5 | 1 |
| 19 | Probe: `secmonk-probe` binary, dispatch, allowlist, discovery, watch stream, spool, privileged helper, cross builds | | 3 | 1.5 |
| 20 | Engine service: probe registry, job routing, several jobs + cancellation, idempotent ingest, classification on ingest | | 2.5 | 1 |
| 21 | Transports, first tier: in-process, child stdio, SSH stdio (push, forced command, harvest fallback), TLS/WebSocket dial-out | | 3 | 1.5 |
| 22 | Security: identities, engine CA, enrollment tokens and pinning, mTLS, UI authentication and roles, audit, compromise tests | | 3 | 1.5 |
| 23 | Federation in the desktop UI: engine connections, credentials in the keychain, merged views, asset namespacing, stories and mock | | 3 | 1.5 |
| 24 | Probe packaging and distribution: signing on 3 OSes, systemd / launchd / Windows service, signed self-update | | 2 | 1 |
| | **Total with the distributed core** | | **~76–80** (range 67–88) | **~5–6 months** |
| 25 | Overlay: OS client documented and tested (0.5); embedded via `libtailscale` or a `tsnet` sidecar (+2) | | 0.5–2.5 | 0.5–1 |
| 26 | RDP dynamic virtual channel: Windows probe side, client plugin, tests on real Windows | | 3–4 | 1.5–2 |
| | **Total, everything** | | **~80–87** | **~6–7 months** |
| 27 | Python module host ([§9](#9-mixed-rustpython-python-as-the-fast-lane)): manifests, stdio adapter, pinned uv + signed offline bundles, Python `safeio` package, process limits | | 2.5 | 1 |

The full-port numbers assume a feature freeze on the Python side, or that every Python change is mirrored; without a
freeze, add about 20%. Packages 18–24 cost about the same in Python (except the probe binary, 19 and 24), which is why
the recommended path starts them there.

**Strangler sequencing** ([§9.6](#96-strangler-migration)). The same packages, reordered: the Rust host first, every
other module running as a Python module until it is worth porting.

| Plan | In Rust before the first distributed release | Person-weeks | With agents | Afterwards |
|---|---|---:|---:|---|
| Full port | everything (0–24) | ~76–80 | ~5–6 months | — |
| **Strangler** (recommended) | 0–4, 6, the rootfs part of 7, the engine part of 12, 13–15 for those, 17, 18–24, 27 | **~50–54** | **~3.5–4 months** | ~22 pw of modules ported by value (5, rest of 7, 8–11, rest of 12 and 14), 5 possibly never; 16 when a server needs it |

- **Saves**: about 25 person-weeks and 1.5–2 months to the first distributed release; no feature freeze, since new
  features and unported modules keep moving in Python; modules that never earn a port (sources) are never ported.
- **Costs**: the module host (+2.5 pw); the total if everything is eventually ported is ~78–84 pw, a few weeks above
  the full port; while both languages live, about 10–15% of feature work goes to two toolchains, two CI setups and the
  differential runs (estimate); the desktop app ships uv and an interpreter (+~100 MB **(verify)**) until its modules are
  ported; Python modules on remote hosts need a runtime there, so agentless hosts rely on the Rust probe or on harvests.

## 13. Risks

| Risk | Effect | How to reduce it |
|---|---|---|
| Version comparison differs from univers | **False negatives** (missed vulnerabilities) that look like normal output | Differential tests on every version pair in a synced OSV mirror (millions of `(version, range)` checks against Python univers), plus property tests (ordering is transitive and antisymmetric). Block the release until there are 0 differences, or every difference is explained. |
| Parser drift (lockfiles, binaries, dpkg/rpm/apk) | Missing or wrong components | Golden tests: Python and Rust run on every fixture, and the inventory JSON must match after normalization. |
| Safety helpers lost in translation | Path escape or decompression bombs from untrusted targets | Port `read_within`/`resolve_within` first as `secmonk-safeio`; fuzz the tar/zip/plist/lockfile parsers with `cargo-fuzz`. |
| The protocol is frozen too early, or never | Every probe in the field pins the engine's evolution; or every release breaks probes | Freeze after the Python implementation has run topology (b) on real hosts; additive minors only; the engine supports the previous major. |
| Remote collection becomes an attack tool | A compromised engine moves laterally through the SSH keys and probes it holds | No "execute" method, allowlists held by the probes, forced-command SSH keys, release-signed binaries, audit log ([§6](#6-security-model)). |
| Pushing a binary breaks the agentless promise | Users who chose SSH because nothing is written on the target | Push is opt-in per host and decided in an ADR; harvest stays the default fallback. |
| Rust is weak on overlays and RDP | Embedded overlay drags the Go runtime into the build; RDP needs a client plugin | OS overlay clients first; embedded overlay and RDP only on request; reconsider Go if they become core. |
| PKI and fleet operations | Enrollment, revocation, certificate expiry, probe upgrades: a product of its own | Keep the engine CA minimal (one CA per engine, long-lived probe certificates with revocation list); no fleet management beyond list / revoke / upgrade. |
| The prototype is still moving | Porting a moving target doubles the work | 138 open items in [plans/](../plans/README.md) are still unverified on real macOS, Windows and Docker. Port each module after its platform plan is mostly done. |
| Async spreads through the code | Harder code, slower port | Keep the collectors and the engine synchronous (`rayon` for parallel parsing). Use `tokio` only in `rpc`, `transport`, the HTTP client and server, behind small adapters. |
| Few contributors know Rust | Bus factor, slower review | Rust is harder to review than Python or Go. Factor this into the stack choice ([§14](#14-other-compiled-stacks)). |
| Two languages for a long time | Two toolchains, two CI setups, contributors need both; the strangler never finishes | Port by value with a written order; each module has one production binding and keeps two only for one release ([§9.4](#94-lifecycle-of-a-module)). |
| Drift between bindings | A Python and a Rust module disagree silently, or a fix lands in one only | The differential harness runs on every change to either binding; the manifest names the one production runtime. |
| No Python runtime on hosts | Python modules cannot run on locked-down or minimal targets | Run them engine-side on harvests; the Rust probe covers live facts; Python on targets only opt-in. |
| Three databases | Every query tested three times; MySQL quirks (index length, collation, JSON) | Support PostgreSQL first; add MySQL only if a user asks for it. |

## 14. Other compiled stacks

| | **Rust** | **Go** | **C# / .NET 9 (Native AOT)** | **Kotlin/Java + GraalVM native** |
|---|---|---|---|---|
| Port effort, single node (same features + 3 DBs + desktop) | ~57–61 pw | **~35–40 pw** | ~50–56 pw | ~57–64 pw |
| With the distributed core | ~76–80 pw | **~50–56 pw** | ~68–74 pw | ~76–83 pw |
| Version schemes | Mostly written by us | **osv-scalibr `semantic`**: OSV-maintained, every OSV ecosystem | Written by us | Maven exact (`ComparableVersion`); rest written by us |
| Ecosystem extractors to reuse | some (`auditable-info`, `cargo-lock`) | **osv-scalibr** extractors (lockfiles, dpkg/rpm/apk, Go/Java binaries), `packageurl-go`, Syft as a library | few | few (CycloneDX libraries) |
| Images / registry | written by us on `reqwest` (`oci-client` exists) **(verify)** | **go-containerregistry** | written by us | jib-core |
| SSH client (and server for tests) | russh / libssh2 | **x/crypto/ssh** + `ssh_config` libraries | SSH.NET | sshj / Apache MINA |
| RPC over any stream, gRPC | written by us on `serde`; `tonic` | written by us; **`grpc-go`, `connect-go`** | written by us; `Grpc.Net` | written by us; `grpc-java` |
| Embedded overlay | `libtailscale` (Go runtime via C) **(verify)**, `boringtun` | **`tsnet`, native** | none | none |
| RDP virtual channel | `windows` crate; IronRDP **(verify)** | Win32 syscalls; no RDP stack | **best Win32 interop** | weak |
| Several DBs | sqlx + sea-query (good) | database/sql + sqlc or goqu (good); pure-Go SQLite (modernc) | **EF Core** (best of all) | jOOQ / Exposed (very good) |
| Desktop app with the Vue front end | **Tauri** | **Wails** | Photino / WebView2 (Windows first) | JCEF / webview bindings (weak) |
| Static single binary, cross-compiling | good (musl; macOS signing) | **best** (`CGO_ENABLED=0`; `tsnet` keeps it) | good, but AOT limits reflection and serializers | slow builds, reflection configuration |
| Memory safety on untrusted input (the probe) | **best** (no nil, strict types, fuzzing tools) | good (GC, bounds checks; nil and races are possible) | good | good |
| Size / memory | **smallest** | small | medium | medium-large |
| Speed of writing, ease of hiring | slowest | **fastest** | fast | medium |
| Matches the existing tools | — | **Syft, Grype, Trivy, osv-scanner, osv-scalibr are all Go** ([ADR-0001](../decisions/0001-language-python-uv-mise.md) already named Go as the fallback) | — | Dependency-Track is Java |

Go, .NET and JVM numbers are the 2026-11-08 estimates scaled by the growth of the code since (+20%) plus the
distributed core with each ecosystem's libraries; they were not built bottom-up.

Reading the table:

- **Go is the cheapest and lowest-risk compiled target**, and the distributed mode widens the gap: SSH, gRPC/Connect
  and an embeddable Tailscale are first-class Go libraries. The hardest parts of the port (version semantics,
  extractors, registry) already exist as maintained Apache-2.0 libraries that OSV's own scanner uses, so the univers
  risk largely goes away. Wails keeps the Vue app. Cost: a bigger binary than Rust, fewer compile-time guarantees, and
  a weaker desktop story than Tauri.
- **Rust** is the right choice if the product's centre of gravity is the **desktop app plus a probe running on
  untrusted hosts**, where a small footprint and memory safety come first, and if the team can write and review
  Rust for the long term.
- **Rust probe + Go engine** becomes possible with the contracts, with nothing duplicated (versions and matching live
  only in the engine); the cost is two compiled toolchains. Worth a look in the spike, not as the default.
- **.NET** is worth a look only if Windows endpoints and enterprise databases are the main market (EF Core, WMI,
  registry and WTS APIs, MSI packaging). Otherwise it brings neither ecosystem reuse nor desktop advantages.
- **JVM/GraalVM**: not recommended (native-image friction, weak desktop webview).
- **Mixed (Rust core via PyO3, Python on top)**: the hot paths gain speed but nothing becomes easier to distribute and
  the build gets more complex. Not recommended; the scanner is I/O bound today. Python modules as **subprocesses under
  a compiled host** ([§9](#9-mixed-rustpython-python-as-the-fast-lane)) are a different thing and are recommended.
- **Effect of the strangler on the choice**: it takes the port off the critical path, so Go's main advantage (porting
  speed, reusable extractors) weighs less, while the host's qualities (static probe, Tauri, memory safety) weigh more:
  this tilts towards Rust. The subprocess module design works the same under a Go host, so it does not decide by
  itself; Go keeps its lead on overlays and networking.

## 15. Recommended path

A strangler migration ([§9.6](#96-strangler-migration)): new features and spikes start as Python modules, working end
to end; the Rust host comes early; modules move to Rust by value.

1. **Now, in Python (2–3 weeks): make the boundaries real.** Write JSON Schemas for inventory, snapshot and payloads,
   record reference outputs on every fixture, split the mirror from the inventory in `db.py`. Move classification out
   of `ops.collect` to the engine side, add an `Inventory` reader and an ingest command for what `collect -O` writes,
   and route `ops.scan_target` through a probe interface (in-process). Useful whatever the language.
2. **Protocol and module side in Python (2–3 weeks).** The envelope, both catalogs (the HTTP binding equal to today's
   `/api/`), `secmonk probe serve --stdio`, and `secmonk module serve <name> --stdio` exposing today's collectors,
   sources and tools as modules with manifests. The conformance and differential suites written here are reused by
   every later step.
3. **Decide Rust or Go with a two-week spike.** `versions` + OSV ranges + the `osv-package` matcher in both languages
   against a full OSV mirror; the framed protocol over `ssh … serve --stdio`; a Python module launched offline through
   the pinned uv; `libtailscale` against `tsnet`.
4. **Rust host.** Engine core (versions, store, match, scoring: not pluggable), engine service, HTTP binding, module
   registry with the stdio adapter and uv bundles; every collector and source still runs as a Python module. The Tauri
   app on top (standalone, topology a). A Tauri shell with a Python sidecar ([§11.2](#112-desktop-app-without-porting-first-tauri-shell--python-sidecar))
   is worth doing first only if a signed app is needed before this step.
5. **Probe binary.** `safeio`, `lang`, `rootfs`, `fs` and the probe service as `secmonk-probe`, reached over **SSH
   stdio** (forced command; push once its ADR is accepted). Harvest stays the fallback, with Python modules run
   engine-side on the harvested tree.
6. **Transports and security by priority:** TLS dial-out probes with enrollment (c), headless server with
   authentication and roles (d). Then **federation** in the desktop UI (e).
7. **Port the remaining modules by value** ([§9.4](#94-lifecycle-of-a-module)): process backends, image layers,
   macOS/Homebrew, Windows; sources last or never.
8. **PostgreSQL** when a headless engine needs it, **MySQL** if someone asks for it.
9. **Overlay and RDP last**: OS overlay clients are documented from step 6; embedded overlay and RDP channels only on
   request.

At each step the Python and compiled implementations share the database schema and the JSON contracts, so the port can
stop at any step and still leave something that works.

## Open questions

- Who are the target users: a single analyst's laptop (standalone), a team with a central server, or a service
  provider running engines for several customers? The answer sets the order of steps 4, 6 and 8.
- Who operates the engines, and are engines **multi-tenant**? This proposal assumes one engine per tenant and network;
  a multi-tenant engine needs tenant ids in the store and the roles.
- Which transports first? Proposed: in-process, SSH stdio, TLS dial-out. Is RDP a real requirement, and for whom? Must
  the overlay be embedded, or is an installed Tailscale / WireGuard client acceptable on both ends?
- May sec-monk write a probe binary to a target over SSH (push), or must SSH stay strictly write-free?
- Federation in the browser UI too, or only in the desktop app (a browser cannot hold credentials to several engines
  without an aggregating server)?
- How do users authenticate to a remote engine: local accounts and tokens, client certificates, or OIDC?
- Mixed Rust/Python: may the desktop app ship uv and a Python interpreter (about 100 MB) until its modules are ported?
  May Python modules ever run on targets (opt-in, like the binary push), or only engine-side?
- Does a ported module's Python binding stay as a maintained fallback (for example for platforms without a Rust build),
  or is it retired after one release?
- Which modules are never worth porting? Proposed: the vulnerability sources.
- Is MySQL a real requirement, or would PostgreSQL be enough? MySQL support costs about 2 of the 5–7 database weeks.
- Who will maintain the code long term, and in which language? This weighs more than any line in [§14](#14-other-compiled-stacks).
- Licensing: osv-scalibr and go-containerregistry are Apache-2.0; Tailscale's client libraries are BSD-3-Clause
  **(verify)**. Confirm this fits the planned distribution.

If accepted: an ADR for the three-component architecture and the wire protocol; an ADR for probe push over SSH
(amends the agentless rule of the SSH collector); an ADR for the distributed security model and enrollment; an ADR that
supersedes [ADR-0001](../decisions/0001-language-python-uv-mise.md) for the chosen language; an ADR for the storage
abstraction (amending [ADR-0004](../decisions/0004-sqlite-schema-v2.md)); an amendment of
[ADR-0006](../decisions/0006-per-user-state-locations.md) for service-installed probes and engines; an ADR for the
desktop app; and a `plans/port-*.md` checklist per step of [§15](#15-recommended-path).
