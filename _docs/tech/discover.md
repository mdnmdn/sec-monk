---
title: Host discovery (host auto mode)
summary: How `discover_host` probes this machine or an SSH target and proposes scan candidates (collector, target, options, availability, default tick) - candidate ids, probes, time bounds and redaction.
read_when: you change what host auto mode proposes, add a candidate, or change how a host is probed before a batch scan
type: tech
context: tech
status: implemented
tags: [discover, auto-mode, ssh, docker, batch]
updated: 2026-11-11
verified: 2026-11-11
sample: synthetic
code: [src/secmonk/discover.py]
related: [tech/collectors/ssh.md, tech/collectors/docker-engine.md, tech/collectors/process.md, tech/collectors/macos.md, tech/architecture.md]
---

# Host discovery (host auto mode)

## What it is

`secmonk.discover.discover_host(target=None, **opts) -> dict` looks at one host and returns what can be scanned
there, as a list of *candidates* the CLI, the web API and the UI show as a checkbox panel and turn into a batch of
ordinary scans. It is not a collector: it never collects, saves or matches. `target` `None`, `""`, `"local"` or
`"localhost"` means this machine; anything else is an SSH target parsed like the SSH collector's
(`[ssh://][user@]host[:port]`).

Result: `{"host": {...}, "candidates": [...], "warnings": [...]}`.

- `host`: `kind` (`local` | `ssh`), `target` (None locally; `[user@]host[:port]`, never a password), `name`, `os`
  (`macos` | `linux` | `windows` | `unknown`), `os_version`, `arch`.
- candidate: `id`, `collector` (registered name), `target`, `options` (`k=v` strings, as `-o`), `label`,
  `description`, `available`, `reason` (why unavailable, or a caveat), `selected` (default tick, never true when
  unavailable), `details` (small dict).

## Rules / model

Candidate ids are a contract with the CLI and the UI:

| id | collector / target | proposed when | ticked |
|---|---|---|---|
| `macos` | `macos`, None | local macOS | yes; caveat when Full Disk Access is missing (probe: list `/Library/Application Support/com.apple.TCC`) |
| `rootfs` | `rootfs`, `/` | local Linux | yes; `details.package_managers` from the dpkg/rpm/apk/pacman databases present |
| `homebrew` | `homebrew`, None | a prefix exists (`homebrew.find_prefixes`) | macOS: no (the `macos` scan already reads Homebrew); Linux: yes (rootfs does not read Linuxbrew) |
| `windows` | `windows`, None | local Windows | unavailable: needs the JSON of `secmonk windows-script` |
| `process` | `process`, None | always | when `collectors/process/backend.BACKENDS` has the platform; over ssh: unavailable ("processes are only collected locally") |
| `fs-home` | `fs`, home folder, `binaries=false` | home folder exists | no (walks the whole home; `fs` has no exclude option) |
| `ssh` | `ssh`, `[user@]host[:port]`, ssh options | SSH target | yes, unless the remote OS is not recognised |
| `docker` | `docker-engine`, `*` | an engine answers, or one is configured / found but down | when at least one container runs |
| `docker-images` | `docker-engine`, `image:*` | same as `docker` | no; each image Id is scanned once (aliases folded) |

Probes:

- **Docker** (`_docker_probe`): `docker_engine.find_endpoint` with the caller's `context` / `host` / `socket`
  plus `tls_ca`, `tls_cert`, `tls_key`, `tls_verify` and the ssh options (or `host=ssh://<target>` remotely), then
  `/_ping`, `/containers/json?all=0` and `/images/json` with a short timeout (`probe_timeout`, default 5 s; over ssh
  at least `connect_timeout` + 5 s, since every request starts ssh, authenticates and starts `dial-stdio`). Those
  options and `timeout` are copied into the docker candidates' options. "Socket not found" means no candidate; a socket that refuses, a missing
  context, a permission error or a failed ping give an unavailable candidate whose reason is the error. The
  candidate's options pin the engine that answered (`socket=`, `context=` or `host=`), plus the ssh options
  docker-engine understands (`identity`, `known_hosts`, `insecure_host_key`, `connect_timeout`, `ssh_option`,
  `ssh_bin`). Up to 50 containers / images are listed in `details`, names and tags truncated.
- **SSH**: one remote command through the SSH collector's transport (`make_transport`, or an injected `Transport`):
  `sh -s` fed `harvest.detect_script("/")` (the SSH collector's OS detection, parsed by `harvest.parse_detect`)
  followed by a fixed tool check: `command -v` for `docker podman brew dpkg rpm apk pacman` and `[ -d <prefix>/Cellar ]`
  for the three Homebrew prefixes, and `[ -x ]` for the docker CLIs a non-interactive macOS shell does not have on
  PATH (`/usr/local/bin`, `/opt/homebrew/bin`, Docker.app); one found only there is used through the docker-engine
  option `remote_docker`. Output is capped at 64 KiB; only known tool names and prefixes are accepted.
  Unrecognised output tries the SSH collector's Windows check (`SSHCollector._is_windows`), else a warning. The
  remote engine is then probed over `ssh://` (`docker system dial-stdio`) only when `docker` exists remotely;
  podman alone gives an unavailable `docker` candidate.
- The ssh options `identity`, `known_hosts`, `insecure_host_key`, `connect_timeout`, `ssh_option`, `transport` (when
  a string) are copied into the `ssh` candidate's options; values with newlines are dropped.

Errors: a failing probe becomes `available=false` + `reason`, or a warning. Only the SSH target itself raises:
`ValueError` for an unparsable target (passwords are never echoed), `RuntimeError` when ssh cannot reach it (exit
255 / no output, with ssh's stderr) or the probe times out (60 s).

Kubernetes (`k8s://<context>`, `k8s://` = current context; options `kubeconfig`, `namespace`, `timeout`,
`kubectl`): one `k8s.probe_cluster` through kubectl (see [k8s collector](collectors/k8s.md)). Host: `kind: k8s`,
`name` = cluster, `os` None, plus `context`, `server` (no credentials), `kubernetes_version`, `distro`, `access`,
and `other_contexts` (+ a warning) when the current context was used and the kubeconfig has others. Candidates:

| id | collector / target | ticked |
|---|---|---|
| `k8s-cluster` | `k8s`, `k8s://<context>`, options kubeconfig/namespace/timeout/kubectl | yes; reason `partial access: could not read …` when RBAC refused something |
| `k8s-images` | `docker-image`, comma list of refs (one `repo@sha256:` per digest the kubelet reported, else the tag), options `source=registry` (never a local path) and `platform=` when all nodes share one | when 1-50 images; unavailable when pods are not readable |
| `k8s-images-private` | the same for refs whose registry is localhost or a private / link-local IP | never (a pull would reach that address from this machine) |
| `k8s-images-<namespace>` | the same, one namespace's images | no; only when 2-10 namespaces have pods |

kubectl missing, the API server unreachable, or nothing readable raise (`ValueError` / `RuntimeError`), as for ssh.

Partial access everywhere: a Docker engine that answers but refuses the container or image listing (authorization
plugin) gives that one candidate `available=false` with the engine's reason; the other candidates stay.

## Limitations

- Local Docker probing reads `~/.docker` (contexts) and sockets; on macOS a sandboxed shell may not see them and then
  proposes no Docker candidate.
- `fs-home` cannot exclude `Library`, caches or `node_modules`: the `fs` collector has no exclude option.
- A Linuxbrew prefix in `~/.linuxbrew` of a remote user is not probed (the SSH harvest reads it).
- Docker over ssh always uses the system ssh, even with `transport=paramiko` (a warning says so).

## Related docs

[ssh collector](collectors/ssh.md), [docker-engine collector](collectors/docker-engine.md),
[process collector](collectors/process.md), [macOS collector](collectors/macos.md).
