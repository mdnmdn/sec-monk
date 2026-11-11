---
title: Plan - on a Linux host with Docker/Podman and an SSH-reachable server
summary: Checklist for a Linux host with Docker or Podman and an SSH server to verify the docker-engine, docker-image, rootfs and SSH collectors and the Linux process backend.
read_when: you are on Linux with Docker, Podman or an SSH server and want to verify those collectors against real systems
type: plan
context: plans
status: open
platform: linux
tags: [plan, linux, docker, podman, ssh, rootfs]
updated: 2026-11-11
verified: 2026-11-11
related: [tech/collectors/docker-engine.md, tech/collectors/docker-image.md, tech/collectors/rootfs.md, tech/collectors/ssh.md, tech/collectors/process.md, decisions/0010-remote-process-snapshot.md, features/inventory-docker.md, features/inventory-ssh.md, features/process-monitor.md]
---

# Plan: what to do on a Linux host with Docker/Podman (+ one SSH-reachable Linux server)

The dev sandbox had no Docker daemon, no sshd, and a restrictive proxy. You need: a Linux machine with Docker >= 25
(containerd image store on and off if possible) **and/or** Podman, internet access to pull images, and a second Linux box (VM is fine)
with OpenSSH server, a normal user, and `sudo NOPASSWD` for one test. Optional: an Alpine VM/container with sshd (busybox), a CentOS 7 /
SLES 12 image (BerkeleyDB rpm).

```bash
git clone <repo> sec-monk && cd sec-monk && uv sync
uv run pytest -q                      # baseline
uv run secmonk sync osv -e Debian -e Alpine -e Ubuntu -e "Rocky Linux" -e PyPI -e npm --db /tmp/lx.db   # see on-open-network.md for sizes
```

Fixtures go to `tests/fixtures/collectors/docker/real/` and `tests/fixtures/collectors/ssh/real/`; flip the doc's `sample:` afterwards.

## A. docker-engine collector against a real engine (currently only a fake socket)

- [ ] **Docker Engine (rootful), containerd image store OFF (classic overlay2).**
  ```bash
  docker run -d --name web nginx:1.25; docker run -d --name pg -e POSTGRES_PASSWORD=x postgres:16; docker create --name stopped alpine:3.19 true
  uv run secmonk containers --db /tmp/lx.db
  uv run secmonk scan docker-engine web --db /tmp/lx.db
  uv run secmonk scan docker-engine image:nginx:1.25 --db /tmp/lx.db
  curl --unix-socket /var/run/docker.sock http://localhost/containers/json?all=1 | jq '.[0]|keys' > /tmp/real-containers-keys.json
  ```
  Verify: container list = `docker ps -a`; asset `container:web` meta (`container_id, image, image_id, labels, state, privileged, published_ports, user, engine`)
  populated; OS packages equal `docker exec web dpkg -l | wc -l`; runtime-installed deps appear (`docker exec web pip install requests` then rescan on a python container).
  Compare real JSON key sets with the synthetic fixtures `containers-json.json`, `version.json`; replace them with trimmed real ones. Update
  [docker-engine.md](../tech/collectors/docker-engine.md) `sample:` and the "never run against a real engine" sentence.
- [ ] **Docker >= 25 with the containerd image store** (`/etc/docker/daemon.json`: `{"features":{"containerd-snapshotter":true}}`).
  ```bash
  docker save nginx:1.25 -o /tmp/nginx-oci.tar && tar tf /tmp/nginx-oci.tar | head      # expect index.json + blobs/ + manifest.json
  uv run secmonk scan docker-engine image:nginx:1.25 --db /tmp/lx.db
  uv run secmonk scan docker-image /tmp/nginx-oci.tar --db /tmp/lx.db
  ```
  Verify: both layouts work; `Id` = manifest digest semantics do not break dedupe; multi-platform image (e.g. `docker pull --platform linux/arm64 alpine:3.20`)
  selects the right platform or fails with a clear message (`?platform=` needs API >= 1.48). Save the OCI-layout tar's `index.json`/`manifest.json` as fixture.
- [ ] **Stopped container whose image was deleted** (`Image` is a bare sha256 -> `/images/{id}/get` 404 -> fallback `/containers/{id}/export`).
  ```bash
  docker create --name orphan alpine:3.19 true && docker rmi -f alpine:3.19
  uv run secmonk scan docker-engine orphan --db /tmp/lx.db
  ```
  Verify: falls back to export, asset has digest-less identity, no traceback. Add a test with the observed JSON.
- [ ] **Podman rootless and rootful** (Docker-compatible API; `libpod` differences: names without slash, `Digest`).
  ```bash
  systemctl --user enable --now podman.socket; podman run -d --name pweb nginx:1.25
  uv run secmonk containers --socket $XDG_RUNTIME_DIR/podman/podman.sock
  uv run secmonk scan docker-engine pweb --socket $XDG_RUNTIME_DIR/podman/podman.sock
  ```
  Verify: container list and export work; `Image` resolves; report quirks in docker-engine.md. Also test `DOCKER_HOST=tcp://127.0.0.1:2375` (plain http).
- [ ] **Remote engine over `ssh://` (`docker system dial-stdio`)**, from this host to the SSH-reachable server with Docker
  installed and the ssh user in its `docker` group (only tested with a fake `ssh` and a Python stand-in on pipes).
  ```bash
  uv run secmonk containers --db /tmp/lx.db        # after: export DOCKER_HOST=ssh://<user>@<server>
  uv run secmonk scan docker-engine 'web,re:^pg' -o host=ssh://<user>@<server> --db /tmp/lx.db
  uv run secmonk scan docker-engine web -o host=ssh://<user>@<server>:2222 -o identity=~/.ssh/id_ed25519 --db /tmp/lx.db
  docker context create remote --docker host=ssh://<user>@<server>; uv run secmonk scan docker-engine web -o context=remote --db /tmp/lx.db
  ```
  Verify: assets are `container:<server>/web` (`:<port>` only when not 22), meta `engine` has no user; a large `/export`
  streams through ssh at a sane speed; the ssh process is gone after the scan (`pgrep -f dial-stdio` on both sides);
  failures are readable: unknown host key (BatchMode), no `docker` on the remote PATH (`(ssh: ... command not found)`),
  user not in the `docker` group (permission denied on the remote socket). Assumed, unverified: `docker system
  dial-stdio` exists on the remote CLI (Docker >= 18.09) and Podman's `docker` shim does not provide it.
- [ ] **tcp + TLS engine** (dockerd `--tlsverify --tlscacert --tlscert --tlskey -H tcp://0.0.0.0:2376`, certs per the
  Docker "Protect the daemon socket" guide). Tested only against a loopback Python HTTPS server with throwaway certs.
  ```bash
  DOCKER_HOST=tcp://<server>:2376 DOCKER_TLS_VERIFY=1 DOCKER_CERT_PATH=~/certs uv run secmonk containers
  uv run secmonk scan docker-engine web -o host=tcp://<server> -o tls_ca=ca.pem -o tls_cert=cert.pem -o tls_key=key.pem --db /tmp/lx.db
  docker context create tls --docker "host=tcp://<server>:2376,ca=ca.pem,cert=cert.pem,key=key.pem"; uv run secmonk containers -o context=tls
  ```
  Verify: default port 2376 when TLS is on; a wrong CA fails with a certificate error, `tls_verify=false` connects;
  the context's TLS files are found under `~/.docker/contexts/tls/<sha256>/docker/`; asset `container:<server>:2376/web`.
- [ ] **Local images by Id and image selectors** (only tested with a fake engine client, 2026-11-11).
  ```bash
  docker pull nginx:1.25 && docker tag nginx:1.25 myreg.example.test/nginx:prod
  uv run secmonk scan docker-engine 'image:nginx:1.25,image:myreg.example.test/nginx:prod' --db /tmp/lx.db   # one scan
  uv run secmonk scan docker-engine 'image:*' --db /tmp/lx.db
  docker pull nginx:latest   # after a new release: the tag moves
  ```
  Verify: assumed, unverified: `GET /images/sha256:<Id>/get` exports exactly that image on the classic and the
  containerd image store (Docker >= 25: `Id` is the manifest/index digest; check that the save of an index Id carries
  one platform and the scan reads it); Podman returns `Id` with `sha256:` in the compat API; `RepoTags` of dangling
  images is `[]` or `["<none>:<none>"]`. Asset is `image:@<Id>` with all tags in meta; a moved tag yields a new asset.
  Check `meta.id_verified` is true on both stores (classic: config digest = Id; containerd: Id = the index or manifest
  digest and that blob is inside the `docker save` output - assumed, unverified).
- [ ] **Host auto mode on Linux** (`secmonk.discover.discover_host`, tested only with fakes): run it locally on
  Debian/Fedora/Alpine and against the SSH server (`discover_host("<user>@<server>")`). Verify: `rootfs` lists the right
  package manager, `process` is unavailable (no Linux backend), `homebrew` appears only with Linuxbrew, the remote probe
  detects `docker` and the `docker` candidate becomes unavailable with a readable reason when the ssh user is not in
  the `docker` group.
- [ ] **Colima/Lima on Linux or `rootless docker`** socket discovery: `docker context ls; ls $XDG_RUNTIME_DIR/docker.sock`. Mac variants are in [on-macos.md](on-macos.md) section D.
- [ ] **Running container export consistency and size** (`/export` of a busy container is not a snapshot; big FS).
  ```bash
  docker run -d --name big -v /tmp/bigdata:/data ubuntu:24.04 sleep 3600
  /usr/bin/time -v uv run secmonk scan docker-engine big --db /tmp/lx.db 2>&1 | grep -E 'Maximum resident|Elapsed'
  ```
  Verify: peak RSS small (streamed through `LayeredTarView`, nothing on disk), size cap respected with a warning. Record in [engine-and-quality.md](engine-and-quality.md) performance table, not here.

## B. docker-image collector: `docker save` tars and layers

- [ ] **Real multi-layer images and whiteouts** (spec-based so far; base images have a single layer).
  ```bash
  cat > /tmp/Dockerfile.wh <<'D'
  FROM debian:12-slim
  RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
  RUN apt-get purge -y curl && apt-get autoremove -y
  RUN rm -rf /usr/lib/python3* ; mkdir /usr/lib/python3 && echo x > /usr/lib/python3/file
  D
  docker build -f /tmp/Dockerfile.wh -t wh-test /tmp && docker save wh-test -o /tmp/wh-test.tar
  uv run secmonk scan docker-image /tmp/wh-test.tar --db /tmp/lx.db
  docker run --rm wh-test dpkg -l | awk 'NR>5{print $2,$3}' | sort > /tmp/dpkg-real.txt
  uv run secmonk inventory show <asset> --category package | sort > /tmp/dpkg-secmonk.txt
  ```
  Verify: purged `curl` is absent (whiteout/opaque dir honoured); package set == `dpkg -l`; the "directory replaced by a regular file" case documented in
  [rootfs.md](../tech/collectors/rootfs.md) Limitations - decide whether to fix. Keep the (small) saved tar under `tests/fixtures/collectors/docker/real/`.
- [ ] **`docker save` output of Docker >= 25 vs real registry pull equality.**
  ```bash
  uv run secmonk scan docker-image debian:12-slim --db /tmp/a.db; docker pull debian:12-slim && docker save debian:12-slim -o /tmp/d12.tar && uv run secmonk scan docker-image /tmp/d12.tar --db /tmp/b.db
  diff <(sqlite3 /tmp/a.db "select purl from component order by 1") <(sqlite3 /tmp/b.db "select purl from component order by 1")
  ```
  Verify: no diff. Also `scan docker-image ghcr.io/<org>/<small-image>` and `quay.io/...`, `registry.access.redhat.com/ubi9/ubi-minimal` (blocked in the sandbox).
- [ ] **zstd layers.**
  ```bash
  docker buildx build --output type=image,name=localhost:5000/zst,compression=zstd,push=true -t localhost:5000/zst - <<< $'FROM alpine:3.20\nRUN apk add curl'   # needs a local registry:2
  uv run secmonk scan docker-image localhost:5000/zst --db /tmp/lx.db
  ```
  Verify: `zstandard` is already a declared dependency in `pyproject.toml`, so the layer must be read fully (not skipped with the "zstd needs ..." warning); also test a venv without it to confirm the warning path. Save the small zstd image tar as fixture.
- [ ] **rpm BerkeleyDB / ndb unsupported.**
  ```bash
  uv run secmonk scan docker-image centos:7 --db /tmp/lx.db        # BDB: /var/lib/rpm/Packages
  uv run secmonk scan docker-image registry.suse.com/suse/sles12sp5 --db /tmp/lx.db   # ndb Packages.db (if reachable)
  uv run secmonk scan docker-image rockylinux:9 --db /tmp/lx.db    # sqlite rpmdb.sqlite must work
  uv run secmonk scan docker-image fedora:40 --db /tmp/lx.db; uv run secmonk scan docker-image almalinux:9-minimal --db /tmp/lx.db
  ```
  Verify: sqlite rpmdb gives `rpm -qa | wc -l` equal packages (check epoch/arch/`distro` qualifier); BDB/NDB yield an explicit warning "rpm DB format unsupported", never an
  empty silent result. Decide if BDB parsing (`Packages` hash/btree) is worth it -> [engine-and-quality.md](engine-and-quality.md) if yes.
- [ ] **Private registry auth (not supported beyond inline `auths`).**
  ```bash
  docker run -d -p 5001:5000 --name reg -v /tmp/htpasswd:/auth -e REGISTRY_AUTH=htpasswd -e REGISTRY_AUTH_HTPASSWD_REALM=r -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd registry:2
  SECMONK_REGISTRY_PASSWORD=pw uv run secmonk scan docker-image localhost:5001/app:1 -o username=u --db /tmp/lx.db
  ```
  Verify: Basic fallback works; `credsStore`/`credHelpers` in `~/.docker/config.json` give a clear "unsupported" message (decide: implement `docker-credential-*` helpers).
  Also GHCR token and ECR (`aws ecr get-login-password`) as manual `username/password`.
- [ ] **Docker Hub anonymous rate limit (429) and retry/backoff** (`Retry-After`, max 4) - provoke with ~100 pulls of small manifests, or `curl -I` the rate-limit headers.
  Verify the `mirror.gcr.io` hint message appears.
- [ ] **Performance on big images** (CUDA/PyTorch 5+ GB, `ubuntu` + node + python mix, 50+ layers).
  ```bash
  /usr/bin/time -v uv run secmonk scan docker-image pytorch/pytorch:2.4.0-cuda12.1-cudnn9-runtime --db /tmp/lx.db 2>&1 | egrep 'Elapsed|Maximum resident'
  ```
  Verify: `max_layer_bytes` (4 GiB) behaviour, blob cache dir size, memory flat. Record numbers in [engine-and-quality.md](engine-and-quality.md) (Performance); only fix bugs here.
- [ ] **Binaries not owned by packages** (curl'd binaries, `/usr/local/bin`, Go/Rust static): scan `golang:1.22` (CPython-from-source + GOPATH cases belong to [engine-and-quality.md](engine-and-quality.md)),
  `grafana/grafana`, `traefik:v3` (Go with modules), `ghcr.io/astral-sh/uv`. Verify Go modules appear; record what is invisible.

## C. rootfs on a live host and Linuxbrew

- [ ] **Rootfs of a live `/`** (not an unpacked image).
  ```bash
  sudo uv run secmonk collect rootfs / -O /tmp/host.json --db /tmp/lx.db
  dpkg -l | awk 'NR>5' | wc -l      # or: rpm -qa | wc -l / apk list -I | wc -l
  jq '[.components[]|select(.category=="package")]|length' /tmp/host.json; jq .warnings /tmp/host.json
  ```
  Verify: counts equal the native tool; no walking into `/proc`, `/sys`, `/dev`, container storage (`/var/lib/docker`), `/nix/store`; size/count limits warn instead of hanging;
  works on Debian, Ubuntu, Fedora/RHEL (sqlite rpmdb), Alpine, Arch (pacman DB unsupported - confirm warning), openSUSE. Language files owned by OS packages are *not* dropped (documented): measure duplicate findings.
- [ ] **Linuxbrew** (`/home/linuxbrew/.linuxbrew`).
  ```bash
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; /home/linuxbrew/.linuxbrew/bin/brew install jq openssl@3 httpie
  uv run secmonk scan homebrew /home/linuxbrew/.linuxbrew --db /tmp/lx.db
  ```
  Verify: same checks as [on-macos.md](on-macos.md) section B (opt links, receipts, sbom, keg-only), `pkg:brew` purls, vendored PyPI libs from `libexec/lib/python*/site-packages`.
  Note: `MacOSCollector` ignores linuxbrew; the standalone collector is the supported path.
- [ ] **distro `distro_triage` against real tracker data on a Debian/Ubuntu box.** Needs [on-open-network.md](on-open-network.md) item "Debian tracker" done first;
  then `secmonk scan rootfs / --db /tmp/lx.db && secmonk findings --hide-minor --db /tmp/lx.db` vs `apt-get -s upgrade` and `debsecan`; compare counts.

## D. SSH to a real Linux server (only a local `sh` double and in-process paramiko server so far)

Test targets: Debian/Ubuntu (GNU), Alpine (busybox `find`/`tar`), RHEL-like. Two connections per scan (detect + harvest).

- [ ] **OpenSSH transport, GNU userland.**
  ```bash
  uv run secmonk scan ssh deploy@srv1 -o verbose=true --db /tmp/ssh.db
  uv run secmonk scan ssh deploy@srv1 -o binaries=true -o max_binary_mb=100 --db /tmp/ssh.db
  ssh deploy@srv1 'dpkg -l | wc -l'; uv run secmonk inventory show ssh:srv1 --category package --db /tmp/ssh.db | wc -l
  ```
  Verify: asset `ssh:srv1` meta (`transport, user, port, remote_os, remote_hostname, harvested_files, harvested_bytes, sudo, truncated`); package count == remote `dpkg -l`;
  language files harvested (dist-info, node_modules, jars with `binaries=true`). Update [ssh.md](../tech/collectors/ssh.md) `sample:` and save a trimmed inventory JSON as fixture.
- [ ] **`sudo -n` (NOPASSWD) and no-root.**
  ```bash
  uv run secmonk scan ssh deploy@srv1 -o sudo=true --db /tmp/ssh.db      # needs `deploy ALL=(ALL) NOPASSWD: ALL` for the test
  uv run secmonk scan ssh deploy@srv1 -o sudo=false --db /tmp/ssh2.db
  ```
  Verify: with sudo more root-only trees (`/root`, `/var/lib/...`) harvested; without sudo graceful warnings; with sudo requiring a password it fails fast (no hang on tty prompt).
- [ ] **busybox `find`/`tar` (Alpine target, `--null` support).**
  ```bash
  uv run secmonk scan ssh root@alpine-vm -o verbose=true --db /tmp/ssh3.db
  ssh root@alpine-vm 'tar --help 2>&1 | head -5; find --help 2>&1 | head -3'
  ```
  Verify: the harvest script works with busybox (tar may lack `--null`; the script is meant to avoid GNU-only flags - [ssh.md](../tech/collectors/ssh.md) Limitations). If it fails, add an xargs/cpio fallback and a test. `apk` DB read.
- [ ] **ProxyJump, ssh config, agent, `ssh_option`, ports, IPv6.**
  ```bash
  uv run secmonk scan ssh deploy@srv-internal -o ssh_option=ProxyJump=bastion --db /tmp/ssh4.db
  uv run secmonk scan ssh ssh://deploy@[fe80::1%eth0]:2222 --db /tmp/ssh5.db
  uv run secmonk scan ssh deploy@srv1 -o transport=paramiko -o identity=~/.ssh/id_ed25519 --db /tmp/ssh6.db
  ```
  Verify: OpenSSH honours `~/.ssh/config`; paramiko does not support ProxyJump (message clear); host-key policy (unknown host key must **not** be silently accepted - check `StrictHostKeyChecking` behaviour; security-relevant).
- [ ] **Two connections / ControlMaster** (documented limit): measure overhead; try `-o ssh_option=ControlMaster=auto -o ssh_option=ControlPath=~/.ssh/cm-%r@%h:%p -o ssh_option=ControlPersist=60`.
  Decide whether to reuse a master automatically. Record seconds per scan.
- [ ] **Large servers**: scan a host with 1M files: `-o root=/ -o exclude=/data,/mnt -o xdev=false -o max_mb=1024`; check `truncated` flag, time, and that `/nix/store`, container storage are pruned (NixOS-managed software is a documented gap -> [next-sources.md](next-sources.md) NixOS).
- [ ] **Windows OpenSSH server from Linux** is covered in [on-windows.md](on-windows.md) section C. **macOS target:** [on-macos.md](on-macos.md) section C.

## F. Process monitor: Linux backend, local and over ssh (implemented 2026-11-11 on fixtures only)

Implemented in `collectors/process/linux.py` + `remote.py` and tested against a synthetic tree
(`tests/fixtures/collectors/process/linux/`, the remote script run by macOS `sh` with fake `stat` / `dpkg-query`).
Design: [tech/collectors/process.md](../tech/collectors/process.md) "Where the data lives (Linux)" and "Remote Linux
over ssh"; [ADR-0010](../decisions/0010-remote-process-snapshot.md). Each item below is an assumption only a real host
can confirm; capture a trimmed, anonymized snapshot (`--snapshot-out`) into `tests/fixtures/collectors/process/linux/real/`
with a README.

- [ ] **Live `/proc` run, root and non-root** on a desktop (GNOME or KDE) and a server:
  ```bash
  uv run secmonk procs --no-match --snapshot-out /tmp/linux-user.json
  sudo uv run secmonk procs --no-match --snapshot-out /tmp/linux-root.json; sudo uv run secmonk procs --suspicious
  ```
  Verify: process count = `ps -e --no-headers | wc -l` minus kernel threads (`-o kernel_threads=true` for the total);
  `started` equals `ps -o lstart` (field 22 + `btime` + `CLK_TCK`); non-root shows the warning with the number of
  unreadable executables and no traceback; `/var/spool/cron/crontabs` denied -> one warning.
- [ ] **Units and labels**: systemd services carry their unit as `label` on the main pid only (nginx workers are
  children); `user@<uid>.service` labels `systemd --user`; GNOME/KDE apps appear as `app-*.scope` (`gui-app`) and
  autostart entries as `app-*@autostart.service` (`login-item`) — confirm the scope / service names on the desktop in
  use (GNOME 4x, KDE Plasma 6) and on systems without systemd-xdg-autostart-generator; `getty@tty1` resolves to
  `getty@.service`; a timer-started service is `scheduled`.
- [ ] **cgroup v1 / hybrid** (CentOS 7, Ubuntu 18.04, or `systemd.unified_cgroup_hierarchy=0`): the `name=systemd`
  line is used and units are labelled as on v2.
- [ ] **Containers**: `docker run -d nginx`, `podman run -d nginx`, a k3s/kind pod: the container's processes appear as
  `child (container)` under `containerd-shim-runc-v2` / `conmon` with the right runtime and id, and are not attributed
  to host packages; decide whether to link them to the `container:<name>` asset of `docker-engine`.
- [ ] **Identity on rpm and apk hosts**: Rocky/Alma 9 (live: `rpm -qf`; check the number of subprocesses and time with
  ~300 executables) and Alpine (apk `installed` `R:` lines, busybox applets via `/bin/busybox`); merged-/usr Debian 12
  and a non-merged Debian 11 (dpkg `.list` paths); a deleted-on-upgrade daemon (`apt upgrade` without restart) is
  `exe-missing`; snap (`/snap/<name>/<rev>`) and flatpak apps; Linuxbrew kegs.
- [ ] **Remote over ssh** to the same hosts: `secmonk procs ssh://user@host`, then `-o sudo=true` (NOPASSWD rule) and
  without a sudo rule (expect the `sudo -n` hint, exit 1); compare with the local run (same rows, same identities, same
  launch kinds); a busybox-only host (Alpine) where `stat -c`, `readlink`, `od` are busybox applets; a host without
  `getconf` (start times empty); `-o transport=paramiko`; output size and run time on a host with ~1000 processes
  (cap is 32 MiB); a login shell that prints a banner in `.bashrc` (the script must still be found between its
  markers); `dpkg-query -S --`, `rpm -qf ... --` and busybox `stat -L -c ... --` accept `--` before the path; batched `rpm -qf -- p1 p2 ...` prints exactly one line per path (also "not owned" on stdout), else the per-path fallback runs; `stat -L /proc/<pid>/root` as root tells chroot / nspawn / flatpak processes apart from services with only a private mount namespace (`PrivateTmp=`, `ProtectSystem=`), which must stay host processes.
- [ ] **dpkg-query fields**: `dpkg-query -W -f='${Source}'` on dpkg >= 1.21 (Debian 12, Ubuntu 24.04) yields the source
  package as expected (empty when equal to the binary name); the `.list` mtime is a usable install time (it changes on
  every upgrade of the package).

## E. Wrap-up

- [ ] Commit real fixtures + tests; set `sample:` in `tech/collectors/docker-engine.md`, `docker-image.md`, `ssh.md`, `rootfs.md`; update [inventory-docker.md](../features/inventory-docker.md) / [inventory-ssh.md](../features/inventory-ssh.md) caveats; regenerate INDEX (`uv run python scripts/docs.py index`).

## K. Kubernetes clusters (k8s collector, synthetic kubectl output only)

- [ ] **kind / k3d / minikube on this host** (2026-11-11: never run against a real cluster).
  ```bash
  kind create cluster --name dev && kubectl --context kind-dev apply -f https://k8s.io/examples/application/deployment.yaml
  uv run secmonk scan k8s k8s://kind-dev --db /tmp/lx.db
  uv run python -c "from secmonk.discover import discover_host; import json; print(json.dumps(discover_host('k8s://kind-dev'), indent=1))"
  ```
  Verify: asset `k8s:kind-dev`, control plane / kubelet / containerd / Debian node OS components; `imageID`s are
  `repo@sha256:` (assumed for containerd: unverified) so `k8s-images` is pinned; `meta.distro` contains `kind`.
- [ ] **Restricted RBAC user** (a ServiceAccount with only `list pods` in one namespace): expect a partial
  inventory, `meta.access.pods = "namespaces: <ns>"`, a clear warning, and no traceback; with no rights at all,
  "no read access". Check that kubectl's real Forbidden wording is caught by `_DENIED`.
- [ ] **Managed clusters (EKS, GKE, AKS)** with exec auth plugins: `gitVersion` suffixes, `providerID` hints, and
  that tokens never appear in messages (`redact`). Large cluster (1000+ pods): time and memory of
  `get pods --all-namespaces -o json` against the 256 MiB cap.
- [ ] **Vendor builds in matching**: `meta.vendor_build` (EKS/GKE/k3s control planes) is recorded but the engine
  does not use it yet; decide how to treat upstream CVEs on vendor builds (confidence, distro triage).
- [ ] **Private registry images** found in a cluster: scanning the `k8s-images` list needs registry credentials
  (`-o username=` + `SECMONK_REGISTRY_PASSWORD`); decide on imagePullSecrets (never read today).
