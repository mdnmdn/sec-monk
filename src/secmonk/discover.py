"""Host auto mode: look at a host (this machine, or one reachable over SSH) and propose what to scan.

`discover_host(target, **opts)` returns the host facts and a list of *candidates*: one per collector run that makes
sense there (collector + target + options), each with `available` / `reason` and a default `selected` tick. The CLI,
the web API and the UI turn the selected candidates into a batch of ordinary scans; nothing here collects, saves or
matches.

Probes are read-only, time-bounded and failure-tolerant: a failing probe becomes `available=False` + `reason` (or a
warning), never an exception. Only an unparsable or unreachable SSH target raises. Remote output is size-capped and
targets are reported without passwords. See _docs/tech/discover.md.
"""

from __future__ import annotations

import os
import platform
import re
import socket
import sys
from pathlib import Path
from typing import Any

from .collectors.base import strip_url_secrets
from .collectors.docker_transport import REMOTE_DOCKER_PATHS

LOCAL_TARGETS = ("", "local", "localhost")
PROBE_TIMEOUT = 5.0          # seconds, docker ping / listing
SSH_PROBE_TIMEOUT = 60       # seconds, the one remote probe command
MAX_PROBE_OUTPUT = 64 * 1024
MAX_CONTAINERS = 50

# options of the ssh collector worth carrying into every ssh-based candidate (contract with the CLI/API)
SSH_OPTS = ("identity", "known_hosts", "insecure_host_key", "connect_timeout", "ssh_option", "transport")
# ... and the subset docker-engine understands for ssh:// engines (system ssh only)
DOCKER_SSH_OPTS = ("identity", "known_hosts", "insecure_host_key", "connect_timeout", "ssh_option", "ssh_bin",
                   "timeout")
# engine options a local probe honours and copies into the docker candidates (context/host/socket are pinned)
LOCAL_ENGINE_OPTS = ("tls_ca", "tls_cert", "tls_key", "tls_verify", "identity", "known_hosts", "insecure_host_key",
                     "ssh_option", "connect_timeout", "ssh_bin", "timeout")

# fs on a home directory: the walk has no exclude option, so the candidate keeps it light (no binary parsing)
FS_HOME_OPTIONS = ["binaries=false"]

# package managers recognised on a Linux root, by the database the rootfs collector reads
_PKG_DBS = (("dpkg", "var/lib/dpkg/status"), ("rpm", "var/lib/rpm"), ("rpm", "usr/lib/sysimage/rpm"),
            ("apk", "lib/apk/db/installed"), ("pacman", "var/lib/pacman/local"))
_ROOTFS_READS = ("dpkg", "rpm", "apk")             # what rootfs parses (pacman is detected, not read)

# the remote probe: OS detection of the ssh collector (harvest.detect_script) + this fixed, read-only tool check
TOOL_PREFIX = "@@secmonk-tool:"
REMOTE_TOOLS = ("docker", "podman", "brew", "dpkg", "rpm", "apk", "pacman")
_TOOL_LOOP = (f"for t in {' '.join(REMOTE_TOOLS)}; do command -v \"$t\" >/dev/null 2>&1 && "
              f"printf '{TOOL_PREFIX}%s\\n' \"$t\"; done")
_PREFIX_LOOP = ("for p in /opt/homebrew /usr/local /home/linuxbrew/.linuxbrew; do "
                f"[ -d \"$p/Cellar\" ] && printf '{TOOL_PREFIX}brew-prefix=%s\\n' \"$p\"; done")
# macOS: docker often lives outside the non-interactive ssh PATH (docker_transport.REMOTE_DOCKER_PATHS)
_DOCKER_PATHS = REMOTE_DOCKER_PATHS
_DOCKER_LOOP = (f"for p in {' '.join(_DOCKER_PATHS)}; do "
                f"[ -x \"$p\" ] && printf '{TOOL_PREFIX}docker-path=%s\\n' \"$p\"; done")
TOOLS_SCRIPT = f"{_TOOL_LOOP}\n{_PREFIX_LOOP}\n{_DOCKER_LOOP}\ntrue\n"


# --------------------------------------------------------------------------- public

def discover_host(target: str | None = None, **opts: Any) -> dict:
    """What can be scanned on `target`: None / "" / "local" / "localhost" = this machine, else an SSH target
    (`[ssh://][user@]host[:port]`). See the module docstring and _docs/tech/discover.md for the result shape."""
    if target is None or str(target).strip().lower() in LOCAL_TARGETS:
        return _discover_local(opts)
    return _discover_ssh(str(target).strip(), opts)


def candidate(cid: str, collector: str, target: str | None, *, label: str, description: str,
              options: list[str] | None = None, available: bool = True, reason: str | None = None,
              selected: bool | None = None, details: dict | None = None) -> dict:
    return {"id": cid, "collector": collector, "target": target, "options": list(options or []), "label": label,
            "description": description, "available": available, "reason": reason,
            "selected": bool(available if selected is None else selected and available),
            "details": details or {}}


# --------------------------------------------------------------------------- local

def _local_os() -> str:
    return {"darwin": "macos", "linux": "linux", "win32": "windows"}.get(sys.platform, "unknown")


def _os_release(root: Path = Path("/")) -> dict[str, str]:
    for rel in ("etc/os-release", "usr/lib/os-release"):
        try:
            text = (root / rel).read_text(errors="replace")[:MAX_PROBE_OUTPUT]
        except OSError:
            continue
        out: dict[str, str] = {}
        for line in text.splitlines():
            k, sep, v = line.partition("=")
            if sep and re.fullmatch(r"[A-Z_]+", k):
                out[k] = v.strip().strip('"').strip("'")
        return out
    return {}


def _local_host(os_name: str) -> dict:
    version: str | None = None
    if os_name == "macos":
        version = platform.mac_ver()[0] or None
    elif os_name == "linux":
        osr = _os_release()
        version = osr.get("PRETTY_NAME") or osr.get("VERSION_ID") or None
    elif os_name == "windows":
        version = platform.version() or None
    return {"kind": "local", "target": None, "name": socket.gethostname(), "os": os_name, "os_version": version,
            "arch": platform.machine() or None}


def _discover_local(opts: dict[str, Any]) -> dict:
    os_name = _local_os()
    host = _local_host(os_name)
    warnings: list[str] = []
    cands: list[dict] = []
    if os_name == "macos":
        cands.append(_macos_candidate())
        if c := _homebrew_candidate(covered_by="macos"):
            cands.append(c)
    elif os_name == "linux":
        cands.append(_rootfs_candidate())
        if c := _homebrew_candidate(covered_by=None):
            cands.append(c)
    elif os_name == "windows":
        cands.append(candidate(
            "windows", "windows", None, label="Windows software",
            description="Installed programs, hotfixes and OS build from the PowerShell inventory JSON",
            available=False, reason="needs the JSON written by the PowerShell script: run `secmonk windows-script`,"
                                    " execute it, then scan the file with the windows collector"))
    cands.append(_process_candidate())
    if c := _fs_home_candidate():
        cands.append(c)
    cands += _local_docker_candidates(opts)
    return {"host": host, "candidates": cands, "warnings": warnings}


def _macos_candidate() -> dict:
    reason = None
    try:            # readable only with Full Disk Access (macOS privacy protection)
        os.listdir("/Library/Application Support/com.apple.TCC")
    except PermissionError:
        reason = "without Full Disk Access some apps and receipts are skipped (they are listed as warnings)"
    except OSError:
        pass
    return candidate("macos", "macos", None, label="macOS applications",
                     description="Apps (.app bundles), pkgutil receipts, Homebrew formulae and casks, macOS version",
                     reason=reason, selected=True)


def _brew_prefixes(root: Path = Path("/")) -> list[str]:
    from .collectors.homebrew import find_prefixes

    try:
        return [str(p) for p in find_prefixes(root)]
    except OSError:
        return []


def _homebrew_candidate(covered_by: str | None) -> dict | None:
    prefixes = _brew_prefixes()
    if not prefixes:
        return None
    if covered_by:
        return candidate("homebrew", "homebrew", None, label="Homebrew",
                         description=f"Homebrew formulae and casks in {', '.join(prefixes)} as a separate asset",
                         reason=f"already part of the {covered_by} scan; select only for a separate Homebrew asset",
                         selected=False, details={"prefixes": prefixes})
    return candidate("homebrew", "homebrew", None, label="Homebrew",
                     description=f"Linuxbrew formulae in {', '.join(prefixes)} (not read by the rootfs scan)",
                     selected=True, details={"prefixes": prefixes})


def _package_managers(root: Path = Path("/")) -> list[str]:
    found: list[str] = []
    for name, rel in _PKG_DBS:
        if name not in found and (root / rel).exists():
            found.append(name)
    return found


def _rootfs_candidate() -> dict:
    pms = _package_managers()
    read = [p for p in pms if p in _ROOTFS_READS]
    reason = None
    if not read:
        reason = ("no dpkg/rpm/apk database found" + (f" ({', '.join(pms)} is not read)" if pms else "")
                  + ": only language packages and binaries will be found")
    desc = "OS packages" + (f" ({', '.join(read)})" if read else "") + " and language packages of the root filesystem"
    return candidate("rootfs", "rootfs", "/", label="Linux packages", description=desc, reason=reason,
                     selected=True, details={"package_managers": pms})


def _process_candidate() -> dict:
    from .collectors.process.backend import BACKENDS, current_platform

    plat = current_platform()
    ok = plat in BACKENDS
    return candidate("process", "process", None, label="Running processes",
                     description="Running processes: how each was launched, the software behind it, its version",
                     available=ok, reason=None if ok else f"no {plat} process backend yet",
                     selected=True, details={"platform": plat})


def _fs_home_candidate() -> dict | None:
    try:
        home = Path.home()
    except (RuntimeError, KeyError):
        return None
    if not home.is_dir():
        return None
    return candidate("fs-home", "fs", str(home), label="Home folder dependencies",
                     description="Lockfiles, manifests and installed language packages under the home folder",
                     options=FS_HOME_OPTIONS, selected=False,
                     reason="walks the whole home folder (no exclude option): can take minutes",
                     details={"path": str(home)})


# --------------------------------------------------------------------------- docker

def _docker_probe(engine_opts: dict[str, Any], timeout: float) -> dict:
    """{"state": "ok"|"none"|"down", "endpoint": str|None, "options": [...], "containers": [...], "reason": str}.
    "none" = no engine configured or found (no candidate), "down" = one is there but does not answer."""
    from .collectors import docker_engine as de

    try:
        ep = de.find_endpoint(engine_opts)
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        if "socket not found" in msg and "refusing connections" not in msg:
            return {"state": "none", "reason": msg}
        return {"state": "down", "endpoint": None, "reason": msg[:300]}
    if ep.scheme == "ssh":       # every request starts ssh (connect, auth, dial-stdio) before the first byte
        timeout = max(timeout, ep.connect_timeout + 5)
    client = de.EngineClient(ep, timeout)
    try:
        client.ping()
        rows = client.get_json("/containers/json?all=0")
    except Exception as e:  # noqa: BLE001
        return {"state": "down", "endpoint": strip_url_secrets(str(ep), keep_user=True), "reason": str(e)[:300],
                "options": _pin_engine(ep, engine_opts)}
    containers = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        names = [str(n).lstrip("/") for n in r.get("Names") or [] if isinstance(n, str)]
        containers.append({"name": (names[0] if names else str(r.get("Id", ""))[:12])[:128],
                           "image": str(r.get("Image") or "")[:200], "state": str(r.get("State") or "")[:20]})
    images: list[dict] | None = None
    try:
        images = []
        for r in client.get_json("/images/json") or []:
            if isinstance(r, dict) and (tags := de.image_tags(r)) and (iid := de._norm_id(r.get("Id"))):
                images.append({"id": iid.removeprefix("sha256:")[:12], "tags": [t[:200] for t in tags[:20]]})
    except Exception:  # noqa: BLE001 - containers are still worth proposing
        images = None
    return {"state": "ok", "endpoint": strip_url_secrets(str(ep), keep_user=True), "reason": None,
            "containers": containers, "images": images, "options": _pin_engine(ep, engine_opts)}


def _pin_engine(ep: Any, engine_opts: dict[str, Any]) -> list[str]:
    """Options that make the scan hit the engine the probe saw."""
    if engine_opts.get("host"):
        return [f"host={strip_url_secrets(str(engine_opts['host']), keep_user=True)}"]
    if ep.context:
        return [f"context={ep.context}"]
    if ep.scheme == "unix":
        return [f"socket={ep.unix}"]
    return []


def _docker_candidate(probe: dict, extra_options: list[str], *, where: str) -> dict:
    containers = probe.get("containers") or []
    running = [c for c in containers if c.get("state") == "running"]
    details = {"engine": probe.get("endpoint"), "containers": containers[:MAX_CONTAINERS]}
    if len(containers) > MAX_CONTAINERS:
        details["more"] = len(containers) - MAX_CONTAINERS
    opts = [*probe.get("options", []), *extra_options]
    if probe["state"] != "ok":
        return candidate("docker", "docker-engine", "*", label="Docker containers",
                         description=f"Running containers of the Docker engine {where}", options=opts,
                         available=False, reason=probe.get("reason") or "engine not reachable", details=details)
    return candidate("docker", "docker-engine", "*", label="Docker containers",
                     description=f"Running containers of the Docker engine {where} ({len(running)} running)",
                     options=opts, selected=bool(running),
                     reason=None if running else "no running containers", details=details)


def _docker_images_candidate(probe: dict, extra_options: list[str], *, where: str) -> dict:
    """Local images of the engine, each scanned once per image Id (aliases folded). Never selected by default."""
    images = probe.get("images")
    opts = [*probe.get("options", []), *extra_options]
    if probe["state"] != "ok" or images is None:
        return candidate("docker-images", "docker-engine", "image:*", label="Docker images",
                         description=f"Tagged images of the Docker engine {where}, once per image Id", options=opts,
                         available=False, reason=probe.get("reason") or "cannot list the engine's images",
                         selected=False)
    n_tags = sum(len(i["tags"]) for i in images)
    details = {"tagged_images": n_tags, "unique_ids": len(images), "images": images[:MAX_CONTAINERS]}
    return candidate("docker-images", "docker-engine", "image:*", label="Docker images",
                     description=f"Tagged images of the Docker engine {where}: {len(images)} unique "
                                 f"({n_tags} tags), each scanned once per image Id",
                     options=opts, available=bool(images), selected=False,
                     reason=None if images else "no tagged images", details=details)


def _local_docker_candidates(opts: dict[str, Any]) -> list[dict]:
    engine_opts = {k: opts[k] for k in ("context", "host", "socket", *LOCAL_ENGINE_OPTS)
                   if opts.get(k) not in (None, "")}
    probe = _docker_probe(engine_opts, _probe_timeout(opts))
    if probe["state"] == "none":
        return []
    extra = _opt_strings(engine_opts, LOCAL_ENGINE_OPTS)
    return [_docker_candidate(probe, extra, where="on this machine"),
            _docker_images_candidate(probe, extra, where="on this machine")]


def _probe_timeout(opts: dict[str, Any]) -> float:
    try:
        t = float(opts.get("probe_timeout") or PROBE_TIMEOUT)
    except (TypeError, ValueError):
        return PROBE_TIMEOUT
    return t if 0 < t < 300 else PROBE_TIMEOUT


# --------------------------------------------------------------------------- ssh

def _opt_strings(opts: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    """`k=v` strings for the options present (lists -> repeated keys; non-string objects skipped)."""
    out: list[str] = []
    for k in keys:
        v = opts.get(k)
        if v is None or v == "" or not isinstance(v, (str, int, float, bool, list, tuple)):
            continue
        for item in v if isinstance(v, (list, tuple)) else [v]:
            item = str(item).lower() if isinstance(item, bool) else str(item)
            if "\n" not in item and "\r" not in item:
                out.append(f"{k}={item}")
    return out


def _parse_tools(text: str) -> tuple[list[str], list[str], list[str]]:
    """(tools on PATH, Homebrew prefixes, docker CLIs at known off-PATH locations); unknown values are ignored."""
    tools: list[str] = []
    prefixes: list[str] = []
    docker_paths: list[str] = []
    for line in text.splitlines():
        if not line.startswith(TOOL_PREFIX):
            continue
        v = line[len(TOOL_PREFIX):].strip()
        if v.startswith("brew-prefix="):
            p = v.split("=", 1)[1]
            if p in ("/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew") and p not in prefixes:
                prefixes.append(p)
        elif v.startswith("docker-path="):
            p = v.split("=", 1)[1]
            if p in _DOCKER_PATHS and p not in docker_paths:
                docker_paths.append(p)
        elif v in REMOTE_TOOLS and v not in tools:
            tools.append(v)
    return tools, prefixes, docker_paths


def _discover_ssh(target: str, opts: dict[str, Any]) -> dict:
    from .collectors import harvest
    from .collectors.ssh import SSHCollector, Transport, _stderr_text, make_transport, parse_target

    t = parse_target(target)               # ValueError on an unparsable target
    shown = str(t)                         # [user@]host[:port]: never a password (parse_target refuses one)
    injected = opts.get("transport")
    transport = injected if isinstance(injected, Transport) else make_transport(t, opts)
    warnings: list[str] = []
    os_name, version, arch, name = "unknown", None, None, t.host
    tools: list[str] = []
    prefixes: list[str] = []
    docker_paths: list[str] = []
    try:
        script = harvest.detect_script("/") + TOOLS_SCRIPT
        try:
            rc, out, err = transport.run("sh -s", timeout=SSH_PROBE_TIMEOUT, stdin=script.encode())
        except TimeoutError as e:
            raise RuntimeError(f"probe of {shown} timed out: {e}") from e
        except Exception as e:
            raise RuntimeError(f"cannot reach {shown} over ssh: {e}") from e
        text = out[:MAX_PROBE_OUTPUT].decode("utf-8", "replace")
        try:
            info = harvest.parse_detect(text)
        except ValueError:
            if rc == 255 or not out:
                raise RuntimeError(f"cannot reach {shown} over ssh (rc={rc}): "
                                   f"{_stderr_text(err[:MAX_PROBE_OUTPUT]) or 'no output'}") from None
            info = None
        if info is None:
            if SSHCollector()._is_windows(transport, SSH_PROBE_TIMEOUT):
                os_name = "windows"
            else:
                warnings.append(f"remote OS not recognised (rc={rc}); the ssh scan may fail")
        else:
            os_name = info.family or "unknown"
            version = (info.description if info.family else info.kernel or None) or None
            arch = info.arch or None
            name = (info.hostname or t.host)[:255]
            tools, prefixes, docker_paths = _parse_tools(text)
    finally:
        if transport is not injected:
            transport.close()

    ssh_opts = _opt_strings(opts, SSH_OPTS)
    host = {"kind": "ssh", "target": strip_url_secrets(f"ssh://{shown}", keep_user=True).removeprefix("ssh://"),
            "name": name, "os": os_name, "os_version": version, "arch": arch}
    cands = [_ssh_candidate(shown, os_name, tools, prefixes, ssh_opts)]
    cands += _remote_docker_candidates(shown, tools, opts, warnings, docker_paths)
    cands.append(candidate("process", "process", None, label="Running processes",
                           description="Running processes and how they were launched", available=False,
                           reason="processes are only collected locally"))
    return {"host": host, "candidates": cands, "warnings": warnings}


def _ssh_candidate(shown: str, os_name: str, tools: list[str], prefixes: list[str], ssh_opts: list[str]) -> dict:
    pms = [p for p in ("dpkg", "rpm", "apk", "pacman") if p in tools]
    if os_name == "macos":
        desc = "Apps, pkgutil receipts and Homebrew of the remote Mac, read-only over ssh"
    elif os_name == "windows":
        desc = "Installed programs and OS build of the remote Windows host (PowerShell inventory over ssh)"
    else:
        desc = ("OS packages" + (f" ({', '.join(pms)})" if pms else "") + ", language packages"
                + (" and Homebrew" if prefixes else "") + " of the remote host, read-only over ssh")
    reason = None
    if os_name == "linux" and not any(p in _ROOTFS_READS for p in pms):
        reason = "no dpkg/rpm/apk found: only language packages and binaries will be found"
    elif os_name == "unknown":
        reason = "remote OS not recognised"
    return candidate("ssh", "ssh", shown, label="Remote host software", description=desc, options=ssh_opts,
                     reason=reason, selected=os_name != "unknown",
                     details={"package_managers": pms, "brew_prefixes": prefixes, "tools": tools})


def _remote_docker_candidates(shown: str, tools: list[str], opts: dict[str, Any], warnings: list[str],
                              docker_paths: list[str] | None = None) -> list[dict]:
    if "docker" not in tools and not docker_paths:
        if "podman" in tools:
            return [candidate("docker", "docker-engine", "*", label="Docker containers",
                             description="Containers of the remote Podman", available=False,
                             reason="only podman found: scanning over ssh needs the docker CLI "
                                    "(`docker system dial-stdio`) on the remote host")]
        return []
    transport = str(opts.get("transport") or "auto").lower() if isinstance(opts.get("transport"), str) else "auto"
    engine_opts: dict[str, Any] = {k: opts[k] for k in DOCKER_SSH_OPTS if opts.get(k) not in (None, "")}
    engine_opts["host"] = f"ssh://{shown}"
    if "docker" not in tools and docker_paths:      # not on the non-interactive PATH (macOS)
        engine_opts["remote_docker"] = docker_paths[0]
    extra = _opt_strings(engine_opts, (*DOCKER_SSH_OPTS, "remote_docker"))
    probe = _docker_probe(engine_opts, _probe_timeout(opts))
    if probe["state"] == "none":           # cannot happen for an explicit host; keep the shape anyway
        probe = {**probe, "state": "down"}
    if transport == "paramiko":
        warnings.append("docker over ssh uses the system ssh, not paramiko")
    return [_docker_candidate(probe, extra, where=f"on {shown}"),
            _docker_images_candidate(probe, extra, where=f"on {shown}")]
