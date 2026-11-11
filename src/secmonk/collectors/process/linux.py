"""Linux backend of the process monitor (local `/proc`; the ssh variant in remote.py reuses everything here).

* snapshot: `/proc/<pid>/{stat,status,cmdline,cgroup}` + the `exe` link, boot time from `/proc/stat`; launch items
  from systemd unit files (`ExecStart`, `.timer`), XDG autostart `.desktop` files and crontabs.
  The cgroup names the systemd unit (-> `label`, `pid-label` evidence) and the container a process runs in.
* inspector (live or a copied tree under `root`; None = a snapshot from elsewhere, paths only): executable ->
  distro package owning it (dpkg `info/*.list`, apk `installed`, live rpm via `rpm -qf`), Linuxbrew keg, snap,
  flatpak, Go/Rust build info; provenance facts (file times, owner, sha256, package install time).

Both the local reader and the remote script produce a `Capture` (raw file contents), turned into a `Snapshot` by
the same pure parsers. Nothing is executed locally except the fixed read-only `rpm -qf --queryformat ... -- <path>`
(live, rpm-based hosts only). See _docs/tech/collectors/process.md.
"""

from __future__ import annotations

import contextlib
import os
import posixpath
import re
import shlex
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ...engine import purl as purls
from ...models import CAT_APPLICATION, CAT_OS_PACKAGE, Asset, Component
from ..base import read_within, redact_command, resolve_within
from ..rootfs import (
    _PURL_NS,
    DirView,
    FsView,
    _distro_qualifier,
    _os_component,
    collect_from_view,
    distro_ecosystem,
    parse_os_release,
    rpm_source_name,
)
from .backend import Inspector, Resolution
from .launch import systemd_unit
from .model import LaunchItem, ProcessRecord, Snapshot
from .snapshot import MAX_ARGS

PF_KTHREAD = 0x00200000
MAX_PROC_FILE = 64 * 1024
MAX_CMDLINE = 128 * 1024
MAX_CONFIG_BYTES = 1024 * 1024        # one unit / desktop / crontab file
MAX_LIST_BYTES = 512 * 1024 * 1024    # all dpkg .list files together
MAX_APK_DB = 64 * 1024 * 1024
DEFAULT_MAX_BINARY = 128 * 1024 * 1024
CMD_TIMEOUT = 30

# systemd unit directories in precedence order (a unit in /etc hides the vendor one of the same name)
SYSTEM_UNIT_DIRS = ("/etc/systemd/system", "/usr/local/lib/systemd/system", "/lib/systemd/system",
                    "/usr/lib/systemd/system")
USER_UNIT_DIRS = ("/etc/systemd/user", "/usr/local/lib/systemd/user", "/usr/lib/systemd/user")
HOME_UNIT_DIR = ".config/systemd/user"
AUTOSTART_DIR = "/etc/xdg/autostart"
HOME_AUTOSTART_DIR = ".config/autostart"
SYSTEM_CRONTABS = ("/etc/crontab",)
SYSTEM_CRON_DIRS = ("/etc/cron.d",)
USER_CRON_DIRS = ("/var/spool/cron/crontabs", "/var/spool/cron")    # Debian, RHEL
# writable by an ordinary user
USER_WRITABLE = ("/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")
BIN_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")


# ============================================================================ raw capture

@dataclass
class RawProc:
    pid: int
    stat: bytes = b""
    status: str = ""
    cmdline: bytes = b""
    cgroup: str = ""
    exe: str | None = None          # readlink of /proc/<pid>/exe, as is (may end in " (deleted)")
    exe_denied: bool = False        # the link exists but could not be read (other user's process, not root)
    root_id: str = ""               # "<dev>:<inode>" of /proc/<pid>/root: differs from pid 1's in a chroot/container


@dataclass
class Capture:
    """Raw contents read from a Linux machine (locally or by the remote script)."""

    hostname: str = ""
    ostype: str = ""
    boot_id: str = ""
    btime: int | None = None
    clk_tck: int | None = None
    uid: int | None = None          # who read it
    os_release: str = ""
    debian_version: str = ""
    passwd: str = ""
    procs: list[RawProc] = field(default_factory=list)
    units: list[tuple[str, str]] = field(default_factory=list)       # (path, text)
    masked: list[str] = field(default_factory=list)                  # unit paths linked to /dev/null
    autostart: list[tuple[str, str]] = field(default_factory=list)
    crontabs: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # remote only: facts and package ownership computed on the target
    files: dict[str, tuple[int, int, int, int]] = field(default_factory=dict)   # path -> mtime, size, uid, mode
    dpkg_search: str = ""                                             # `dpkg-query -S -- <all paths>` output
    rpm_owner: dict[str, str] = field(default_factory=dict)           # path -> its `rpm -qf --queryformat` row(s)
    snap_versions: dict[str, str] = field(default_factory=dict)       # /snap/<name>/<rev> -> version
    dpkg_table: str = ""                                              # dpkg-query -W stanzas
    dpkg_lists: dict[str, int] = field(default_factory=dict)          # package -> .list mtime
    apk_db: str = ""
    begun: bool = False
    complete: bool = False


# ============================================================================ parsers (pure, tested on fixtures)

MAX_DIGITS = 20


def to_int(v: str | None) -> int | None:
    """A non-negative decimal from untrusted text; None when not digits or absurdly long (Python refuses int() of
    more than 4300 digits, and no field read here needs more than 20)."""
    v = (v or "").strip()
    return int(v) if v.isdigit() and len(v) <= MAX_DIGITS else None


def parse_stat(data: bytes | str) -> dict[str, Any] | None:
    """`/proc/<pid>/stat`. `comm` (field 2) is in parentheses and may itself contain spaces and parentheses,
    so it runs to the *last* `)`. Returns pid, comm, state, ppid, flags (field 9), starttime (field 22, clock ticks
    since boot)."""
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    left, right = text.find("("), text.rfind(")")
    if left < 0 or right < left:
        return None
    rest = text[right + 1:].split()
    if len(rest) < 20:
        return None
    pid, ppid, flags, start = to_int(text[:left]), to_int(rest[1]), to_int(rest[6]), to_int(rest[19])
    if pid is None or ppid is None or flags is None or start is None:
        return None
    return {"pid": pid, "comm": text[left + 1:right], "state": rest[0], "ppid": ppid, "flags": flags,
            "starttime": start}


def parse_status(text: str) -> dict[str, Any]:
    """`/proc/<pid>/status` subset: Name, PPid, Uid (real uid, the first of the four)."""
    out: dict[str, Any] = {}
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if not sep:
            continue
        v = v.strip()
        if k == "Name":
            out["name"] = v
        elif k == "PPid" and to_int(v) is not None:
            out["ppid"] = to_int(v)
        elif k == "Uid" and v.split() and to_int(v.split()[0]) is not None:
            out["uid"] = to_int(v.split()[0])
    return out


def parse_cmdline(data: bytes) -> list[str]:
    """`/proc/<pid>/cmdline`: NUL-separated argv (exact boundaries, unlike `ps`), redacted, max 64 args."""
    if not data:
        return []
    parts = data.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    args = list(redact_command([a.decode("utf-8", "replace") for a in parts[:MAX_ARGS]]) or [])
    # setproctitle() rewrites argv into one string ("postgres: user db 10.0.0.1 idle", "app --token x"): an
    # argument holding spaces is redacted again in its string form
    return [str(redact_command(a)) if any(c.isspace() for c in a) else a for a in args]


def parse_exe_link(target: str | None) -> tuple[str | None, bool]:
    """readlink of `/proc/<pid>/exe` -> (path, deleted). The kernel appends ` (deleted)` when the file was removed
    or replaced (package upgrade) while running."""
    if not target:
        return None, False
    deleted = target.endswith(" (deleted)")
    path = target[:-len(" (deleted)")] if deleted else target
    return (path if path.startswith("/") else None), deleted


_CONTAINER_PATTERNS = (
    (re.compile(r"(?:^|/)docker-([0-9a-f]{64})\.scope$"), "docker"),
    (re.compile(r"/docker/([0-9a-f]{64})(?:/|$)"), "docker"),
    (re.compile(r"(?:^|/)cri-containerd-([0-9a-f]{64})\.scope$"), "containerd"),
    (re.compile(r"(?:^|/)crio-([0-9a-f]{64})\.scope$"), "cri-o"),
    (re.compile(r"(?:^|/)libpod-(?!conmon-)([0-9a-f]{64})\.scope(?:/|$)"), "podman"),
    (re.compile(r"/libpod_parent/libpod-([0-9a-f]{64})(?:/|$)"), "podman"),
    (re.compile(r"/kubepods[^/]*/(?:.*/)?pod[0-9a-f_-]{36}/([0-9a-f]{64})$"), "containerd"),
    (re.compile(r"^/lxc\.payload\.([^/]+)"), "lxc"),
    (re.compile(r"^/lxc/([^/]+)"), "lxc"),
    (re.compile(r"(?:^|/)machine-([^/]+)\.scope(?:/|$)"), "nspawn"),          # systemd-nspawn / machinectl
    (re.compile(r"(?:^|/)app-flatpak-([^/]+?)-\d+\.scope(?:/|$)"), "flatpak"),
)
_POD = re.compile(r"pod([0-9a-f]{8}[_-][0-9a-f]{4}[_-][0-9a-f]{4}[_-][0-9a-f]{4}[_-][0-9a-f]{12})")


def parse_cgroup(text: str) -> dict[str, Any]:
    """`/proc/<pid>/cgroup` (v1 `n:controllers:/path` lines or the v2 `0::/path` line) -> {path, unit, user_unit,
    container}. The path is the systemd hierarchy (`name=systemd` on v1, the unified one on v2, else the first
    non-root controller path). `unit` = the innermost `.service` / `.scope` / `.socket`; `user_unit` when it sits
    below a `user@<uid>.service` (a systemd --user unit). `container` = {runtime, id, pod?} from docker, containerd /
    Kubernetes, CRI-O, podman and LXC path conventions."""
    systemd = unified = other = None
    paths: list[str] = []
    for line in text.splitlines():
        parts = line.strip().split(":", 2)
        if len(parts) != 3:
            continue
        hid, ctrl, path = parts
        paths.append(path)
        if ctrl == "name=systemd":
            systemd = path
        elif hid == "0" and ctrl == "":
            unified = path
        elif other is None and path not in ("", "/"):
            other = path
    path = systemd or (unified if unified not in (None, "/") else None) or other or unified or ""
    out: dict[str, Any] = {"path": path}
    segs = [s for s in path.split("/") if s]
    unit = systemd_unit(path)
    if unit:
        out["unit"] = unit
        idx = segs.index(unit)
        out["user_unit"] = any(s.startswith("user@") and s.endswith(".service") for s in segs[:idx])
    for p in paths:
        for rx, runtime in _CONTAINER_PATTERNS:
            m = rx.search(p)
            if m:
                c = {"runtime": runtime, "id": m.group(1)}
                pod = _POD.search(p)
                if pod:
                    c["pod"] = pod.group(1).replace("_", "-")
                out["container"] = c
                return out
    return out


def parse_proc_btime(text: str) -> int | None:
    """`btime <epoch seconds>` line of /proc/stat."""
    m = re.search(r"^btime\s+(\d+)\s*$", text, re.MULTILINE)
    return to_int(m.group(1)) if m else None


def started_at(starttime: int | None, btime: int | None, clk_tck: int | None) -> str | None:
    """Field 22 (ticks since boot) + boot time -> ISO 8601 UTC."""
    if starttime is None or not btime or not clk_tck:
        return None
    with contextlib.suppress(OverflowError, OSError, ValueError):
        return datetime.fromtimestamp(btime + starttime / clk_tck, UTC).replace(microsecond=0).isoformat()
    return None


def parse_passwd(text: str) -> dict[int, str]:
    """uid -> user name from `/etc/passwd` lines or `name:uid` pairs (what the remote script sends)."""
    out: dict[int, str] = {}
    for line in text.splitlines():
        f = line.split(":")
        uid = to_int(f[2]) if len(f) >= 3 else to_int(f[1]) if len(f) == 2 else None
        if uid is not None:
            out.setdefault(uid, f[0])
    return out


def _split_command(value: str) -> list[str]:
    try:
        return shlex.split(value, posix=True)
    except ValueError:
        return value.split()


def parse_unit_file(text: str) -> dict[str, Any]:
    """A systemd unit file: first effective `ExecStart` (an empty `ExecStart=` resets the list; prefixes `-@:+!`
    stripped; with `@` the second token is argv[0] and dropped), `User`, `Type`, and `Unit` of a `[Timer]`."""
    out: dict[str, Any] = {}
    section = ""
    execs: list[str] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        while line.endswith("\\") and i + 1 < len(lines):      # continuation
            i += 1
            line = line[:-1] + " " + lines[i].strip()
        i += 1
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        k, sep, v = line.partition("=")
        if not sep:
            continue
        k, v = k.strip(), v.strip()
        if section == "Service" and k == "ExecStart":
            if v:
                execs.append(v)
            else:
                execs = []
        elif section == "Service" and k in ("User", "Type"):
            out[k.lower()] = v
        elif section == "Timer" and k == "Unit":
            out["unit"] = v
        elif section == "Unit" and k == "Description":
            out["description"] = v[:200]
    if execs:
        v = execs[0]
        prefix = ""
        while v and v[0] in "@-:+!":
            prefix += v[0]
            v = v[1:]
        argv = _split_command(v)
        if "@" in prefix and len(argv) >= 2:
            argv = [argv[0], *argv[2:]]
        out["exec"] = argv
    return out


_FIELD_CODE = re.compile(r"^%[fFuUdDnNickvm]$")


def parse_desktop_entry(text: str) -> dict[str, Any]:
    """`[Desktop Entry]` of an XDG autostart file: Exec (field codes like `%u` dropped), Name, and whether it is
    turned off (`Hidden=true`, `X-GNOME-Autostart-enabled=false`)."""
    out: dict[str, Any] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section != "Desktop Entry" or "=" not in line or line.startswith("#"):
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if k == "Exec" and "exec" not in out:
            out["exec"] = [a for a in _split_command(v) if not _FIELD_CODE.match(a)]
        elif k == "Name" and "name" not in out:
            out["name"] = v[:200]
        elif k == "Hidden" and v.lower() == "true" or k == "X-GNOME-Autostart-enabled" and v.lower() == "false":
            out["disabled"] = True
    return out


_ENV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")


def parse_crontab(text: str, system: bool) -> list[dict[str, Any]]:
    """Crontab entries: {line, schedule, user (system format only), command}. `/etc/crontab` and `/etc/cron.d/*`
    have a user field after the schedule; user crontabs do not. Variable assignments and comments are skipped."""
    out: list[dict[str, Any]] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or _ENV_LINE.match(line):
            continue
        f = line.split()
        if f[0].startswith("@"):
            sched, rest = f[0], f[1:]
        elif len(f) >= 6:
            sched, rest = " ".join(f[:5]), f[5:]
        else:
            continue
        user = None
        if system:
            if len(rest) < 2:
                continue
            user, rest = rest[0], rest[1:]
        if rest:
            out.append({"line": n, "schedule": sched, "user": user, "command": " ".join(rest)})
    return out


_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def strip_env(argv: list[str]) -> list[str]:
    """Drop leading `NAME=value` assignments (and an `env [-i] NAME=value ...` wrapper) before the program: they
    are not the program and often carry secrets (`PGPASSWORD=... pg_dump`)."""
    i = 0
    if argv and posixpath.basename(argv[0]) == "env":
        i = 1
        while i < len(argv) and argv[i].startswith("-") and argv[i] != "--":
            i += 1
        if i < len(argv) and argv[i] == "--":
            i += 1
    while i < len(argv) and _ASSIGN.match(argv[i]):
        i += 1
    return argv[i:]


def safe_command(name: str) -> str:
    """A bare program name kept for display: redacted and capped."""
    return str(redact_command(name[:256]))


def cron_program(command: str) -> tuple[str | None, list[str]]:
    """Program of a cron command line: the first segment (split on `&&`, `||`, `;`; `%` starts stdin) that starts
    with an absolute path, else the first word of the last segment (`cd / && run-parts ...` -> `run-parts`).
    Debian's `test -x X && X` idiom yields X."""
    segs = [strip_env(_split_command(seg.strip())) for seg in re.split(r"&&|\|\||;", command.split("%", 1)[0])]
    segs = [t for t in segs if t]
    for tok in segs:
        if tok[0].startswith("/"):
            return tok[0], tok[1:]
    return (segs[-1][0], segs[-1][1:]) if segs else (None, [])


def parse_dpkg_search(text: str, path: str | None = None) -> list[str]:
    """`dpkg-query -S <path>` -> owning package names (`pkg:arch` reduced to `pkg`); diversion lines skipped."""
    out: list[str] = []
    for line in text.splitlines():
        if line.startswith(("diversion by", "local diversion")):
            continue
        pkgs, sep, p = line.partition(": ")
        if not sep or (path is not None and p.strip() not in _variants(path)):
            continue
        for name in pkgs.split(","):
            name = name.strip().split(":", 1)[0]
            if name and name not in out:
                out.append(name)
    return out


def dpkg_search_index(text: str) -> dict[str, list[str]]:
    """`dpkg-query -S -- <many paths>` output -> path -> owning packages (same rules as `parse_dpkg_search`)."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if line.startswith(("diversion by", "local diversion")):
            continue
        pkgs, sep, path = line.partition(": ")
        if not sep:
            continue
        names = out.setdefault(path.strip(), [])
        for name in pkgs.split(","):
            name = name.strip().split(":", 1)[0]
            if name and name not in names:
                names.append(name)
    return out


def parse_rpm_query(text: str) -> list[dict[str, Any]]:
    """`rpm -qf --queryformat '%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\t%{INSTALLTIME}
    \\t%{VENDOR}\\n'` rows ("file ... is not owned by any package" lines ignored)."""
    out = []
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) != 8 or not f[0] or not f[2]:
            continue
        none = ("(none)", "")
        srpm = None if f[5] in none else f[5]
        out.append({"name": f[0], "epoch": to_int(f[1]), "version": f[2],
                    "release": None if f[3] in none else f[3], "arch": None if f[4] in none else f[4],
                    "source_rpm": srpm, "source_name": rpm_source_name(srpm, f[0]),
                    "vendor": None if f[7] in none else f[7], "install_time": iso_time(to_int(f[6]))})
    return out


def iso_time(ts: float | None) -> str | None:
    """Epoch seconds -> ISO 8601 UTC; None for values datetime cannot represent (hostile or broken input)."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, UTC).replace(microsecond=0).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def parse_apk_files(text: str, wanted: set[str] | None = None) -> dict[str, str]:
    """`/lib/apk/db/installed` file lists (`F:` folder, `R:` file under it) -> absolute path -> package name."""
    out: dict[str, str] = {}
    pkg = folder = None
    for line in text.splitlines():
        if not line.strip():
            pkg = folder = None
        elif line.startswith("P:"):
            pkg = line[2:].strip()
        elif line.startswith("F:"):
            folder = line[2:].strip()
        elif line.startswith("R:") and pkg:
            p = "/" + posixpath.join(folder or "", line[2:].strip())
            if wanted is None or p in wanted:
                out.setdefault(p, pkg)
    return out


def _variants(path: str) -> list[str]:
    """The same file under merged-/usr (`/bin/x` == `/usr/bin/x`): packages may list either form."""
    out = [path]
    if path.startswith("/usr/") and path[4:].startswith(("/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/")):
        out.append(path[4:])
    elif path.startswith(("/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/")):
        out.append("/usr" + path)
    return out


def os_info(os_release: str, debian_version: str = "") -> dict[str, Any]:
    """os-release -> `Snapshot.os` (name, version, vendor + the keys the OS component and distro ecosystem need)."""
    osr = parse_os_release(os_release) if os_release else {}
    if not osr:
        return {"name": "Linux"}
    out = {"name": osr.get("NAME") or osr.get("ID") or "Linux", "version": osr.get("VERSION_ID"),
           "vendor": osr.get("ID"), "id": osr.get("ID"), "id_like": osr.get("ID_LIKE"),
           "pretty_name": osr.get("PRETTY_NAME"), "codename": osr.get("VERSION_CODENAME"),
           "ubuntu_codename": osr.get("UBUNTU_CODENAME"), "debian_codename": osr.get("DEBIAN_CODENAME"),
           "cpe_name": osr.get("CPE_NAME"), "debian_version": debian_version.strip()[:64] or None}
    return {k: v for k, v in out.items() if v}


def os_release_of(os_: dict[str, Any]) -> dict[str, str]:
    """`Snapshot.os` (untrusted when loaded from a file) back to os-release keys."""
    keys = {"NAME": "name", "VERSION_ID": "version", "ID": "id", "ID_LIKE": "id_like", "PRETTY_NAME": "pretty_name",
            "VERSION_CODENAME": "codename", "UBUNTU_CODENAME": "ubuntu_codename",
            "DEBIAN_CODENAME": "debian_codename", "CPE_NAME": "cpe_name"}
    return {k: os_[v][:256] for k, v in keys.items() if isinstance(os_.get(v), str) and os_[v]}


# ------------------------------------------------------------------ distro package components (same as rootfs)

def package_component(kind: str, p: dict[str, Any], osr: dict[str, str], ecosystem: str | None,
                      source_path: str | None = None) -> Component:
    """An os-package component built exactly like `rootfs.collect_from_view` does (same purl, ecosystem, meta keys),
    for owners resolved without the package database at hand (remote `dpkg-query` / `rpm -qf`)."""
    ns_id = osr.get("ID") or ""
    qual = _distro_qualifier(osr)
    if kind == "deb":
        q = {"arch": p.get("arch"), "distro": qual}
        if p["source"] != p["name"]:
            q["upstream"] = p["source"]
        return Component(
            name=p["name"], version=p["version"], category=CAT_OS_PACKAGE, ecosystem=ecosystem,
            purl=purls.build("deb", p["name"], p["version"], namespace=ns_id or "debian", qualifiers=q),
            vendor=ns_id or None, source_path=source_path,
            meta={"pkg_type": "deb", "arch": p.get("arch"), "source_package": p["source"],
                  "source_version": p["source_version"]})
    if kind == "apk":
        q = {"arch": p.get("arch"), "distro": qual}
        if p["origin"] != p["name"]:
            q["upstream"] = p["origin"]
        return Component(
            name=p["name"], version=p["version"], category=CAT_OS_PACKAGE, ecosystem=ecosystem,
            purl=purls.build("apk", p["name"], p["version"], namespace=ns_id or "alpine", qualifiers=q),
            vendor=ns_id or None, source_path=source_path,
            meta={"pkg_type": "apk", "arch": p.get("arch"), "source_package": p["origin"],
                  "source_version": p["version"]})
    epoch = p.get("epoch")
    ver_rel = f"{p['version']}-{p['release']}" if p.get("release") else p["version"]
    q = {"arch": p.get("arch"), "distro": qual}
    if epoch is not None:
        q["epoch"] = str(epoch)
    if p["source_name"] != p["name"]:
        q["upstream"] = p["source_name"]
    full = f"{epoch if epoch is not None else 0}:{ver_rel}"
    ns = _PURL_NS.get(ns_id, ns_id) or "redhat"
    return Component(
        name=p["name"], version=full, category=CAT_OS_PACKAGE, ecosystem=ecosystem,
        purl=purls.build("rpm", p["name"], ver_rel, namespace=ns, qualifiers=q),
        vendor=ns_id or p.get("vendor"), source_path=source_path,
        meta={"pkg_type": "rpm", "arch": p.get("arch"), "epoch": epoch, "release": p.get("release"),
              "source_package": p["source_name"], "source_version": full, "source_rpm": p.get("source_rpm")})


def identity_of(c: Component, install_time: str | None = None) -> dict[str, Any]:
    """Component -> `executables[path].identity` (snapshot form, see snapshot._IDENT)."""
    d: dict[str, Any] = {"name": c.name, "version": c.version, "category": c.category, "purl": c.purl,
                         "ecosystem": c.ecosystem, "install_time": install_time}
    for k in ("source_package", "source_version", "arch", "pkg_type"):
        if isinstance(c.meta.get(k), str):
            d[k] = c.meta[k]
    return {k: v for k, v in d.items() if v is not None}


# ============================================================================ capture -> snapshot

def _scope_of(path: str) -> tuple[str, str | None]:
    """(scope, user) of a configuration file: `user:<name>` below /home/<name> or /root, else system."""
    m = re.match(r"^/home/([^/]+)/", path)
    if m:
        return f"user:{m.group(1)}", m.group(1)
    if path.startswith("/root/"):
        return "user:root", "root"
    return "system", None


def launch_items(cap: Capture, resolve_program: Any = None) -> list[LaunchItem]:
    """Launch items from the unit files, masked units, autostart entries and crontabs of a capture.
    `resolve_program(name)` turns a bare command (`ExecStart=foo`, `Exec=nm-applet`) into an absolute path."""
    def program_of(argv: list[str]) -> tuple[str | None, list[str], dict[str, Any]]:
        argv = strip_env(argv)
        if not argv:
            return None, [], {}
        prog, extra = argv[0], {}
        if not prog.startswith("/"):
            extra["command"] = safe_command(prog)
            prog = resolve_program(prog) if resolve_program else None
        return prog, list(redact_command(argv[1:32]) or []), extra

    items: list[LaunchItem] = []
    seen: set[tuple[str, str, str]] = set()
    timers: dict[tuple[str, str], tuple[str, str]] = {}     # (scope, service) -> (timer name, timer path)
    masked = set(cap.masked)
    entries = [(p, None) for p in cap.masked] + [(p, t) for p, t in cap.units]
    # precedence: the capture lists files in directory precedence order, masks first within the same scope
    for path, text in entries:
        name = posixpath.basename(path)
        scope, user = _scope_of(path)
        user_unit = scope != "system" or path.startswith(USER_UNIT_DIRS)
        mech = "systemd-user" if user_unit else "systemd-system"
        key = (mech, scope, name)
        if key in seen:
            continue
        seen.add(key)
        if name.endswith(".timer"):
            if text is not None:
                unit = parse_unit_file(text).get("unit") or name[:-len(".timer")] + ".service"
                timers[(scope, unit)] = (name, path)
            continue
        if not name.endswith(".service"):
            continue
        if path in masked:
            items.append(LaunchItem(mechanism=mech, label=name, program=None, source=path, scope=scope,
                                    disabled=True, meta={"masked": True}))
            continue
        u = parse_unit_file(text or "")
        prog, args, meta = program_of(u.get("exec") or [])
        if u.get("user"):
            meta["UserName"] = u["user"]
        elif user:
            meta["UserName"] = user
        for k in ("type", "description"):
            if u.get(k):
                meta[k] = u[k]
        items.append(LaunchItem(mechanism=mech, label=name, program=prog, args=args, source=path, scope=scope,
                                meta=meta))
    for it in items:
        t = timers.get((it.scope or "system", it.label))
        if t:                                   # started by a .timer: scheduled, not a long-running service
            it.meta["timer"], it.meta["timer_source"] = t
            it.meta["service_mechanism"] = it.mechanism
            it.mechanism = "systemd-timer"
    for path, text in cap.autostart:
        d = parse_desktop_entry(text)
        scope, user = _scope_of(path)
        prog, args, meta = program_of(d.get("exec") or [])
        if d.get("name"):
            meta["name"] = d["name"]
        label = posixpath.basename(path).removesuffix(".desktop")
        items.append(LaunchItem(mechanism="xdg-autostart", label=label, program=prog, args=args, source=path,
                                scope=scope, run_at_load=True, disabled=True if d.get("disabled") else None,
                                meta=meta))
    for path, text in cap.crontabs:
        system = path in SYSTEM_CRONTABS or posixpath.dirname(path) in SYSTEM_CRON_DIRS
        owner = None if system else posixpath.basename(path)
        for e in parse_crontab(text, system):
            prog, args = cron_program(e["command"])
            meta: dict[str, Any] = {"schedule": e["schedule"]}
            if prog and not prog.startswith("/"):
                meta["command"] = safe_command(prog)
                prog = resolve_program(prog) if resolve_program else None
            run_as = e["user"] or owner
            if run_as:
                meta["UserName"] = run_as
            items.append(LaunchItem(mechanism="cron", label=f"{path}:{e['line']}", program=prog,
                                    args=list(redact_command(args[:31]) or []), source=path,
                                    scope="system" if system else f"user:{owner}", meta=meta))
    return items


def snapshot_from_capture(cap: Capture, opts: dict[str, Any], host: str,
                          resolve_program: Any = None) -> Snapshot:
    """Pure: a `Capture` (local or remote) -> `Snapshot` with processes, labels, launch items, OS."""
    warnings = list(cap.warnings)
    users = parse_passwd(cap.passwd)
    keep_kthreads = _flag(opts.get("kernel_threads"), False)
    with_args = _flag(opts.get("args"), True)
    procs: list[ProcessRecord] = []
    executables: dict[str, dict[str, Any]] = {}
    cgroups: dict[int, str] = {}
    units: dict[int, str] = {}
    denied = kthreads = 0
    host_root = next((r.root_id for r in cap.procs if r.pid == 1), "")
    for raw in cap.procs:
        st = parse_stat(raw.stat)
        if st is None or st["pid"] != raw.pid:
            continue
        status = parse_status(raw.status) if raw.status else {}
        exe, deleted = parse_exe_link(raw.exe)
        kthread = bool(st["flags"] & PF_KTHREAD) or raw.pid == 2 or (st["ppid"] == 2 and exe is None)
        if kthread:
            kthreads += 1
            if not keep_kthreads:
                continue
        elif exe is None and raw.exe_denied and cap.uid != 0 and st["state"] not in ("Z", "X"):
            denied += 1                 # zombies have no executable; root reads every link
        if exe and deleted:
            executables.setdefault(exe, {})["exists"] = False
        cg = parse_cgroup(raw.cgroup) if raw.cgroup else {}
        if not cg.get("container") and raw.root_id and host_root and raw.root_id != host_root:
            # another root filesystem (chroot, RootDirectory=, a sandbox the cgroup does not name): its executable
            # paths are not the host's files
            cg["container"] = {"runtime": "chroot", "id": cg.get("unit") or raw.root_id}
        uid = status.get("uid")
        p = ProcessRecord(
            pid=raw.pid, ppid=st["ppid"], exe=exe, uid=uid, user=users.get(uid) if uid is not None else None,
            started=started_at(st["starttime"], cap.btime, cap.clk_tck),
            args=parse_cmdline(raw.cmdline) if with_args else [], name=status.get("name") or st["comm"],
            cgroup=cg.get("path") or None, container=cg.get("container"))
        procs.append(p)
        if cg.get("path"):
            cgroups[p.pid] = cg["path"]
        unit = cg.get("unit")
        if unit and (unit.endswith(".service") or unit.startswith("app-")):
            units[p.pid] = unit
    # the unit labels its main process only (the one whose parent is outside the unit's cgroup), like `launchctl
    # list` names one pid per job: workers and helpers stay children of it
    for p in procs:
        if p.pid in units and cgroups.get(p.ppid) != cgroups.get(p.pid):
            p.label = units[p.pid]
    if denied:
        warnings.append(f"executable of {denied} process(es) unreadable (other users' processes; not root): their "
                        "identity is unknown (run as root, or -o sudo=true over ssh)")
    items = launch_items(cap, resolve_program)
    return Snapshot(platform="linux", host=host, taken_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
                    processes=procs, launch_items=items, os=os_info(cap.os_release, cap.debian_version),
                    executables=executables, warnings=warnings)


def _flag(v: Any, default: bool) -> bool:
    if v is None:
        return default
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


# ============================================================================ local capture

def _read(path: Path, boundary: Path, cap: int) -> bytes | None:
    try:
        return read_within(path, boundary, cap)
    except (OSError, ValueError):
        return None


def _text(path: Path, boundary: Path, cap: int = MAX_CONFIG_BYTES) -> str | None:
    data = _read(path, boundary, cap)
    return data.decode("utf-8", "replace") if data is not None else None


def _list(d: Path, label: str, warnings: list[str]) -> list[Path]:
    try:
        return sorted(d.iterdir())
    except (FileNotFoundError, NotADirectoryError):
        return []
    except PermissionError:
        warnings.append(f"cannot list {label}: permission denied (not indexed; run as root)")
        return []
    except OSError as e:
        warnings.append(f"cannot list {label}: {type(e).__name__}: {e}")
        return []


def _homes(root: Path, opt: Any) -> list[Path]:
    if opt:
        return [Path(h) for h in (opt if isinstance(opt, list) else [opt])]
    out = [h for h in _list(root / "home", "/home", []) if h.is_dir() and not h.is_symlink()]
    if (root / "root").is_dir() and not (root / "root").is_symlink():
        out.append(root / "root")
    return out


def _target(p: Path, root: Path) -> str:
    try:
        return "/" + p.relative_to(root).as_posix()
    except ValueError:
        return str(p)


def read_local_capture(root: Path, opts: dict[str, Any]) -> Capture:
    """Read `<root>/proc` and the launch configuration under `root` (`/` = this machine)."""
    live = str(root) == "/"
    boundary = root.resolve()
    cap = Capture(begun=True, complete=True)
    proc = root / "proc"
    cap.ostype = (_text(proc / "sys/kernel/ostype", boundary, 256) or "").strip()
    cap.hostname = (_text(proc / "sys/kernel/hostname", boundary, 256)
                    or _text(root / "etc/hostname", boundary, 256) or "").strip()
    cap.boot_id = (_text(proc / "sys/kernel/random/boot_id", boundary, 256) or "").strip()
    cap.btime = parse_proc_btime(_text(proc / "stat", boundary, MAX_PROC_FILE) or "")
    if live and hasattr(os, "sysconf"):
        with contextlib.suppress(ValueError, OSError):
            cap.clk_tck = os.sysconf("SC_CLK_TCK")
        cap.uid = os.geteuid()
    cap.clk_tck = cap.clk_tck or int(opts.get("clk_tck") or 100)
    cap.os_release = _text(root / "etc/os-release", boundary, 65536) or _text(root / "usr/lib/os-release",
                                                                              boundary, 65536) or ""
    cap.debian_version = _text(root / "etc/debian_version", boundary, 256) or ""
    cap.passwd = _text(root / "etc/passwd", boundary, 16 * 1024 * 1024) or ""
    try:
        pids = sorted(int(e.name) for e in proc.iterdir() if e.name.isdigit())
    except OSError as e:
        raise RuntimeError(f"cannot list {proc}: {type(e).__name__}: {e} (no process list without /proc)") from e
    for pid in pids:
        d = proc / str(pid)
        st = _read(d / "stat", boundary, MAX_PROC_FILE)
        if not st:
            continue                    # exited meanwhile
        raw = RawProc(pid=pid, stat=st, status=(_text(d / "status", boundary, MAX_PROC_FILE) or ""),
                      cmdline=_read(d / "cmdline", boundary, MAX_CMDLINE) or b"",
                      cgroup=_text(d / "cgroup", boundary, MAX_PROC_FILE) or "")
        try:
            raw.exe = os.readlink(d / "exe")          # never followed: only the path string is used
        except PermissionError:
            raw.exe_denied = True
        except OSError:
            pass                                       # zombie / kernel thread: no executable
        with contextlib.suppress(OSError):
            st = os.stat(d / "root")                   # stat only: which root filesystem the process sees
            raw.root_id = f"{st.st_dev}:{st.st_ino}"
        cap.procs.append(raw)
    _local_launch_files(root, boundary, opts, cap)
    return cap


def _local_launch_files(root: Path, boundary: Path, opts: dict[str, Any], cap: Capture) -> None:
    w = cap.warnings
    homes = _homes(root, opts.get("home"))
    unit_dirs = [(root / d.lstrip("/"), None) for d in (*SYSTEM_UNIT_DIRS, *USER_UNIT_DIRS)]
    unit_dirs += [(h / HOME_UNIT_DIR, h) for h in homes]
    for d, home in unit_dirs:
        for f in _list(d, _target(d, root), w):
            if not f.name.endswith((".service", ".timer")) or (home is not None and not _inside_home(f, home)):
                continue
            t = _target(f, root)
            with contextlib.suppress(OSError):
                if f.is_symlink() and os.readlink(f) == "/dev/null":
                    cap.masked.append(t)
                    continue
            text = _text(f, boundary)
            if text is not None:
                cap.units.append((t, text))
    for d, home in [(root / AUTOSTART_DIR.lstrip("/"), None), *((h / HOME_AUTOSTART_DIR, h) for h in homes)]:
        for f in _list(d, _target(d, root), w):
            if f.name.endswith(".desktop") and (home is None or _inside_home(f, home)):
                text = _text(f, boundary)
                if text is not None:
                    cap.autostart.append((_target(f, root), text))
    files = [root / p.lstrip("/") for p in SYSTEM_CRONTABS]
    for d in (*SYSTEM_CRON_DIRS, *USER_CRON_DIRS):
        files += [f for f in _list(root / d.lstrip("/"), d, w) if f.is_file() and not f.name.startswith(".")]
    for f in files:
        t = _target(f, root)
        try:
            text = read_within(f, boundary, MAX_CONFIG_BYTES).decode("utf-8", "replace")
        except FileNotFoundError:
            continue
        except PermissionError:
            w.append(f"cannot read crontab {t}: permission denied (run as root)")
            continue
        except (OSError, ValueError):
            continue
        cap.crontabs.append((t, text))


def _inside_home(f: Path, home: Path) -> bool:
    """A file under a user's home is the user's: never a symlink, never through a linked directory (a user could
    otherwise point `~/.config/autostart/x.desktop` at a root-only file)."""
    try:
        return not f.is_symlink() and f.resolve().parent == f.parent.resolve() and \
            f.parent.resolve().is_relative_to(home.resolve())
    except OSError:
        return False


def _local_resolver(root: Path) -> Any:
    def resolve(name: str) -> str | None:
        if "/" in name or not name:
            return None
        for d in BIN_DIRS:
            if os.path.lexists(root / d.lstrip("/") / name):
                return f"{d}/{name}"
        return None
    return resolve


def take_snapshot(root: Path, opts: dict[str, Any]) -> Snapshot:
    """Live process snapshot of this Linux machine (or of a `/proc` + config tree under `root`, for tests)."""
    cap = read_local_capture(root, opts)
    if cap.ostype and cap.ostype.lower() != "linux":
        cap.warnings.append(f"kernel reports {cap.ostype!r}, not Linux")
    if str(root) == "/" and cap.uid not in (0, None):
        cap.warnings.append("not running as root: other users' executables and crontabs may be missing")
    host = opts.get("hostname") or (socket.gethostname() if str(root) == "/" else None) or cap.hostname or "unknown"
    snap = snapshot_from_capture(cap, opts, host, _local_resolver(root))
    if cap.boot_id:
        snap.source = {"kind": "local", "boot_id": cap.boot_id}
    return snap


# ============================================================================ executable inspector

class _PackageDbView(FsView):
    """The package databases of a tree, without the language-package walk `collect_from_view` does on a DirView."""

    def __init__(self, root: Path):
        self.dir = DirView(root)
        self.root = self.dir.root

    def _readlink(self, path: str) -> str | None:
        return self.dir._readlink(path)

    def _read_raw(self, path: str, limit: int) -> bytes | None:
        return self.dir._read_raw(path, limit)

    def _listdir_raw(self, path: str) -> list[str]:
        return self.dir._listdir_raw(path)

    def iter_lang_files(self):
        return iter(())


def _run(cmd: list[str], timeout: int = CMD_TIMEOUT) -> subprocess.CompletedProcess:
    """Fixed read-only command (only `rpm -qf --queryformat ... -- <path>`)."""
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, check=False, env={**os.environ, "LC_ALL": "C"})


RPM_QUERYFORMAT = ("%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\t%{INSTALLTIME}"
                   "\\t%{VENDOR}\\n")
_SNAP = re.compile(r"^/snap/(?P<name>[^/]+)/(?P<rev>[^/]+)/")
_FLATPAK = re.compile(r"^(?:/var/lib/flatpak|/home/[^/]+/\.local/share/flatpak)/app/(?P<id>[^/]+)/(?P<arch>[^/]+)/"
                      r"(?P<branch>[^/]+)/")
_BREW = re.compile(r"^(?P<prefix>.*?)/Cellar/(?P<name>[^/]+)/(?P<ver>[^/]+)/")


class LinuxInspector(Inspector):
    """Executable -> identity + provenance on Linux.

    `root` is `/` for this machine, a copied tree (tests, a mounted disk), or None for a snapshot taken elsewhere
    (remote over ssh: package owners arrive precomputed in `executables[path].identity`; the rest by path only).
    """

    def __init__(self, snap: Snapshot, root: Path | None, opts: dict[str, Any], warnings: list[str]):
        super().__init__(snap, opts, warnings)
        self.root = root
        self.fs = root is not None
        self.boundary = root.resolve() if root is not None else None
        self.live = root is not None and str(root) == "/" and sys.platform.startswith("linux")
        self.max_binary = int(opts.get("max_binary_mb", DEFAULT_MAX_BINARY // (1024 * 1024))) * 1024 * 1024
        self._facts: dict[str, dict[str, Any]] = {}
        self._reported: set[str] = set()
        self._pkgs: dict[str, dict[str, Component]] | None = None    # kind -> name -> component
        self._owners: dict[str, tuple[str, str, str | None]] = {}     # path -> (kind, package, install time)
        self._stamp: tuple | None = None
        self._osr = os_release_of(snap.os)

    def _once(self, key: str, message: str) -> None:
        if key not in self._reported:
            self._reported.add(key)
            self.warnings.append(message)

    # ------------------------------------------------------------------ paths
    def local(self, target: str) -> Path:
        assert self.root is not None
        return Path(target) if str(self.root) == "/" else self.root / target.lstrip("/")

    def target(self, local: Path) -> str:
        assert self.root is not None and self.boundary is not None
        return str(local) if str(self.root) == "/" else _target(local, self.boundary)

    def real_target(self, target: str) -> str | None:
        if not self.fs:
            return None
        try:
            return self.target(resolve_within(self.local(target), self.boundary))
        except ValueError:
            return None

    # ------------------------------------------------------------------ identity
    def os_component(self) -> Component | None:
        if self._os is None and self._osr.get("VERSION_ID"):
            dv = self.snap.os.get("debian_version") if isinstance(self.snap.os.get("debian_version"), str) else None
            self._os = _os_component(self._osr, distro_ecosystem(self._osr, dv))
        return self._os

    def _ecosystem(self) -> str | None:
        osc = self.os_component()
        return osc.meta.get("osv_ecosystem") if osc is not None else None

    def resolve(self, exe: str) -> Resolution:
        res = super().resolve(exe)
        if res.method not in ("none", "container") and (self.snap.executables.get(exe) or {}).get("exists") is False:
            # the running binary was deleted or replaced (an upgrade without restart): the identity describes the
            # file installed at that path now, the running version is probably older
            res.notes["version_is_installed_not_running"] = True
        return res

    def _resolve(self, exe: str) -> Resolution:
        real = self.real_target(exe) or exe
        for fn in (self._brew, self._snap, self._flatpak, self._package, self._binary):
            res = fn(real)
            if res is None and fn == self._package and real != exe:
                res = fn(exe)                   # a package may own the link (/usr/bin/python3) and not its target
            if res is not None:
                if real != exe:
                    res.notes["resolved_from"] = exe
                return res
        return Resolution("none", [self.unidentified(real)])

    def _brew(self, path: str) -> Resolution | None:
        from ..homebrew import _formula_component, _keg_component

        m = _BREW.match(path)
        if not m:
            return None
        keg_t = path[:m.end() - 1]
        if not self.fs:
            c = _formula_component(m["name"], m["ver"], None)
            c.source_path = keg_t
            return Resolution("brew-keg", [c], anchor=keg_t, notes={"identity": "path-only"})
        prefix, keg = self.local(m["prefix"] or "/"), self.local(keg_t)
        c = _keg_component(prefix, None if str(self.root) == "/" else self.root, m["name"], keg, True, False,
                           self.warnings, self.boundary)
        return Resolution("brew-keg", [c], anchor=keg_t)

    def _snap(self, path: str) -> Resolution | None:
        m = _SNAP.match(path)
        if not m:
            return None
        version = None
        if self.fs:
            text = _text(self.local(f"/snap/{m['name']}/{m['rev']}/meta/snap.yaml"), self.boundary, 1024 * 1024)
            vm = re.search(r"^version:\s*['\"]?([^'\"\s#]+)", text or "", re.MULTILINE)
            version = vm.group(1) if vm else None
        anchor = f"/snap/{m['name']}/{m['rev']}"
        meta = {"snap": m["name"], "snap_revision": m["rev"], "evidence": "snap"}
        if version is None:
            meta["identity"] = "path-only"
        return Resolution("snap", [Component(name=m["name"], version=version, category=CAT_APPLICATION,
                                             source_path=anchor, meta=meta)], anchor=anchor)

    def _flatpak(self, path: str) -> Resolution | None:
        m = _FLATPAK.match(path)
        if not m:
            return None
        anchor = path[:m.end() - 1]
        return Resolution("flatpak", [Component(
            name=m["id"], version=None, category=CAT_APPLICATION, source_path=anchor,
            meta={"flatpak": m["id"], "flatpak_branch": m["branch"], "identity": "path-only"})], anchor=anchor,
            notes={"identity": "path-only"})

    # ---------------------------------------------------------------- distro packages
    def _package_db(self) -> dict[str, dict[str, Component]]:
        """All os-package components of the tree, once (rootfs parsers: dpkg status, apk installed, rpmdb.sqlite)."""
        if self._pkgs is None:
            self._pkgs = {"deb": {}, "apk": {}, "rpm": {}}
            if self.fs and _flag(self.opts.get("packages"), True):
                w: list[str] = []
                try:
                    comps = collect_from_view(_PackageDbView(self.root), Asset(id="process-index", type="server",
                                                                                name="index"), w)
                except Exception as e:  # noqa: BLE001 - a broken package db must not stop the monitor
                    self.warnings.append(f"package index: {type(e).__name__}: {e}")
                    comps = []
                for c in comps:
                    kind = c.meta.get("pkg_type")
                    if kind in self._pkgs:
                        self._pkgs[kind].setdefault(c.name, c)
                self.warnings.extend(f"package index: {x}" for x in w if "operating system not identified" not in x)
        return self._pkgs

    def _db_stamp(self) -> tuple:
        """Changes when a package is installed, removed or upgraded (dpkg info dir, dpkg status, apk db, rpmdb)."""
        out = []
        for t in ("/var/lib/dpkg/info", "/var/lib/dpkg/status", "/lib/apk/db/installed", "/var/lib/rpm",
                  "/usr/lib/sysimage/rpm"):
            try:
                st = self.local(t).stat()
                out.append((st.st_ino, st.st_mtime_ns, st.st_size))
            except OSError:
                out.append(None)
        return tuple(out)

    def _refresh(self) -> None:
        """Path -> owning package for every file of dpkg `info/*.list` and apk `installed` (`F:`/`R:`), built once and
        rebuilt only when the package databases change (--watch after an upgrade)."""
        stamp = self._db_stamp()
        if stamp == self._stamp:
            return
        self._stamp, self._pkgs, self._owners = stamp, None, {}
        dpkg = self.local("/var/lib/dpkg/info")
        total = 0
        for f in _list(dpkg, "/var/lib/dpkg/info", self.warnings):
            if not f.name.endswith(".list"):
                continue
            data = _read(f, self.boundary, 64 * 1024 * 1024)
            if data is None:
                continue
            total += len(data)
            if total > MAX_LIST_BYTES:
                self._once("dpkg-lists", "dpkg file lists exceed the size cap; some executables not attributed")
                break
            hit = ("deb", f.name[:-len(".list")].split(":", 1)[0], self._mtime(f))
            for line in data.decode("utf-8", "replace").splitlines():
                if line.startswith("/") and line not in self._owners:
                    self._owners[line] = hit
        text = _text(self.local("/lib/apk/db/installed"), self.boundary, MAX_APK_DB)
        if text:
            for path, pkg in parse_apk_files(text).items():
                self._owners.setdefault(path, ("apk", pkg, None))

    @staticmethod
    def _mtime(p: Path) -> str | None:
        with contextlib.suppress(OSError):
            return iso_time(p.stat().st_mtime)
        return None

    def _package(self, path: str) -> Resolution | None:
        if not self.fs or not _flag(self.opts.get("packages"), True):
            return None
        self._refresh()
        db = self._package_db()
        for v in _variants(path):
            hit = self._owners.get(v)
            if hit:
                kind, name, when = hit
                c = db[kind].get(name)
                if c is not None:
                    return Resolution("os-package", [c], notes={"pkg_install_time": when} if when else {})
        if self.live and not self.user_writable(path):
            return self._rpm_qf(path, db["rpm"])
        return None

    def _rpm_qf(self, path: str, known: dict[str, Component]) -> Resolution | None:
        """Live rpm hosts: `rpm -qf` (the file lists of rpmdb are not parsed). Once per executable, cached."""
        if not known and not os.path.exists("/var/lib/rpm") and not os.path.exists("/usr/lib/sysimage/rpm"):
            return None
        try:
            r = _run(["rpm", "-qf", "--queryformat", RPM_QUERYFORMAT, "--", path])
        except (OSError, subprocess.SubprocessError) as e:
            self._once("rpm", f"cannot run rpm: {type(e).__name__}: {e}; rpm owners unavailable")
            return None
        rows = parse_rpm_query(r.stdout)
        if not rows:
            return None
        row = rows[0]
        c = known.get(row["name"]) or package_component("rpm", row, self._osr, self._ecosystem())
        return Resolution("os-package", [c], notes={"pkg_install_time": row["install_time"]}
                          if row.get("install_time") else {})

    def _binary(self, path: str) -> Resolution | None:
        if not self.fs or not _flag(self.opts.get("binaries"), True):
            return None
        data = self._read_binary(path)
        if not data:
            return None
        from ..lang import golang, rust

        comps, warns = golang.parse_go_binary_ex(path, data)
        self.warnings.extend(f"{path}: {w}" for w in warns)
        if comps:
            main = [c for c in comps if c.meta.get("main")]
            return Resolution("go-binary", main + [c for c in comps if not c.meta.get("main")])
        with contextlib.suppress(Exception):
            rc = rust.parse_auditable(path, data)
            if rc:
                return Resolution("rust-binary", rc)
        return None

    def _read_binary(self, path: str) -> bytes | None:
        try:
            st = self.local(path).stat()
            if not stat.S_ISREG(st.st_mode) or st.st_size > self.max_binary:
                return None
            return read_within(self.local(path), self.boundary, self.max_binary)
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------ provenance
    def facts(self, exe: str) -> dict[str, Any]:
        """Snapshot-provided facts win (remote facts, `exists: false` of a deleted executable); otherwise file facts."""
        if exe in self._facts:
            return self._facts[exe]
        f = super().facts(exe)
        if not f and self.fs:
            try:
                f = self._facts_fs(exe)
            except Exception as e:  # noqa: BLE001
                self.warnings.append(f"cannot inspect {exe}: {type(e).__name__}: {e}")
        self._facts[exe] = f
        return f

    def _facts_fs(self, exe: str) -> dict[str, Any]:
        from .macos import _sha256

        lp = self.local(exe)
        try:
            lp.lstat()
            real = resolve_within(lp, self.boundary)
            st = real.stat()
        except PermissionError:
            self._once("denied", f"cannot inspect {exe} (and possibly other executables): permission denied")
            return {}
        except ValueError:
            return {"outside_root": True}
        except OSError:
            return {"exists": False}
        f: dict[str, Any] = {"exists": True, "size": st.st_size, "owner_uid": st.st_uid,
                             "mtime": datetime.fromtimestamp(st.st_mtime, UTC).replace(microsecond=0).isoformat()}
        if st.st_mode & stat.S_IWOTH:
            f["world_writable"] = True
        if _flag(self.opts.get("hash"), True) and stat.S_ISREG(st.st_mode) and st.st_size <= self.max_binary:
            with contextlib.suppress(OSError, ValueError):
                f["sha256"] = _sha256(real, self.max_binary)
        return f

    def stamp(self, exe: str) -> tuple | None:
        if not self.fs:
            return None
        try:
            st = resolve_within(self.local(exe), self.boundary).stat()
        except (OSError, ValueError):
            return ("missing",)
        return (st.st_ino, st.st_size, st.st_mtime_ns)

    def forget(self, exe: str) -> None:
        super().forget(exe)
        self._facts.pop(exe, None)

    def user_writable(self, path: str) -> bool:
        return path.startswith(USER_WRITABLE)
