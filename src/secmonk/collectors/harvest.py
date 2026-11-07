"""Harvest spec: which metadata files sec-monk needs from a machine, as a remote `find | tar` script.

Agentless targets (SSH today; WinRM/serial consoles/adb tomorrow) cannot hand us a filesystem, so they
*harvest*: one read-only shell pipeline on the target selects the few metadata files the existing
collectors read and streams them back as a gzip'd tar. `safe_extract` unpacks that stream into a private
temp directory which is then fed to the normal collector (rootfs `collect_from_view(DirView(tmp))` for
Linux, `MacOSCollector().collect(tmp)` for macOS).

Everything here is pure string/file logic (no network), so it is unit-testable:

  * `HarvestSpec` + `build_script()`   — the remote script (POSIX sh, GNU/BSD find, GNU/bsd tar, gzip)
  * `detect_script()` / `parse_detect()` — one command that identifies the remote OS
  * `safe_extract()`                    — hardened tar-stream extraction (no abs paths, `..`, devices,
                                           escaping symlinks; size/count limits)
  * `lang_match()`                      — python mirror of the language-file name filter (drift tests)

See _docs/tech/collectors/ssh.md.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import shlex
import stat
import tarfile
from dataclasses import dataclass, field
from typing import Any, BinaryIO

from .macos import _FRAMEWORKS, MAX_APP_DEPTH
from .rootfs import DPKG_STATUS_D, FIXED_PATHS, MAX_FILE_BYTES, parse_os_release

MB = 1024 * 1024
STREAM_MARKER = "SECMONK-STREAM-BEGIN"      # printed right before the tar bytes (skips login-shell noise)
DETECT_PREFIX = "@@secmonk:"

# --------------------------------------------------------------------------- spec data

#: Linux package databases and OS identification (single source of truth: rootfs.FIXED_PATHS).
LINUX_FIXED_FILES: tuple[str, ...] = tuple(sorted(FIXED_PATHS))
LINUX_FIXED_DIRS: tuple[str, ...] = (DPKG_STATUS_D,)

MACOS_SYSTEM_VERSION = "System/Library/CoreServices/SystemVersion.plist"
MACOS_APP_BASES: tuple[str, ...] = ("Applications", "System/Applications", "Users/*/Applications")
MACOS_RECEIPTS_DIR = "var/db/receipts"
BREW_PREFIXES: tuple[str, ...] = ("opt/homebrew", "usr/local", "home/linuxbrew/.linuxbrew")

#: Language dependency files matched by basename (`find -name`).
LANG_NAMES: tuple[str, ...] = (
    "PKG-INFO", "pyvenv.cfg", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lock", "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "requirements*.txt", "composer.lock",
    "go.mod", "go.sum", "Cargo.lock", "*.deps.json", "packages.lock.json", "project.assets.json",
    "packages.config", "*.csproj", "*.fsproj", "*.vbproj", "Directory.Packages.props", "pom.xml",
    "gradle.lockfile", "verification-metadata.xml",
)
#: ... and by path (`find -path`; `*` also matches `/`, so these over-approximate slightly).
LANG_PATHS: tuple[str, ...] = (
    "*.dist-info/METADATA",
    "*/conda-meta/*.json",
    "*/node_modules/*/package.json",
    "*/node_modules/@*/*/package.json",
    "*/vendor/composer/installed.json",
)
#: A project `package.json` is only harvested when one of these sits next to it.
LOCKFILE_SIBLINGS: tuple[str, ...] = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
                                      "pnpm-lock.yaml", "bun.lock")
#: Optional (binaries=true): archives anywhere, executables in bin dirs (Go buildinfo, cargo-auditable...).
BINARY_NAMES: tuple[str, ...] = ("*.jar", "*.war", "*.ear")
BINARY_EXEC_PATHS: tuple[str, ...] = ("*/bin/*", "*/sbin/*")

#: Subtrees never walked for language files (relative to the search root).
PRUNE_LINUX: tuple[str, ...] = (
    "./proc", "./sys", "./dev", "./run", "./tmp", "./var/tmp", "./var/cache", "./var/lib/docker",
    "./var/lib/containerd", "./snap", "./nix/store", "./lost+found",
)
PRUNE_MACOS: tuple[str, ...] = (
    "./dev", "./Volumes", "./System", "./cores", "./private/tmp", "./private/var/folders",
    "./private/var/vm", "./Library/Caches", "./Users/*/Library/Caches", "./.Spotlight-V100",
    "./.fseventsd", "./.vol", "./Network", "./net", "./tmp",
)
PRUNE_NAMES: tuple[str, ...] = (".git", ".Trash")

_PRUNE_BY_OS = {"linux": PRUNE_LINUX, "macos": PRUNE_MACOS}


@dataclass(frozen=True)
class HarvestSpec:
    os: str                                   # "linux" | "macos"
    root: str = "/"                           # remote path prefix for every harvested path (tests: fixture dir)
    lang: bool = True                         # walk the tree for language dependency files
    binaries: bool = False                    # also harvest *.jar/*.war/*.ear and bin/ executables
    max_binary_bytes: int = 50 * MB
    max_meta_bytes: int = 64 * MB             # per language/manifest file
    max_db_bytes: int = MAX_FILE_BYTES        # per package DB (rpmdb.sqlite can be large)
    xdev: bool | None = None                  # None -> linux True, macos False (firmlinked data volume)
    exclude: tuple[str, ...] = field(default_factory=tuple)   # extra pruned paths, relative to root

    def __post_init__(self) -> None:
        if self.os not in _PRUNE_BY_OS:
            raise ValueError(f"unsupported OS profile {self.os!r}")

    @property
    def use_xdev(self) -> bool:
        return self.xdev if self.xdev is not None else self.os == "linux"


# --------------------------------------------------------------------------- shell builders

def quote(s: str) -> str:
    return shlex.quote(s)


def glob_quote(s: str) -> str:
    """Quote `s` for sh but keep `*` live (spec-controlled globs such as Users/*/Applications)."""
    return "*".join(shlex.quote(p) if p else "" for p in s.split("*"))


def _find(paths: list[str], *expr: str, opts: tuple[str, ...] = (), glob: bool = False) -> str:
    q = glob_quote if glob else quote
    return " ".join(["find", *(q(p) for p in paths), *opts, *expr, "</dev/null", "2>/dev/null"])


def _any(flag: str, values: tuple[str, ...] | list[str]) -> list[str]:
    """`\\( -name a -o -name b \\)`"""
    out: list[str] = ["\\("]
    for i, v in enumerate(values):
        if i:
            out.append("-o")
        out += [flag, quote(v)]
    out.append("\\)")
    return out


def _size(n: int) -> list[str]:
    return ["-size", f"-{n + 1}c"]            # POSIX-ish: both GNU and BSD find accept the `c` suffix


def _norm_exclude(p: str) -> str:
    p = p.strip().replace("\\", "/")
    p = "/".join(x for x in p.split("/") if x not in ("", ".", ".."))
    return "./" + p


def _prune(spec: HarvestSpec) -> list[str]:
    paths = [*dict.fromkeys(_PRUNE_BY_OS[spec.os]), *(_norm_exclude(e) for e in spec.exclude if e.strip("/ ."))]
    toks: list[str] = ["\\(", "\\("]
    for i, p in enumerate(paths):
        if i:
            toks.append("-o")
        toks += ["-path", quote(p)]
    for n in PRUNE_NAMES:
        toks += ["-o", "-name", quote(n)]
    toks += ["\\)", "-prune", "\\)", "-o"]
    return toks


def _walk_head(spec: HarvestSpec) -> tuple[list[str], tuple[str, ...]]:
    return ["."], (("-xdev",) if spec.use_xdev else ())


def _lang_names_expr() -> list[str]:
    toks = ["\\("]
    toks += _any("-name", LANG_NAMES)
    toks += ["-o"] + _any("-path", LANG_PATHS)
    toks.append("\\)")
    return toks


def linux_fixed_commands(spec: HarvestSpec) -> list[str]:
    files = list(LINUX_FIXED_FILES) + list(LINUX_FIXED_DIRS)
    return [_find(files, "\\(", "\\(", "-type", "f", *_size(spec.max_db_bytes), "\\)", "-o", "-type", "l", "\\)",
                  "-print0", opts=("-maxdepth", "1"))]


def macos_fixed_commands(spec: HarvestSpec) -> list[str]:
    cmds = [
        _find([MACOS_SYSTEM_VERSION], "-type", "f", "-print0", opts=("-maxdepth", "0")),
        _find([MACOS_RECEIPTS_DIR], "-type", "f", "-name", quote("*.plist"), "-print0", opts=("-maxdepth", "1")),
    ]
    # .app bundles: Info.plist, MAS receipt marker, bundled Electron/CEF/Sparkle framework Info.plists
    paths = ["*.app/Contents/Info.plist", "*.app/Contents/_MASReceipt/receipt"]
    for fw in _FRAMEWORKS:
        paths.append(f"*.app/Contents/Frameworks/{fw}/Versions/*/Resources/Info.plist")
        paths.append(f"*.app/Contents/Frameworks/{fw}/Resources/Info.plist")
    heavy = ["MacOS", "Resources", "PlugIns", "XPCServices", "Library", "SharedSupport"]
    prune = ["\\("]
    for i, h in enumerate(heavy):
        if i:
            prune.append("-o")
        prune += ["-path", quote(f"*.app/Contents/{h}")]
    prune += ["\\)", "-prune", "-o"]
    max_depth = MAX_APP_DEPTH + 6
    cmds.append(_find(list(MACOS_APP_BASES), *prune, "\\(", "-type", "f", *_any("-path", paths), "-print0", "\\)",
                      opts=("-maxdepth", str(max_depth)), glob=True))
    for p in BREW_PREFIXES:
        cmds += _brew_commands(p, spec)
    return cmds


def _brew_commands(prefix: str, spec: HarvestSpec) -> list[str]:
    cellar, caskroom, opt = f"{prefix}/Cellar", f"{prefix}/Caskroom", f"{prefix}/opt"
    cellar_paths = [f"{cellar}/*/*/INSTALL_RECEIPT.json", f"{cellar}/*/*/sbom.spdx.json",
                    f"{cellar}/*/*/.brew/*.rb"]
    meta_size = _size(spec.max_meta_bytes)
    return [
        _find([cellar], "-type", "f", *_any("-path", cellar_paths), *meta_size, "-print0",
              opts=("-mindepth", "3", "-maxdepth", "4")),
        # Caskroom/<token>/<version> directories are markers (empty entries: tar runs --no-recursion)
        _find([caskroom], "-type", "d", "-print0", opts=("-mindepth", "2", "-maxdepth", "2")),
        _find([caskroom], "\\(", "-type", "d", "-o", "-type", "f", "-o", "-type", "l", "\\)",
              "-name", quote("*.app"), "-print0", opts=("-mindepth", "3", "-maxdepth", "3")),
        _find([f"{caskroom}/*/.metadata"], "-type", "f", "\\(", "-name", quote("*.json"), "-o", "-name",
              quote("*.rb"), "\\)", *meta_size, "-print0", glob=True),
        _find([opt], "-type", "l", "-print0", opts=("-mindepth", "1", "-maxdepth", "1")),
    ]


def lang_commands(spec: HarvestSpec) -> list[str]:
    paths, head = _walk_head(spec)
    prune = _prune(spec)
    body = ["\\(", *_lang_names_expr(), *_size(spec.max_meta_bytes), "\\)"]
    if spec.binaries:
        cap = _size(spec.max_binary_bytes)
        body += ["-o", "\\(", *_any("-name", BINARY_NAMES), *cap, "\\)"]
        body += ["-o", "\\(", "-perm", "-100", *_any("-path", BINARY_EXEC_PATHS), *cap, "\\)"]
    walk = _find(paths, *prune, "\\(", "-type", "f", "\\(", *body, "\\)", "-print0", "\\)", opts=head)
    # project package.json next to a lockfile (the lockfile itself is harvested above)
    sib_script = 'for f; do d=${f%/*}; [ -f "$d/package.json" ] && printf "%s\\0" "$d/package.json"; done'
    siblings = _find(paths, *prune, "\\(", "-type", "f", *_any("-name", LOCKFILE_SIBLINGS),
                     "-exec", "sh", "-c", quote(sib_script), "sh", "{}", "+", "\\)", opts=head)
    return [walk, siblings]


def build_commands(spec: HarvestSpec) -> list[str]:
    """All `find ... -print0` commands whose outputs are concatenated and fed to tar."""
    cmds = linux_fixed_commands(spec) if spec.os == "linux" else macos_fixed_commands(spec)
    if spec.lang:
        cmds += lang_commands(spec)
    return cmds


def build_script(spec: HarvestSpec) -> str:
    """The complete read-only remote script (to be run as `sh -s` with this text on stdin)."""
    cmds = build_commands(spec)
    group = "{\n" + "\n".join(cmds) + "\n}"
    return "\n".join([
        f"cd {quote(spec.root)} || exit 3",
        f"printf '{STREAM_MARKER}\\n'",
        f"{group} | tar --null --no-recursion -T - -czf -",
        "",
    ])


# --------------------------------------------------------------------------- OS detection

def detect_script(root: str = "/") -> str:
    r = root.rstrip("/")
    osr, osr2 = quote(f"{r}/etc/os-release"), quote(f"{r}/usr/lib/os-release")
    sec = DETECT_PREFIX
    mid, mid2 = quote(f"{r}/etc/machine-id"), quote(f"{r}/var/lib/dbus/machine-id")
    return "\n".join([
        f"printf '{sec}kernel@@\\n'; uname -s 2>/dev/null",
        f"printf '{sec}arch@@\\n'; uname -m 2>/dev/null",
        f"printf '{sec}os-release@@\\n'; cat {osr} 2>/dev/null || cat {osr2} 2>/dev/null",
        f"printf '{sec}sw_vers@@\\n'; sw_vers 2>/dev/null",
        f"printf '{sec}hostname@@\\n'; hostname 2>/dev/null",
        # stable machine identity (read-only): systemd machine-id, or the macOS hardware UUID
        f"printf '{sec}machine-id@@\\n'; cat {mid} 2>/dev/null || cat {mid2} 2>/dev/null",
        *([(f"printf '{sec}ioreg@@\\n'; [ \"$(uname -s 2>/dev/null)\" = Darwin ] && "
            "ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | grep IOPlatformUUID")] if not r else []),
        f"printf '{sec}end@@\\n'",
        "",
    ])


@dataclass
class RemoteInfo:
    kernel: str = ""
    arch: str = ""
    os_release: dict[str, str] = field(default_factory=dict)
    sw_vers: dict[str, str] = field(default_factory=dict)
    hostname: str = ""
    machine_id: str = ""                      # raw /etc/machine-id or IOPlatformUUID (never stored raw)
    machine_id_source: str = ""

    @property
    def family(self) -> str | None:
        k = self.kernel.lower()
        if k == "darwin":
            return "macos"
        if k == "linux":
            return "linux"
        return None

    @property
    def description(self) -> str:
        if self.family == "macos":
            return f"macOS {self.sw_vers.get('ProductVersion', '?')}"
        if self.family == "linux":
            return self.os_release.get("PRETTY_NAME") or "Linux"
        return self.kernel or "unknown"


def machine_fingerprint(machine_id: str) -> str:
    """App-specific digest of a machine id: systemd asks that the raw /etc/machine-id is never
    exposed, so inventories only carry this salted hash (stable per machine, not reversible)."""
    return hashlib.sha256(b"secmonk\0machine-id\0" + machine_id.encode()).hexdigest()


def parse_detect(text: str) -> RemoteInfo:
    """Parse `detect_script()` output; anything before the first marker (motd, rc-file noise) is ignored."""
    sections: dict[str, list[str]] = {}
    cur: str | None = None
    for line in text.splitlines():
        if line.startswith(DETECT_PREFIX) and line.endswith("@@"):
            cur = line[len(DETECT_PREFIX):-2]
            sections[cur] = []
        elif cur is not None:
            sections[cur].append(line)
    if "end" not in sections:
        raise ValueError("remote OS detection produced no recognisable output")

    def first(name: str) -> str:
        for ln in sections.get(name, []):
            if ln.strip():
                return ln.strip()
        return ""

    sw: dict[str, str] = {}
    for ln in sections.get("sw_vers", []):
        k, sep, v = ln.partition(":")
        if sep:
            sw[k.strip()] = v.strip()
    mid, src = "", ""
    cand = first("machine-id")
    if re.fullmatch(r"[0-9a-fA-F]{32}", cand):
        mid, src = cand.lower(), "machine-id"
    else:
        m = re.search(r'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"', "\n".join(sections.get("ioreg", [])))
        if m:
            mid, src = m.group(1).upper(), "IOPlatformUUID"
    return RemoteInfo(machine_id=mid, machine_id_source=src,
                      kernel=first("kernel"), arch=first("arch"),
                      os_release=parse_os_release("\n".join(sections.get("os-release", []))),
                      sw_vers=sw, hostname=first("hostname"))


# --------------------------------------------------------------------------- python mirror of the filter

def lang_match(path: str, *, binaries: bool = False) -> bool:
    """Would the harvest's language walk select this (relative, posix) path? Mirrors the find expression."""
    p = "./" + path.lstrip("./") if not path.startswith("./") else path
    base = p.rsplit("/", 1)[-1]
    if any(fnmatch.fnmatchcase(base, n) for n in LANG_NAMES):
        return True
    if any(fnmatch.fnmatchcase(p, g) for g in LANG_PATHS):
        return True
    return bool(binaries and any(fnmatch.fnmatchcase(base, n) for n in BINARY_NAMES))


# --------------------------------------------------------------------------- safe extraction

class HarvestLimitExceeded(Exception):
    """File-count or byte limit hit while extracting; partial results are kept."""


@dataclass
class ExtractStats:
    files: int = 0                 # regular files + symlinks written
    bytes: int = 0                 # regular file content bytes written
    entries: int = 0               # tar members seen
    rejected: list[str] = field(default_factory=list)
    limit: str | None = None       # description when a limit aborted extraction

    def reject(self, name: str, why: str) -> None:
        if len(self.rejected) < 100:
            self.rejected.append(f"{name!r}: {why}")


def _clean_member_path(name: str) -> str | None:
    """Relative posix path inside the root, or None when unsafe/empty. Never resolves `..`."""
    if "\x00" in name or name.startswith("/"):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def _lexical_join(base_dir: str, target: str) -> str | None:
    """Resolve `target` against `base_dir` lexically inside the root; None if it climbs out."""
    parts = [p for p in base_dir.split("/") if p]
    for comp in target.split("/"):
        if comp in ("", "."):
            continue
        if comp == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(comp)
    return "/".join(parts)


def _ensure_parents(dest: str, rel: str) -> str | None:
    """Create parent dirs of `rel` under `dest` without ever traversing a symlink. Returns the full path."""
    cur = dest
    parts = rel.split("/")
    for comp in parts[:-1]:
        cur = os.path.join(cur, comp)
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            os.mkdir(cur, 0o700)
            continue
        if not stat.S_ISDIR(st.st_mode):
            return None                          # symlink or file where a directory is needed
    return os.path.join(cur, parts[-1])


def _clear_final(path: str) -> bool:
    """Remove whatever sits at `path` (never following symlinks) so it can be replaced; False if it is a dir."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return True
    if stat.S_ISDIR(st.st_mode):
        return False
    os.unlink(path)
    return True


def safe_extract(fileobj: BinaryIO, dest: str, *, max_files: int = 200_000, max_bytes: int = 512 * MB,
                 mode: str = "r|gz", stats: ExtractStats | None = None) -> ExtractStats:
    """Stream-extract a (gzip'd) tar into `dest`, defensively.

    Rejected (skipped and listed in `stats.rejected`): absolute paths, `..` components, NUL bytes,
    device/fifo/other special files, symlinks whose target leaves the root (absolute targets are rewritten
    to relative ones inside the root), hard links to anything but an already extracted regular file,
    and any entry whose path would traverse a symlink. Modes/owners are ignored (files are 0600, dirs 0700,
    no setuid). Raises `HarvestLimitExceeded` when limits are hit (stats.limit is set, partial data stays).
    """
    dest = os.path.realpath(dest)
    stats = stats if stats is not None else ExtractStats()
    with tarfile.open(fileobj=fileobj, mode=mode) as tf:   # type: ignore[call-overload]
        for m in tf:
            stats.entries += 1
            if stats.entries > max_files:
                stats.limit = f"more than {max_files} archive entries"
                raise HarvestLimitExceeded(stats.limit)
            rel = _clean_member_path(m.name)
            if rel is None:
                stats.reject(m.name, "absolute path, '..' or NUL in name")
                continue
            if rel == "":
                continue                         # "./" itself
            if m.isdir():
                full = _ensure_parents(dest, rel)
                if full is None:
                    stats.reject(m.name, "path traverses a symlink")
                    continue
                if not os.path.lexists(full):
                    os.mkdir(full, 0o700)
                continue
            if m.isreg():
                full = _ensure_parents(dest, rel)
                if full is None or not _clear_final(full):
                    stats.reject(m.name, "path traverses a symlink or collides with a directory")
                    continue
                if stats.bytes + m.size > max_bytes:
                    stats.limit = f"more than {max_bytes // MB} MB of file content"
                    raise HarvestLimitExceeded(stats.limit)
                src = tf.extractfile(m)
                fd = os.open(full, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "wb") as out:
                    remaining = m.size
                    while remaining > 0 and src is not None:
                        chunk = src.read(min(1 << 20, remaining))
                        if not chunk:
                            break
                        out.write(chunk)
                        remaining -= len(chunk)
                stats.files += 1
                stats.bytes += m.size
                continue
            if m.issym():
                full = _ensure_parents(dest, rel)
                if full is None or not _clear_final(full):
                    stats.reject(m.name, "path traverses a symlink or collides with a directory")
                    continue
                target = m.linkname
                if not target or "\x00" in target:
                    stats.reject(m.name, "empty or invalid symlink target")
                    continue
                base = rel.rpartition("/")[0]
                if target.startswith("/"):       # re-root absolute targets at the harvest root
                    resolved = _lexical_join("", target)
                    resolved = resolved if resolved is not None else ""
                else:
                    resolved = _lexical_join(base, target)
                    if resolved is None:
                        stats.reject(m.name, f"symlink target {target!r} escapes the root")
                        continue
                new_target = os.path.relpath(os.path.join(dest, resolved), os.path.join(dest, base))
                os.symlink(new_target, full)
                stats.files += 1
                continue
            if m.islnk():
                src_rel = _clean_member_path(m.linkname)
                full = _ensure_parents(dest, rel)
                src_full = os.path.join(dest, src_rel) if src_rel else None
                if (full is None or src_full is None or not _clear_final(full)
                        or _ensure_parents(dest, src_rel) is None):
                    stats.reject(m.name, "unsafe hard link")
                    continue
                try:
                    st = os.lstat(src_full)
                except OSError:
                    stats.reject(m.name, "hard link to a file that was not extracted")
                    continue
                if not stat.S_ISREG(st.st_mode):
                    stats.reject(m.name, "hard link to a non-regular file")
                    continue
                if stats.bytes + st.st_size > max_bytes:
                    stats.limit = f"more than {max_bytes // MB} MB of file content"
                    raise HarvestLimitExceeded(stats.limit)
                with open(src_full, "rb") as a, open(full, "xb") as b:
                    b.write(a.read())
                os.chmod(full, 0o600)
                stats.files += 1
                stats.bytes += st.st_size
                continue
            stats.reject(m.name, f"special file type {m.type!r} (device/fifo)")
    return stats


def opts_int(opts: dict[str, Any], key: str, default: int) -> int:
    v = opts.get(key)
    if v is None or v == "":
        return default
    try:
        return int(v)
    except (TypeError, ValueError) as e:
        raise ValueError(f"option {key}={v!r} must be an integer") from e
