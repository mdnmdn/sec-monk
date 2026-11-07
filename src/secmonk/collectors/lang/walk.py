"""Walk a directory tree (project folder, repo, extracted rootfs) and run language parsers.

Used by:
  * collectors/fs.py      — `secmonk scan fs <dir>` (projects / repositories)
  * collectors/rootfs.py  — DirView (mounted / extracted Linux filesystems, SSH harvests)
Image layers use `LangAccumulator` instead (parse while streaming, no file contents retained).
"""

from __future__ import annotations

import os
import stat
import struct
from dataclasses import dataclass, field
from pathlib import Path

from ...models import Component
from . import base

# directories never worth descending into for dependency evidence
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".tox", ".nox", ".idea", ".vscode", ".gradle", ".terraform", ".angular",
})
# `.tox` / `.nox` are test environments (pruned on purpose). `.next` / `.nuxt` hold the build output of
# a deployed Next/Nuxt app (server bundles, standalone node_modules) so only their caches are pruned.
SKIP_REL_SUFFIXES = (".next/cache", ".nuxt/cache")
BINARY_SKIP_NAMES = (".so", ".node", ".dylib", ".a", ".o")
SKIP_ROOT_DIRS = frozenset({"proc", "sys", "dev", "run"})   # when walking a full rootfs

HEAD = 512

_ELF_ET_EXEC, _ELF_ET_DYN = 2, 3


def _has_pt_interp(head: bytes) -> bool:
    """PT_INTERP among the program headers that fit in the first bytes (ELF64 / ELF32)."""
    try:
        e = "<" if head[5] == 1 else ">"
        if head[4] == 2:
            phoff, = struct.unpack_from(e + "Q", head, 0x20)
            phentsize, phnum = struct.unpack_from(e + "HH", head, 0x36)
        else:
            phoff, = struct.unpack_from(e + "I", head, 0x1C)
            phentsize, phnum = struct.unpack_from(e + "HH", head, 0x2A)
        for i in range(min(phnum, 32)):
            pos = phoff + i * phentsize
            if pos + 4 > len(head):
                break
            if struct.unpack_from(e + "I", head, pos)[0] == 3:       # PT_INTERP
                return True
    except (struct.error, IndexError):
        pass
    return False


def binary_candidate(rel: str, head: bytes, mode: int | None = None) -> bool:
    """Is this file an executable (not a shared object / object file / module) worth reading in full?
    Libraries (`*.so`, `*.so.1`, `*.node`, `*.dylib`) never embed a *program's* dependency list, and
    reading them (hundreds of MB in a typical image) dominated scan time. `mode` is the st_mode when
    known: an ET_DYN ELF without exec bit and without PT_INTERP is a library."""
    low = rel.lower().rsplit("/", 1)[-1]
    if low.endswith(BINARY_SKIP_NAMES) or ".so." in low:
        return False
    if head[:4] == b"\x7fELF" and len(head) >= 20:
        etype = struct.unpack_from("<H" if head[5] == 1 else ">H", head, 16)[0]
        if etype == _ELF_ET_EXEC:
            return True
        if etype != _ELF_ET_DYN:
            return False
        if mode is not None and not mode & 0o111 and not _has_pt_interp(head):
            return False
    return True


def read_capped(path: str, cap: int) -> tuple[bytes | None, int, bytes]:
    """Race-safe read: open without following symlinks / blocking on FIFOs, check the *opened* file
    (fstat) and read at most cap+1 bytes. Returns (data or None when over the cap, size, head).
    Raises OSError for unreadable / special files."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) \
        | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb", buffering=0) as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise OSError("not a regular file")
        if st.st_size > cap:
            return None, st.st_size, b""
        chunks, left = [], cap + 1
        while left > 0:
            b = f.read(min(left, 16 * 1024 * 1024))
            if not b:
                break
            chunks.append(b)
            left -= len(b)
        data = b"".join(chunks)
        if len(data) > cap:
            return None, len(data), b""
        return data, len(data), data[:HEAD]


@dataclass
class WalkLimits:
    max_files: int = 200_000          # parsed files cap
    binaries: bool = True             # run binary parsers (Go/Rust executables, jars)
    max_binary_bytes: int = 256 * 1024 * 1024
    skip_dirs: frozenset[str] = SKIP_DIRS


@dataclass
class LangResult:
    components: list[Component] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files_parsed: int = 0
    truncated: bool = False


def _skip_rel(rel_dir: str) -> bool:
    return rel_dir.endswith(SKIP_REL_SUFFIXES)


def _peek(path: str) -> bytes:
    """First HEAD bytes, opened race-safely (see read_capped)."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb", buffering=0) as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise OSError("not a regular file")
        return f.read(HEAD)


def _applicable(rel: str, head: bytes, binaries: bool) -> list[base.LangParser]:
    ps = base.parsers_for(rel, head)
    return [p for p in ps if binaries or not p.binary]


def walk_dir(root: str | Path, *, limits: WalkLimits | None = None, rootfs: bool = False,
             path_prefix: str = "", match_prefix: str = "") -> LangResult:
    """Parse every dependency file under `root`. Paths in results are relative to root,
    prefixed by `path_prefix` (e.g. '/' for rootfs-style absolute display).
    `match_prefix` is prepended to the relative path for parser selection only, when `root` is
    itself a directory the parsers key on (e.g. 'node_modules/' when root is a node_modules dir)."""
    from . import _ensure_loaded

    _ensure_loaded()
    limits = limits or WalkLimits()
    res = LangResult()
    root = Path(root)
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        dirs[:] = sorted(d for d in dirs if d not in limits.skip_dirs
                         and not (rootfs and rel_dir == "" and d in SKIP_ROOT_DIRS)
                         and not _skip_rel(f"{rel_dir}/{d}" if rel_dir else d))
        for fn in sorted(files):
            rel = match_prefix + (f"{rel_dir}/{fn}" if rel_dir else fn)
            if not base.wants(rel):
                continue
            full = os.path.join(dirpath, fn)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
                continue
            try:
                head = _peek(full)
                parsers = _applicable(rel, head, limits.binaries)
                if any(p.binary for p in parsers) and not binary_candidate(rel, head, st.st_mode):
                    parsers = [p for p in parsers if not p.binary]
                if not parsers:
                    continue
                cap = max(p.max_bytes for p in parsers)
                if any(p.binary for p in parsers):
                    cap = min(cap, limits.max_binary_bytes)
                data, size, _ = read_capped(full, cap)
                if data is None:
                    res.warnings.append(f"{rel}: skipped ({size} bytes > {cap})")
                    continue
            except OSError as e:
                res.warnings.append(f"{rel}: {e}")
                continue
            comps, warns = base.parse_file(rel, data)
            display = path_prefix + rel[len(match_prefix):]
            for c in comps:
                if c.source_path == rel or not c.source_path:
                    c.source_path = display
                elif not c.source_path.startswith(path_prefix):
                    c.source_path = path_prefix + c.source_path
            res.components.extend(comps)
            res.warnings.extend(warns)
            res.files_parsed += 1
            if res.files_parsed >= limits.max_files:
                res.truncated = True
                res.warnings.append(f"stopped after {limits.max_files} dependency files")
                res.components = base.dedupe(res.components)
                return res
    res.components = base.dedupe(res.components)
    return res


class LangAccumulator:
    """Parse dependency files while streaming tar layers (bottom layer first).

    Results are keyed by path so that later layers can overwrite or whiteout them; only parsed
    components are retained, never file contents.
    """

    def __init__(self, limits: WalkLimits | None = None):
        from . import _ensure_loaded

        _ensure_loaded()
        self.limits = limits or WalkLimits()
        self.by_path: dict[str, list[Component]] = {}
        self._gen: dict[str, int] = {}        # path -> layer generation that produced the entry
        self.warnings: list[str] = []
        self.truncated = False

    @staticmethod
    def wants(path: str) -> bool:
        return base.wants(path)

    def feed(self, path: str, size: int, read, *, layer: int | None = None, mode: int | None = None) -> None:
        """`read(n=-1) -> bytes` reads the member; called only if wants(path). `layer` is the current
        layer generation (lets `remove_under(only_older=True)` spare entries of the same layer);
        `mode` is the tar member's st_mode, if known (executables vs shared objects)."""
        if len(self.by_path) >= self.limits.max_files:
            self.truncated = True
            return
        head = read(HEAD)
        parsers = _applicable(path, head, self.limits.binaries)
        if any(p.binary for p in parsers) and not binary_candidate(path, head, mode):
            parsers = [p for p in parsers if not p.binary]
        if not parsers:
            self.by_path.pop(path, None)   # file replaced by something we don't parse
            self._gen.pop(path, None)
            return
        cap = max(p.max_bytes for p in parsers)
        if any(p.binary for p in parsers):
            cap = min(cap, self.limits.max_binary_bytes)
        if size > cap:
            self.warnings.append(f"{path}: skipped ({size} bytes > {cap})")
            return
        data = head + read()
        comps, warns = base.parse_file(path, data)
        self.warnings.extend(warns)
        for c in comps:
            if not c.source_path or c.source_path == path:
                c.source_path = "/" + path
            elif not c.source_path.startswith("/"):
                c.source_path = "/" + c.source_path
        self.by_path[path] = comps
        if layer is not None:
            self._gen[path] = layer

    def remove_under(self, prefix: str, *, only_older: bool = False, layer: int | None = None) -> None:
        """Drop entries at/under `prefix` (whiteouts, replaced directories). With `only_older` and the
        current `layer`, entries added by the *same* layer survive (a layer may add files and a
        whiteout for the same directory; tar order must not matter). Entries with unknown generation
        count as older."""
        pre = prefix + "/"
        for p in [p for p in self.by_path if p == prefix or p.startswith(pre)]:
            if only_older and layer is not None and self._gen.get(p, -1) >= layer:
                continue
            del self.by_path[p]
            self._gen.pop(p, None)

    def alias(self, path: str, src: str, *, layer: int | None = None) -> None:
        """Hard link: `path` shares the parsed components of `src`."""
        if src in self.by_path:
            self.by_path[path] = self.by_path[src]
            if layer is not None:
                self._gen[path] = layer

    def clear(self, *, only_older: bool = False, layer: int | None = None) -> None:
        """Forget results; with `only_older`, keep those produced by `layer` itself (an opaque
        root marker hides lower layers only)."""
        if only_older and layer is not None:
            for p in [p for p in self.by_path if self._gen.get(p, -1) < layer]:
                del self.by_path[p]
                self._gen.pop(p, None)
            return
        self.by_path.clear()
        self._gen.clear()

    def components(self) -> list[Component]:
        return base.dedupe([c for comps in self.by_path.values() for c in comps])
