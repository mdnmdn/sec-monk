"""Walk a directory tree (project folder, repo, extracted rootfs) and run language parsers.

Used by:
  * collectors/fs.py      — `secmonk scan fs <dir>` (projects / repositories)
  * collectors/rootfs.py  — DirView (mounted / extracted Linux filesystems, SSH harvests)
Image layers use `LangAccumulator` instead (parse while streaming, no file contents retained).
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from ...models import Component
from . import base

# directories never worth descending into for dependency evidence
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".tox", ".nox", ".idea", ".vscode", ".gradle", ".terraform", ".next", ".nuxt", ".angular",
})
SKIP_ROOT_DIRS = frozenset({"proc", "sys", "dev", "run"})   # when walking a full rootfs

HEAD = 512


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


def _applicable(rel: str, head: bytes, binaries: bool) -> list[base.LangParser]:
    ps = base.parsers_for(rel, head)
    return [p for p in ps if binaries or not p.binary]


def walk_dir(root: str | Path, *, limits: WalkLimits | None = None, rootfs: bool = False,
             path_prefix: str = "") -> LangResult:
    """Parse every dependency file under `root`. Paths in results are relative to root,
    prefixed by `path_prefix` (e.g. '/' for rootfs-style absolute display)."""
    from . import _ensure_loaded

    _ensure_loaded()
    limits = limits or WalkLimits()
    res = LangResult()
    root = Path(root)
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        dirs[:] = sorted(d for d in dirs if d not in limits.skip_dirs
                         and not (rootfs and rel_dir == "" and d in SKIP_ROOT_DIRS))
        for fn in sorted(files):
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
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
                with open(full, "rb") as f:
                    head = f.read(HEAD)
                    parsers = _applicable(rel, head, limits.binaries)
                    if not parsers:
                        continue
                    cap = max(p.max_bytes for p in parsers)
                    if any(p.binary for p in parsers):
                        cap = min(cap, limits.max_binary_bytes)
                    if st.st_size > cap:
                        res.warnings.append(f"{rel}: skipped ({st.st_size} bytes > {cap})")
                        continue
                    data = head + f.read()
            except OSError as e:
                res.warnings.append(f"{rel}: {e}")
                continue
            comps, warns = base.parse_file(rel, data)
            display = path_prefix + rel
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
        self.warnings: list[str] = []
        self.truncated = False

    @staticmethod
    def wants(path: str) -> bool:
        return base.wants(path)

    def feed(self, path: str, size: int, read) -> None:
        """`read(n=-1) -> bytes` reads the member; called only if wants(path)."""
        if len(self.by_path) >= self.limits.max_files:
            self.truncated = True
            return
        head = read(HEAD)
        parsers = _applicable(path, head, self.limits.binaries)
        if not parsers:
            self.by_path.pop(path, None)   # file replaced by something we don't parse
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

    def remove_under(self, prefix: str) -> None:
        pre = prefix + "/"
        for p in [p for p in self.by_path if p == prefix or p.startswith(pre)]:
            del self.by_path[p]

    def clear(self) -> None:
        self.by_path.clear()

    def components(self) -> list[Component]:
        return base.dedupe([c for comps in self.by_path.values() for c in comps])
