"""`fs` collector: dependency inventory of a project folder / repository / any directory.

    secmonk scan fs ./my-service
    secmonk scan fs ~/code -o binaries=false

Finds lockfiles, manifests, installed packages (node_modules, venvs, vendor/), jars and Go/Rust
binaries for npm, PyPI, Go, crates.io, Maven, NuGet and Packagist. See
_docs/features/inventory-dependencies.md.
"""

from __future__ import annotations

import configparser
import os
import re
import stat
from pathlib import Path
from typing import Any

from ..models import Asset, Inventory
from .base import Collector, register, resolve_within, strip_url_secrets
from .lang.walk import WalkLimits, walk_dir

_REF_RE = re.compile(r"^refs/[A-Za-z0-9._/-]+$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
MAX_REF_BYTES = 128           # HEAD and loose ref files hold a ref name or a hex object id
MAX_GITCONFIG_BYTES = 1024 * 1024
MAX_PACKED_REFS_BYTES = 4 * 1024 * 1024


def _read_small(path: Path, limit: int, boundary: Path | None = None) -> str | None:
    """Read up to `limit` bytes of a regular file without following a symlink at the last component
    (and, with `boundary`, none that leave it). None when missing/unreadable/special."""
    try:
        if boundary is not None:
            resolve_within(path.parent, boundary)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_CLOEXEC", 0))
    except (OSError, ValueError):
        return None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        return f.read(limit).decode("utf-8", "replace")


def _valid_ref(ref: str) -> bool:
    return bool(_REF_RE.fullmatch(ref)) and ".." not in ref and "//" not in ref and not ref.endswith("/") \
        and "/." not in ref and not ref.endswith(".lock")


def _find_gitdirs(root: Path) -> tuple[Path, Path] | None:
    """(gitdir, commondir) of a checkout. `.git` may be a directory, or a file `gitdir: <path>`
    (worktrees, submodules). A pointer is followed only when it names a real directory holding a
    regular `HEAD`: a hostile checkout cannot make us read arbitrary files this way."""
    git = root / ".git"
    try:
        st = os.lstat(git)
    except OSError:
        return None
    gitdir: Path | None = None
    if stat.S_ISDIR(st.st_mode):
        gitdir = git
    elif stat.S_ISREG(st.st_mode):
        text = _read_small(git, 1024)
        m = re.match(r"^gitdir:\s*(.+?)\s*$", (text or "").splitlines()[0] if text else "")
        if m and "\x00" not in m.group(1):
            cand = Path(m.group(1))
            gitdir = cand if cand.is_absolute() else root / cand
    if gitdir is None:
        return None
    try:
        gitdir = gitdir.resolve()
    except (OSError, RuntimeError):
        return None
    if not gitdir.is_dir() or _read_small(gitdir / "HEAD", MAX_REF_BYTES) is None:
        return None
    common = gitdir
    cd = _read_small(gitdir / "commondir", 512)
    if cd and cd.strip():
        cand = (gitdir / cd.strip()).resolve()
        if cand.is_dir() and ((cand / "config").is_file() or (cand / "HEAD").is_file()):
            common = cand
    return gitdir, common


def _packed_ref(common: Path, ref: str) -> str | None:
    text = _read_small(common / "packed-refs", MAX_PACKED_REFS_BYTES)
    for line in (text or "").splitlines():
        sha, _, name = line.partition(" ")
        if name.strip() == ref and _COMMIT_RE.fullmatch(sha):
            return sha
    return None


def _git_info(root: Path) -> dict:
    """Branch, commit and (credential-free) origin URL of a checkout. Only fixed paths below the
    git dir are read; nothing a repository can name is followed."""
    found = _find_gitdirs(root)
    if found is None:
        return {}
    gitdir, common = found
    info: dict[str, Any] = {}
    head = (_read_small(gitdir / "HEAD", MAX_REF_BYTES) or "").strip()
    if head.startswith("ref:"):
        ref = head[4:].strip()
        if _valid_ref(ref):
            info["branch"] = ref.removeprefix("refs/heads/")
            commit = (_read_small(gitdir / ref, MAX_REF_BYTES, boundary=common) or "").strip()
            if not _COMMIT_RE.fullmatch(commit):
                commit = (_read_small(common / ref, MAX_REF_BYTES, boundary=common) or "").strip()
            if not _COMMIT_RE.fullmatch(commit):
                commit = _packed_ref(common, ref) or ""
            if commit:
                info["commit"] = commit
    elif _COMMIT_RE.fullmatch(head):
        info["commit"] = head
    text = _read_small(common / "config", MAX_GITCONFIG_BYTES)
    if text:
        cfg = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
        try:
            cfg.read_string(text)
            url = cfg.get('remote "origin"', "url", fallback=None) if cfg.has_section('remote "origin"') else None
        except configparser.Error:
            url = None
        if url:
            info["remote"] = strip_url_secrets(url.strip())
    return info


def _bool(v: Any, default: bool) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).lower() in ("1", "true", "yes")


@register
class FsCollector(Collector):
    name = "fs"
    description = "Language dependencies in a folder/repo: lockfiles, manifests, installed packages, binaries"

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        root = Path(target or ".").expanduser().resolve()
        if not root.is_dir():
            raise NotADirectoryError(str(root))
        limits = WalkLimits(
            binaries=_bool(opts.get("binaries"), True),
            max_files=int(opts.get("max_files", WalkLimits.max_files)),
        )
        res = walk_dir(root, limits=limits)
        git = _git_info(root)
        asset = Asset(
            id=opts.get("asset_id") or f"{'repo' if git else 'dir'}:{root}",
            type="repo" if git else "directory",
            name=root.name,
            meta={"path": str(root), "files_parsed": res.files_parsed, **({"git": git} if git else {})},
        )
        return Inventory(asset=asset, collector=self.name, components=res.components,
                         warnings=res.warnings)
