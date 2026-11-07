"""`fs` collector: dependency inventory of a project folder / repository / any directory.

    secmonk scan fs ./my-service
    secmonk scan fs ~/code -o binaries=false

Finds lockfiles, manifests, installed packages (node_modules, venvs, vendor/), jars and Go/Rust
binaries for npm, PyPI, Go, crates.io, Maven, NuGet and Packagist. See
_docs/features/inventory-dependencies.md.
"""

from __future__ import annotations

import configparser
from pathlib import Path
from typing import Any

from ..models import Asset, Inventory
from .base import Collector, register
from .lang.walk import WalkLimits, walk_dir


def _git_info(root: Path) -> dict:
    git = root / ".git"
    if not git.is_dir():
        return {}
    info: dict[str, Any] = {}
    try:
        head = (git / "HEAD").read_text().strip()
        if head.startswith("ref: "):
            ref = head[5:]
            info["branch"] = ref.rsplit("/", 1)[-1]
            ref_file = git / ref
            if ref_file.is_file():
                info["commit"] = ref_file.read_text().strip()
        else:
            info["commit"] = head
        cfg = configparser.ConfigParser(strict=False)
        cfg.read(git / "config")
        if cfg.has_section('remote "origin"'):
            url = cfg.get('remote "origin"', "url", fallback=None)
            if url and "@" in url and "://" in url:      # strip credentials from https URLs
                scheme, rest = url.split("://", 1)
                url = f"{scheme}://{rest.split('@', 1)[-1]}"
            info["remote"] = url
    except OSError:
        pass
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
