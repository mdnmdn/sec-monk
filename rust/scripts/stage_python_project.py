#!/usr/bin/env python3
"""Stage the Python side of a sec-monk release: the root `secmonk` project and the modules project.

`rust/python/pyproject.toml` depends on the repository root through a uv path source (`../..`), so a release must
keep that layout. This script copies, into OUT (created empty):

    OUT/pyproject.toml, OUT/README.md, OUT/uv.lock      the root project (hatchling needs the README)
    OUT/src/secmonk/                                    the secmonk package
    OUT/rust/python/                                    the modules project (no tests, venv or caches)

Used by the release workflow for the server archive and the desktop bundle (Tauri resource `python-project/`), and
runnable locally before `cargo tauri build --config tauri.bundle.conf.json`. Standard library only; works on
Windows, macOS and Linux.

usage: python3 rust/scripts/stage_python_project.py OUT
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {"__pycache__", ".venv", ".pytest_cache", ".ruff_cache", ".mypy_cache", "tests", "build", "dist"}
SKIP_SUFFIXES = {".pyc", ".pyo"}


def _ignore(_dir: str, names: list[str]) -> set[str]:
    return {n for n in names if n in SKIP_DIRS or Path(n).suffix in SKIP_SUFFIXES or n.endswith(".egg-info")}


def stage(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name in ("pyproject.toml", "README.md", "uv.lock"):
        src = ROOT / name
        if src.is_file():
            shutil.copy2(src, out / name)
    shutil.copytree(ROOT / "src" / "secmonk", out / "src" / "secmonk", ignore=_ignore)
    shutil.copytree(ROOT / "rust" / "python", out / "rust" / "python", ignore=_ignore)
    for required in ("pyproject.toml", "README.md", "src/secmonk/__init__.py", "rust/python/pyproject.toml",
                     "rust/python/uv.lock", "rust/python/modules"):
        if not (out / required).exists():
            raise SystemExit(f"stage_python_project: missing {required} in {out}")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    out = Path(argv[1]).resolve()
    protected = [ROOT / "src", ROOT / "rust" / "python"]
    if out == ROOT or any(out == p or p in out.parents for p in protected):
        print(f"stage_python_project: refusing to stage into the source tree: {out}", file=sys.stderr)
        return 2
    stage(out)
    files = sum(1 for p in out.rglob("*") if p.is_file())
    print(f"staged {files} files into {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
