"""Print the integrity pins of a module project for `trust = "pinned"` (rust/_docs/tech/configuration.md).

    uv run python scripts/pins.py                 # this project (rust/python)
    uv run python scripts/pins.py <project-dir>

Output: a `[modules.pins]` block for every manifest in `<project>/modules/`. `lock_sha256` is the sha256 of
`uv.lock`; `tree_sha256` is the `secmonk-tree/1` hash, the same algorithm as `secmonk_runtime::tree`:
`pyproject.toml` plus every regular file below `src/` (skipping `__pycache__`, `.venv`, `.git`, tool caches,
`*.pyc` / `*.pyo`, `.DS_Store`), one `sha256sum` line `<sha256>  <relative/path>\\n` per file in byte order of the
path, hashed together. A symlink in the tree is an error.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

EXCLUDED_DIRS = {"__pycache__", ".venv", ".git", ".pytest_cache", ".ruff_cache", ".mypy_cache", ".tox", "node_modules"}
EXCLUDED_FILES = {".DS_Store", "Thumbs.db"}
MAX_FILES = 50_000
MAX_FILE_BYTES = 64 * 1024 * 1024


def file_sha256(p: Path) -> str:
    if p.is_symlink() or not p.is_file():
        raise ValueError(f"{p} is not a regular file")
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{p} is larger than {MAX_FILE_BYTES} bytes")
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk(dir_: Path, rel: str, out: dict[str, str]) -> None:
    for e in dir_.iterdir():
        r = f"{rel}/{e.name}"
        if e.is_symlink():
            raise ValueError(f"symlink in the module tree: {r}")
        if e.is_dir():
            if e.name not in EXCLUDED_DIRS:
                _walk(e, r, out)
        elif e.is_file():
            if e.name in EXCLUDED_FILES or e.name.endswith((".pyc", ".pyo")):
                continue
            if len(out) >= MAX_FILES:
                raise ValueError(f"more than {MAX_FILES} files")
            out[r] = file_sha256(e)
        else:
            raise ValueError(f"not a regular file in the module tree: {r}")


def tree_sha256(project: Path) -> tuple[str, int]:
    files = {"pyproject.toml": file_sha256(project / "pyproject.toml")}
    src = project / "src"
    if src.is_symlink() or (src.exists() and not src.is_dir()):
        raise ValueError(f"{src} is not a directory")
    if src.is_dir():
        _walk(src, "src", files)
    lines = "".join(f"{files[p]}  {p}\n" for p in sorted(files, key=lambda s: s.encode()))
    return hashlib.sha256(lines.encode()).hexdigest(), len(files)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    project = Path(args[0] if args else Path(__file__).resolve().parents[1]).resolve()
    lock = file_sha256(project / "uv.lock")
    tree, n = tree_sha256(project)
    names = sorted(p.stem for p in (project / "modules").glob("*.toml"))
    print(f"# {project.name}: {n} files in the tree")
    print("[modules.pins]")
    for name in names:
        print(f'{name} = {{ lock_sha256 = "{lock}", tree_sha256 = "{tree}" }}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
