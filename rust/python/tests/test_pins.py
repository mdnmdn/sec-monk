"""scripts/pins.py: the secmonk-tree/1 hash, cross-checked with secmonk_runtime::tree on a shared test vector."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import pins

# the same constant as VECTOR_TREE_SHA256 in rust/crates/secmonk-runtime/src/tree.rs
VECTOR_TREE_SHA256 = "8f3e1c253c9ae6335fc57147a349301c3ab39b49b07a109db6dddbb470fbd7bc"


def vector_tree(root: Path) -> None:
    files = {
        "pyproject.toml": b'[project]\nname = "x"\n',
        "uv.lock": b"version = 1\n",
        "src/pkg/__init__.py": b"",
        "src/pkg/mod.py": b"print('hi')\n",
        "src/pkg/B.txt": b"upper sorts first\n",
        "src/pkg/__pycache__/mod.cpython-313.pyc": b"junk",
        "src/pkg/old.pyc": b"junk",
        "src/.DS_Store": b"junk",
        "modules/py-x.toml": b"not in the tree\n",
        "tests/test_x.py": b"not in the tree\n",
    }
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def test_tree_hash_matches_the_rust_vector(tmp_path):
    vector_tree(tmp_path)
    assert pins.tree_sha256(tmp_path) == (VECTOR_TREE_SHA256, 4)


def test_symlink_in_tree_is_refused(tmp_path):
    vector_tree(tmp_path)
    (tmp_path / "src/pkg/link.py").symlink_to("/etc/hosts")
    with pytest.raises(ValueError, match="symlink"):
        pins.tree_sha256(tmp_path)


def test_this_project_hashes(capsys):
    assert pins.main([]) == 0
    out = capsys.readouterr().out
    assert "[modules.pins]" in out and "py-probe = { lock_sha256 = " in out
