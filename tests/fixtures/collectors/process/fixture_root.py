"""Build the process-collector fixture tree (shared by tests/conftest.py and scripts/design_mock.py).

The tree = ../macos/root (apps, Homebrew, SystemVersion.plist) + ./root (launchd plists, placeholder executables,
privileged helper) + the Go fixture binary at /usr/local/bin/hello. Built at run time so no binary is duplicated.
"""

from __future__ import annotations

import shutil
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[2]          # tests/fixtures


def build_root(dest: Path) -> Path:
    root = Path(dest)
    shutil.copytree(FIXTURES / "collectors/macos/root", root, symlinks=True)
    shutil.copytree(FIXTURES / "collectors/process/root", root, symlinks=True, dirs_exist_ok=True)
    (root / "usr/local/bin").mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "lang/go/hello-darwin-arm64", root / "usr/local/bin/hello")
    return root
