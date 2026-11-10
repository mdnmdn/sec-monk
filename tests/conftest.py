"""Shared pytest fixtures."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from secmonk.db import connect

FIXTURES = Path(__file__).parent / "fixtures" / "sources"


@pytest.fixture
def conn() -> sqlite3.Connection:
    c = connect(":memory:")
    yield c
    c.close()


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def process_root(tmp_path) -> Path:
    """The process-collector fixture tree (tests/fixtures/collectors/process/fixture_root.py)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "process_fixture_root", Path(__file__).parent / "fixtures/collectors/process/fixture_root.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_root(tmp_path / "root")


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path_factory, monkeypatch):
    """Never touch the developer's real database or cache."""
    root = tmp_path_factory.mktemp("home")
    monkeypatch.delenv("SECMONK_DB", raising=False)
    monkeypatch.setenv("SECMONK_HOME", str(root / "data"))
    monkeypatch.setenv("SECMONK_CACHE", str(root / "cache"))
    # never the developer's Docker CLI configuration or environment (contexts, DOCKER_HOST, TLS material)
    for var in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        monkeypatch.delenv(var, raising=False)
    (root / "docker-config").mkdir()
    monkeypatch.setenv("DOCKER_CONFIG", str(root / "docker-config"))
