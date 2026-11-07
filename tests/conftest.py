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


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path_factory, monkeypatch):
    """Never touch the developer's real database or cache."""
    root = tmp_path_factory.mktemp("home")
    monkeypatch.delenv("SECMONK_DB", raising=False)
    monkeypatch.setenv("SECMONK_HOME", str(root / "data"))
    monkeypatch.setenv("SECMONK_CACHE", str(root / "cache"))
