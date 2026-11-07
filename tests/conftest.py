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
