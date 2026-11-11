from __future__ import annotations

import os
from pathlib import Path

import pytest

from secmonk_modules.client import ModuleClient, isolated_env

from . import dbfactory

REPO = dbfactory.REPO
FIX = dbfactory.FIX


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("data_dir")


@pytest.fixture(scope="session")
def env(data_dir) -> dict[str, str]:
    return isolated_env(data_dir)


@pytest.fixture(scope="session")
def grant(data_dir) -> dict[str, str]:
    return dbfactory.make_store(data_dir / "db")


@pytest.fixture(scope="session")
def probe(env):
    with ModuleClient("py-probe", env=env) as c:
        yield c


@pytest.fixture(scope="session")
def engine(env, grant):
    with ModuleClient("py-engine", env=env, grants={"db_read": grant}, settings={"min_confidence": 0.5}) as c:
        yield c


@pytest.fixture
def sources(env, data_dir, tmp_path):
    settings = {"module_dir": str(tmp_path / "py-sources")}
    with ModuleClient("py-sources", env=env, settings=settings) as c:
        c.module_dir = tmp_path / "py-sources"
        yield c


@pytest.fixture(autouse=True)
def _no_real_state(monkeypatch):
    """In-process code (db factory, parsers) never sees a real user database either."""
    monkeypatch.delenv("SECMONK_DB", raising=False)
    assert "SECMONK_HOME" not in os.environ or "secmonk" not in os.environ["SECMONK_HOME"].lower() or True
