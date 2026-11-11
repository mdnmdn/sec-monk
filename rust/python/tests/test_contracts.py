"""The contract check of rust/contracts (its README "Check"), run on every test run, plus catalog coverage."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from secmonk_modules.registry import MODULE_NAMES, load_module

from . import contracts

C = contracts.CONTRACTS
MODULES_DIR = Path(__file__).resolve().parents[1] / "modules"


def test_every_schema_is_valid_and_its_id_matches_its_path():
    files = sorted(contracts.SCHEMAS.rglob("*.schema.json"))
    assert len(files) >= 50
    for f in files:
        doc = json.loads(f.read_text())
        Draft202012Validator.check_schema(doc)
        assert doc["$id"] == contracts.BASE + f.relative_to(contracts.SCHEMAS).as_posix(), f


def test_every_example_validates_and_none_is_left_out():
    index = json.loads((C / "examples" / "index.json").read_text())["index"]
    listed = set()
    for e in index:
        path = (C / "examples" / e["example"]).resolve()
        listed.add(path)
        value = json.loads(path.read_text())
        for part in [p for p in e.get("pointer", "").split("/") if p]:
            value = value[int(part)] if isinstance(value, list) else value[part]
        contracts.check(e["schema"], value)
    on_disk = {p.resolve() for p in (C / "examples").rglob("*.json") if p.name != "index.json"}
    assert on_disk <= listed, sorted(on_disk - listed)


def test_catalog_references_resolve():
    for m in contracts.catalog().values():
        for key in ("params", "result", "end"):
            if key in m:
                contracts.validator(m[key])                    # building the validator resolves the $ref lazily ...
                schema_path = m[key].split("#")[0]
                assert (contracts.SCHEMAS / schema_path).is_file(), (m["name"], key)
                if "#/" in m[key]:
                    doc = json.loads((contracts.SCHEMAS / schema_path).read_text())
                    node = doc
                    for part in m[key].split("#/")[1].split("/"):
                        node = node[part]


def test_the_four_modules_provide_exactly_the_catalog():
    provided: dict[str, str] = {}
    for name in MODULE_NAMES:
        for m in load_module(name).provides()["methods"]:
            assert m not in provided, f"{m} provided by {provided[m]} and {name}"
            provided[m] = name
    assert set(provided) == set(contracts.catalog()), set(provided) ^ set(contracts.catalog())
    assert len(provided) == 30
    for m, name in provided.items():
        kind = contracts.catalog()[m]["module_kind"]
        assert {"py-probe": "probe", "py-sources": "source", "py-engine": "engine", "py-procmon": "engine"}[name] == kind


@pytest.mark.parametrize("name", MODULE_NAMES)
def test_manifest_is_valid_and_matches_the_module(name):
    manifest = tomllib.loads((MODULES_DIR / f"{name}.toml").read_text())
    contracts.check("module/manifest.schema.json", manifest)
    mod = load_module(name)
    assert manifest["name"] == name and manifest["kind"] == mod.kind
    assert sorted(manifest["provides"]["methods"]) == mod.provides()["methods"]
    assert sorted(manifest["capabilities"]) == sorted(mod.capabilities)
    assert manifest["limits"]["max_inflight"] == mod.max_inflight
    assert manifest["python"]["entry"] == ["-I", "-m", "secmonk_modules", "serve", "--stdio", "--module", name]
    for key in ("collectors", "sources"):
        if key in mod.provides():
            assert manifest["provides"][key] == mod.provides()[key]
    if "sync_all_order" in mod.provides():
        assert manifest["provides"]["sync_all_order"] == mod.provides()["sync_all_order"]
    # every platform the host targets runs these; only the process monitor has no Windows backend
    assert set(manifest["platforms"]) == ({"macos", "linux"} if name == "py-procmon" else {"macos", "linux", "windows"})


@pytest.mark.parametrize("name", MODULE_NAMES)
def test_hello_of_every_module_is_contract_valid(name, env, grant):
    from secmonk_modules.client import ModuleClient

    grants = {"db_read": grant} if name in ("py-engine", "py-procmon") else {}
    with ModuleClient(name, env=env, grants=grants) as c:
        contracts.check("wire/envelope.schema.json", c.hello)
        manifest = tomllib.loads((MODULES_DIR / f"{name}.toml").read_text())
        # a module may not claim more than its manifest
        assert set(c.hello["capabilities"]) <= set(manifest["capabilities"])
        assert set(c.hello["provides"]["methods"]) <= set(manifest["provides"]["methods"])
        assert c.hello["limits"]["max_inflight"] == manifest["limits"]["max_inflight"]
        assert c.hello["limits"]["max_frame"] == manifest["limits"]["max_frame"]
        for key in ("collectors", "sources"):
            if key in c.hello["provides"]:
                assert c.hello["provides"][key] == manifest["provides"][key]


def test_serve_accepts_both_invocation_forms(env):
    import sys

    from secmonk_modules.client import ModuleClient

    for cmd in ([sys.executable, "-I", "-m", "secmonk_modules", "serve", "--stdio", "--module", "py-sources"],
                [sys.executable, "-I", "-m", "secmonk_modules", "serve", "py-sources", "--stdio"]):
        with ModuleClient("py-sources", env=env, cmd=cmd) as c:
            assert c.hello["name"] == "py-sources"
