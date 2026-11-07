from __future__ import annotations

import json
from pathlib import Path

from secmonk.collectors import lang
from secmonk.collectors.lang.base import EV_INSTALLED, EV_LOCKFILE, EV_MANIFEST, dedupe, parse_file
from secmonk.collectors.lang.python import pep503

FX = Path(__file__).parents[2] / "fixtures" / "lang" / "python"


def run(rel: str):
    comps, warns = parse_file(rel, (FX / rel).read_bytes())
    assert warns == []
    return {c.purl: c for c in comps}


def test_pep503():
    assert pep503("Flask_Login") == "flask-login"
    assert pep503("zope.interface") == "zope-interface"
    assert pep503("A--b__c..d") == "a-b-c-d"


def test_installed_dist_info_in_venv():
    sp = "venv/lib/python3.13/site-packages"
    c = run(f"{sp}/requests-2.25.0.dist-info/METADATA")["pkg:pypi/requests@2.25.0"]
    assert (c.name, c.version, c.ecosystem) == ("requests", "2.25.0", "PyPI")
    assert c.meta["evidence"] == EV_INSTALLED and c.meta["venv_root"] == "venv"
    assert c.meta["license"] == "Apache 2.0"
    u = run(f"{sp}/urllib3-1.26.4.dist-info/METADATA")
    assert "pkg:pypi/urllib3@1.26.4" in u


def test_dist_info_only_inside_site_packages():
    assert lang.parsers_for("src/foo.dist-info/METADATA") == []
    assert lang.parsers_for("usr/lib/python3/dist-packages/foo-1.dist-info/METADATA")
    assert lang.parsers_for("C:/x/Lib/site-packages/foo-1.dist-info/METADATA")


def test_egg_info_dir_and_single_file_with_normalization():
    got = run("egg/lib/python3/dist-packages/Legacy_Pkg.egg-info/PKG-INFO")
    c = got["pkg:pypi/legacy-pkg@0.9.1"]
    assert c.name == "Legacy_Pkg" and "license" not in c.meta        # UNKNOWN dropped
    got = run("egg/lib/python3/dist-packages/single.file.pkg-2.0.egg-info")
    assert "pkg:pypi/single-file-pkg@2.0" in got


def test_conda_meta_is_not_pypi():
    got = run("conda/opt/conda/conda-meta/numpy-1.26.4-py311h64a7726_0.json")
    c = got["pkg:conda/numpy@1.26.4"]
    assert c.ecosystem is None and c.meta["channel"] == "conda-forge" and c.meta["build"] == "py311h64a7726_0"
    assert lang.parse_file("conda-meta/history.json", b"[]") == ([], [])        # list, not a record
    assert run("conda/opt/conda/conda-meta/python-3.11.9-h955ad1f_0.json")["pkg:conda/python@3.11.9"].meta[
        "channel"] == "main"


def test_poetry_lock_groups():
    got = run("poetry/poetry.lock")
    assert "pkg:pypi/requests@2.25.0" in got
    assert got["pkg:pypi/iniconfig@2.0.0"].meta["dev"] is True
    assert "dev" not in got["pkg:pypi/requests@2.25.0"].meta
    old = b'[[package]]\nname = "pytest"\nversion = "6.0.0"\ncategory = "dev"\n[[package]]\nname = "loc"\nversion = "1"\n[package.source]\ntype = "directory"\nurl = "."\n'
    comps, _ = parse_file("poetry.lock", old)
    assert [(c.purl, c.meta.get("dev")) for c in comps] == [("pkg:pypi/pytest@6.0.0", True)]


def test_pipfile_lock():
    got = run("pipenv/Pipfile.lock")
    assert got["pkg:pypi/requests@2.25.0"].meta["evidence"] == EV_LOCKFILE
    assert got["pkg:pypi/iniconfig@2.0.0"].meta["dev"] is True
    lock = {"default": {"a": {"version": "==1.0"}, "g": {"git": "https://x", "ref": "abc"},
                        "e": {"editable": True, "path": "."}}, "develop": {}}
    assert [c.purl for c in parse_file("Pipfile.lock", json.dumps(lock).encode())[0]] == ["pkg:pypi/a@1.0"]


def test_uv_lock_dev_graph_and_virtual_root_skipped():
    got = run("uv/uv.lock")
    assert not any("/demo@" in p for p in got)
    assert got["pkg:pypi/iniconfig@2.0.0"].meta["dev"] is True
    assert "dev" not in got["pkg:pypi/requests@2.25.0"].meta
    assert "dev" not in got["pkg:pypi/urllib3@1.26.4"].meta
    assert len(got) == 6


def test_pdm_lock():
    got = run("pdm/pdm.lock")
    assert got["pkg:pypi/iniconfig@2.0.0"].meta["dev"] is True
    assert "pkg:pypi/requests@2.25.0" in got and len(got) == 6


def test_requirements_txt_edge_cases():
    got = run("requirements/requirements.txt")
    assert set(got) == {"pkg:pypi/requests@2.25.0", "pkg:pypi/django@3.2.4", "pkg:pypi/pyyaml@5.3",
                        "pkg:pypi/flask-login@0.5.0"}
    d = got["pkg:pypi/django@3.2.4"]
    assert d.name == "Django" and d.meta["extras"] == ["argon2", "bcrypt"]
    assert d.meta["marker"] == 'python_version >= "3.6"' and d.meta["evidence"] == EV_MANIFEST
    assert got["pkg:pypi/requests@2.25.0"].meta.get("marker") is None


def test_requirements_matching_names():
    for p in ("requirements.txt", "a/requirements-dev.txt", "constraints.txt", "req/requirements/prod.txt",
              "x/dev-requirements.txt"):
        assert any(q.name == "requirements-txt" for q in lang.parsers_for(p)), p
    assert not lang.parsers_for("notes.txt")


def test_requirements_unpinned_and_odd_lines_skipped():
    txt = b"a>=1\nb~=2.0\nc==1.0,!=1.0.1\nd==2.*\ne==3.0.0 # ok\n\xef\xbb\xbfignored\n"
    assert [c.purl for c in parse_file("requirements.txt", txt)[0]] == ["pkg:pypi/e@3.0.0"]


def test_malformed():
    comps, warns = parse_file("poetry.lock", b"[[package")
    assert comps == [] and len(warns) == 1


def test_dedupe_installed_beats_lock_and_requirements():
    lock = parse_file("p/poetry.lock", (FX / "poetry/poetry.lock").read_bytes())[0]
    req = parse_file("p/requirements.txt", (FX / "requirements/requirements.txt").read_bytes())[0]
    rel = "venv/lib/python3.13/site-packages/requests-2.25.0.dist-info/METADATA"
    inst = parse_file("p/" + rel, (FX / rel).read_bytes())[0]
    merged = {c.purl: c for c in dedupe(lock + req + inst)}
    c = merged["pkg:pypi/requests@2.25.0"]
    assert c.meta["evidence"] == EV_INSTALLED
    assert c.meta["paths"] == ["p/poetry.lock", "p/requirements.txt", "p/" + rel]
