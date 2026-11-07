from __future__ import annotations

import json
from pathlib import Path

from secmonk.collectors import lang
from secmonk.collectors.lang.base import EV_INSTALLED, EV_LOCKFILE, dedupe, parse_file

FX = Path(__file__).parents[2] / "fixtures" / "lang" / "php"


def run(rel: str, path: str | None = None):
    comps, warns = parse_file(path or rel.split("/", 1)[1], (FX / rel).read_bytes())
    assert warns == []
    return {c.purl: c for c in comps}


def test_composer_lock_dev_and_v_prefix():
    got = run("composer2/composer.lock")
    g = got["pkg:composer/guzzlehttp/guzzle@7.4.0"]
    assert (g.name, g.version, g.ecosystem) == ("guzzlehttp/guzzle", "7.4.0", "Packagist")
    assert g.meta["evidence"] == EV_LOCKFILE and "dev" not in g.meta
    p = got["pkg:composer/symfony/polyfill-php80@1.43.0"]          # lock says v1.43.0
    assert p.version == "1.43.0" and p.meta["raw_version"] == "v1.43.0"
    assert got["pkg:composer/phpunit/phpunit@9.5.0"].meta["dev"] is True
    assert len(got) == 7


def test_installed_json_composer2_dev_names():
    got = run("composer2/vendor/composer/installed.json")
    assert got["pkg:composer/guzzlehttp/guzzle@7.4.0"].meta["evidence"] == EV_INSTALLED
    assert got["pkg:composer/phpunit/phpunit@9.5.0"].meta["dev"] is True
    assert "dev" not in got["pkg:composer/guzzlehttp/psr7@2.13.2"].meta


def test_installed_json_composer1_list_and_dev_branch():
    comps, w = parse_file("vendor/composer/installed.json",
                          (FX / "composer1/vendor/composer/installed.json").read_bytes())
    assert w == []
    by = {c.name: c for c in comps}
    assert by["symfony/polyfill-mbstring"].purl == "pkg:composer/symfony/polyfill-mbstring@1.13.1"
    inh = by["acme/in-house"]
    assert inh.version is None and inh.meta["dev_branch"] == "dev-master"
    assert inh.purl == "pkg:composer/acme/in-house"


def test_branch_alias_and_matching():
    lock = {"packages": [{"name": "a/b", "version": "1.x-dev"}, {"name": "a/c", "version": "V2.0.0"},
                         {"name": "bad"}, {"name": "x/y", "version": "v1.0.0-beta1"}], "packages-dev": None}
    comps, _ = parse_file("composer.lock", json.dumps(lock).encode())
    assert [(c.name, c.version) for c in comps] == [("a/b", None), ("a/c", "2.0.0"), ("x/y", "1.0.0-beta1")]
    assert lang.parsers_for("vendor/composer/installed.json")
    assert not lang.parsers_for("vendor/installed.json")


def test_malformed():
    comps, warns = parse_file("composer.lock", b"{oops")
    assert comps == [] and len(warns) == 1
    assert parse_file("composer.lock", b"[]") == ([], [])


def test_dedupe_installed_beats_lock():
    lock = parse_file("app/composer.lock", (FX / "composer2/composer.lock").read_bytes())[0]
    inst = parse_file("app/vendor/composer/installed.json",
                      (FX / "composer2/vendor/composer/installed.json").read_bytes())[0]
    merged = {c.purl: c for c in dedupe(lock + inst)}
    c = merged["pkg:composer/guzzlehttp/guzzle@7.4.0"]
    assert c.meta["evidence"] == EV_INSTALLED
    assert c.meta["paths"] == ["app/composer.lock", "app/vendor/composer/installed.json"]
    assert len(merged) == 7
