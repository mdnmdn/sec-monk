"""Cross-cutting behaviour of the parser registry: vendored paths, dedupe flags, warnings, safe_library."""

from __future__ import annotations

import pytest

from secmonk.collectors.lang import base, parse_file, parsers_for, wants
from secmonk.collectors.lang.base import EV_LOCKFILE, dedupe, library, safe_library
from secmonk.models import CAT_LIBRARY, Component

_CONTENT = {
    "package-lock.json": b'{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}',
    "yarn.lock": b'a@^1.0.0:\n  version "1.0.0"\n',
    "requirements.txt": b"requests==2.0.0\n",
    "poetry.lock": b'[[package]]\nname = "a"\nversion = "1.0.0"\n',
    "Cargo.lock": b'[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
    "go.mod": b"module m\ngo 1.21\nrequire github.com/a/b v1.0.0\n",
    "composer.lock": b'{"packages":[{"name":"a/b","version":"1.0.0"}]}',
    "pom.xml": b"<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>"
               b"<version>1</version></dependency></dependencies></project>",
}


@pytest.mark.parametrize("path", [
    "app/node_modules/foo/package-lock.json",
    "app/node_modules/foo/requirements.txt",
    "node_modules/foo/yarn.lock",
    "usr/lib/python3/site-packages/foo/poetry.lock",
    "usr/lib/python3/dist-packages/foo/requirements.txt",
    "home/u/.cargo/registry/src/idx/serde-1.0/Cargo.lock",
    "app/vendor/github.com/x/y/go.mod",
    "app/vendor/acme/lib/composer.lock",
    "app/vendor/acme/lib/pom.xml",
])
def test_vendored_lockfiles_and_manifests_are_not_project_evidence(path):
    data = _CONTENT[path.rsplit("/", 1)[-1]]
    assert parse_file(path, data) == ([], [])
    assert not [p for p in parsers_for(path, data) if p.evidence in (base.EV_LOCKFILE, base.EV_MANIFEST)]
    # the same file outside a dependency directory *is* evidence
    top = path.rsplit("/", 1)[-1]
    assert parse_file(f"proj/{top}", data)[0]


@pytest.mark.parametrize("path", [
    "app/package-lock.json", "app/requirements.txt", "Cargo.lock", "app/go.mod", "app/composer.lock",
    # installed-package metadata stays
    "app/node_modules/foo/package.json",
    "app/vendor/composer/installed.json",
    "usr/lib/python3/site-packages/foo-1.0.dist-info/METADATA",
])
def test_non_vendored_and_installed_metadata_still_wanted(path):
    assert wants(path)


def _c(name, ver, evidence=EV_LOCKFILE, **meta):
    c = library("npm", name, ver, path=f"p/{meta.pop('where', 'a')}", evidence=evidence, parser="t",
                **{k: v for k, v in meta.items() if v is not None})
    return c


def test_dedupe_scope_flags_require_every_instance():
    a = _c("x", "1.0.0", dev=True, optional=True, peer=True, dev_optional=True, where="a")
    b = _c("x", "1.0.0", dev=True, where="b")                      # not optional/peer anywhere else
    (m,) = dedupe([a, b])
    assert m.meta["dev"] is True
    assert not any(k in m.meta for k in ("optional", "peer", "dev_optional"))
    assert m.meta["paths"] == ["p/a", "p/b"]


def test_dedupe_dev_dropped_when_also_a_production_dependency():
    (m,) = dedupe([_c("y", "1.0.0", dev=True, where="a"), _c("y", "1.0.0", where="b")])
    assert "dev" not in m.meta


def test_dedupe_all_dev_stays_dev():
    (m,) = dedupe([_c("z", "1", dev=True, where="a"), _c("z", "1", dev=True, where="b")])
    assert m.meta["dev"] is True


def test_parse_file_accepts_tuple_results_with_warnings():
    def parse(path, data):
        return [Component(name="a", version="1", category=CAT_LIBRARY, purl="pkg:npm/a@1")], ["careful"]

    p = base.LangParser("t", "npm", EV_LOCKFILE, lambda p: p == "tuple.lock", parse)
    base.REGISTRY.append(p)
    try:
        comps, warns = parse_file("tuple.lock", b"x")
    finally:
        base.REGISTRY.remove(p)
    assert len(comps) == 1 and warns == ["tuple.lock: careful"]


def test_safe_library_returns_none_on_malformed_entries():
    assert safe_library("npm", "", "1.0.0", path="p", evidence=EV_LOCKFILE, parser="t") is None
    assert safe_library("npm", "ok", "1.0.0", path="p", evidence=EV_LOCKFILE, parser="t") is not None


def test_one_malformed_entry_does_not_drop_the_rest():
    lock = b'{"lockfileVersion":3,"packages":{"node_modules/":{"version":"1.0.0"},"node_modules/ok":{"version":"2.0.0"}}}'
    comps, warns = parse_file("package-lock.json", lock)
    assert [c.purl for c in comps] == ["pkg:npm/ok@2.0.0"] and not warns
