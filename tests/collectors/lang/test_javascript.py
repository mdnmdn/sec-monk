from __future__ import annotations

import json
from pathlib import Path

import pytest

from secmonk.collectors import lang
from secmonk.collectors.lang import javascript as js
from secmonk.collectors.lang.base import EV_INSTALLED, EV_LOCKFILE, dedupe, parse_file

FX = Path(__file__).parents[2] / "fixtures" / "lang" / "javascript"


def run(rel: str, as_path: str | None = None):
    comps, warns = parse_file(as_path or rel.split("/", 1)[1], (FX / rel).read_bytes())
    assert warns == []
    return {c.purl: c for c in comps}


LODASH = "pkg:npm/lodash@4.17.20"
MINIMIST = "pkg:npm/minimist@1.2.5"
BABEL = "pkg:npm/%40babel/code-frame@7.12.13"


@pytest.mark.parametrize("rel", ["npm-v3/package-lock.json", "npm-v2/package-lock.json",
                                 "npm-v1/package-lock.json", "yarn-v1/yarn.lock", "yarn-berry/yarn.lock",
                                 "pnpm-v9/pnpm-lock.yaml", "pnpm-v6/pnpm-lock.yaml", "bun/bun.lock"])
def test_all_lockfiles_agree_on_direct_deps(rel):
    got = run(rel)
    for purl in (LODASH, MINIMIST, BABEL, "pkg:npm/semver@7.3.5"):
        assert purl in got, (rel, sorted(got))
    c = got[BABEL]
    assert c.name == "@babel/code-frame" and c.version == "7.12.13"
    assert c.ecosystem == "npm" and c.category == "library"
    assert c.meta["evidence"] == EV_LOCKFILE


def test_npm_v3_flags_and_root_skipped():
    got = run("npm-v3/package-lock.json")
    assert len(got) == 18
    assert not any("demo" in (c.purl or "") for c in got.values())      # root "" entry
    assert got["pkg:npm/semver@7.3.5"].meta["dev"] is True
    assert "dev" not in got[LODASH].meta
    assert got["pkg:npm/fsevents@2.3.2"].meta["optional"] is True
    assert got[LODASH].meta["resolved_host"] == "registry.npmjs.org"
    assert got[LODASH].meta["lockfile_version"] == 3


def test_npm_v1_tree_and_dev():
    got = run("npm-v1/package-lock.json")
    assert got["pkg:npm/semver@7.3.5"].meta["dev"] is True
    assert got[LODASH].meta["lockfile_version"] == 1


def test_npm_v2_nested_and_special_entries():
    lock = {"lockfileVersion": 2, "packages": {
        "": {"name": "root"},
        "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
        "node_modules/a/node_modules/b": {"version": "2.0.0", "peer": True},
        "node_modules/b": {"version": "3.0.0", "inBundle": True},
        "node_modules/ws": {"resolved": "packages/ws", "link": True},
        "packages/ws": {"name": "ws", "version": "0.0.1"},
        "node_modules/alias": {"name": "real-pkg", "version": "1.1.1"},
        "node_modules/@s/x": {"version": "1.2.3-beta.1", "dev": True},
    }}
    comps, _ = parse_file("package-lock.json", json.dumps(lock).encode())
    got = {c.purl: c for c in comps}
    assert set(got) == {"pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0", "pkg:npm/b@3.0.0", "pkg:npm/real-pkg@1.1.1",
                        "pkg:npm/%40s/x@1.2.3-beta.1"}
    assert got["pkg:npm/b@2.0.0"].meta["peer"] is True
    assert got["pkg:npm/b@3.0.0"].meta["bundled"] is True      # inBundle: emitted, flagged


def test_npm_v1_alias_and_git_version():
    lock = {"lockfileVersion": 1, "dependencies": {
        "al": {"version": "npm:real@1.0.0"},
        "g": {"version": "github:foo/bar#abcdef"},
        "parent": {"version": "1.0.0", "dependencies": {"child": {"version": "2.0.0", "dev": True}}},
    }}
    comps, _ = parse_file("npm-shrinkwrap.json", json.dumps(lock).encode())
    got = {c.name: c for c in comps}
    assert got["real"].version == "1.0.0"
    assert got["g"].version is None and got["g"].meta["non_registry_version"].startswith("github:")
    assert got["child"].meta["dev"] is True


def test_yarn_v1_multi_spec_key():
    text = ('# yarn lockfile v1\n\n"@a/b@^1.0.0", "@a/b@^1.1.0", c@~2:\n  version "1.2.0"\n'
            '  resolved "https://registry.yarnpkg.com/@a/b/-/b-1.2.0.tgz#abc"\n\n'
            '"foo@npm:bar@^1.0.0":\n  version "1.4.0"\n')
    comps, _ = parse_file("yarn.lock", text.encode())
    assert sorted(c.purl for c in comps) == ["pkg:npm/%40a/b@1.2.0", "pkg:npm/bar@1.4.0"]


def test_yarn_berry_skips_workspace_keeps_patch_inner_version():
    got = run("yarn-berry/yarn.lock")
    assert not any("workspace" in str(c.meta) for c in got.values())
    assert "pkg:npm/demo@0.0.0" not in got and not any("demo" == c.name for c in got.values())
    assert got["pkg:npm/fsevents@2.3.2"].meta["lockfile_format"] == "yarn-berry"
    # synthetic: only a patch: resolution, no plain npm entry
    text = ('__metadata:\n  version: 8\n\n'
            '"fsevents@patch:fsevents@npm%3A2.3.2#optional!builtin<compat/fsevents>":\n'
            '  version: 2.3.2\n  resolution: "fsevents@patch:fsevents@npm%3A2.3.2#optional!builtin<compat/fsevents>::version=2.3.2&hash=df0bf1"\n'
            '"w@workspace:.":\n  version: 0.0.0\n  resolution: "w@workspace:."\n'
            '"g@https://x/y.tgz":\n  version: 1.0.0\n  resolution: "g@https://x/y.tgz#hash"\n')
    comps, _ = parse_file("yarn.lock", text.encode())
    assert [(c.purl, c.meta.get("patched")) for c in comps] == [("pkg:npm/fsevents@2.3.2", True)]


def test_pnpm_v9_and_v6_dev_flags():
    v9 = run("pnpm-v9/pnpm-lock.yaml")
    assert len(v9) == 18 and v9[BABEL].meta["lockfile_version"] == "9.0"
    v6 = run("pnpm-v6/pnpm-lock.yaml")
    assert v6["pkg:npm/semver@7.3.5"].meta["dev"] is True
    assert "dev" not in v6[LODASH].meta


def test_pnpm_key_formats():
    v5 = ("lockfileVersion: 5.4\npackages:\n  /@babel/code-frame/7.12.13:\n    dev: false\n"
          "  /react-dom/17.0.2_react@17.0.2:\n    dev: true\n  github.com/foo/bar/abc:\n    name: bar\n    version: 1.0.0\n")
    c5 = {c.purl: c for c in parse_file("pnpm-lock.yaml", v5.encode())[0]}
    assert set(c5) == {BABEL, "pkg:npm/react-dom@17.0.2"}
    assert c5["pkg:npm/react-dom@17.0.2"].meta["dev"] is True
    v9 = ("lockfileVersion: '9.0'\npackages:\n  react-dom@18.2.0:\n    resolution: {integrity: x}\n"
          "  '@scope/pkg@1.0.0':\n    resolution: {integrity: x}\n"
          "snapshots:\n  react-dom@18.2.0(react@18.2.0):\n    dependencies: {}\n"
          "  tar@https://x/y.tgz: {}\n")
    c9 = {c.purl for c in parse_file("pnpm-lock.yaml", v9.encode())[0]}
    assert c9 == {"pkg:npm/react-dom@18.2.0", "pkg:npm/%40scope/pkg@1.0.0"}


def test_bun_lock_jsonc_and_skips():
    got = run("bun/bun.lock")
    assert len(got) == 18 and "pkg:npm/semver@7.3.5" in got
    text = ('{"lockfileVersion": 1, "workspaces": {"": {"devDependencies": {"d": "1",},},},'
            ' "packages": {"d": ["d@1.0.0", "", {}, "sha"], "w": ["w@workspace:packages/w"],'
            ' "x": ["x@github:o/r#abc", {}, "o-r-abc"], "al": ["al@npm:real@2.0.0", "", {}, "s"],},}')
    comps, w = parse_file("bun.lock", text.encode())
    assert w == []
    assert {c.purl: c.meta.get("dev_direct") for c in comps} == {
        "pkg:npm/d@1.0.0": True, "pkg:npm/real@2.0.0": None}


def test_installed_node_modules():
    paths = sorted(p.relative_to(FX / "installed").as_posix() for p in (FX / "installed").rglob("package.json"))
    got = {}
    for rel in paths:
        comps, w = parse_file(rel, (FX / "installed" / rel).read_bytes())
        assert w == []
        for c in comps:
            got[c.purl] = c
    assert {LODASH, MINIMIST, BABEL, "pkg:npm/semver@7.3.5", "pkg:npm/lru-cache@6.0.0"} == set(got)
    assert all(c.meta["evidence"] == EV_INSTALLED for c in got.values())
    # nested fixture inside a package's own (non node_modules) folder is ignored
    assert lang.parsers_for("node_modules/lodash/test/fixtures/package.json") == []
    assert lang.parsers_for("app/package.json") == []
    assert lang.parsers_for("usr/lib/node_modules/npm/package.json")
    assert lang.parsers_for("app/node_modules/.pnpm/a@1.0.0/node_modules/a/package.json")


def test_installed_requires_name_and_version():
    assert parse_file("node_modules/x/package.json", b'{"name": "x"}') == ([], [])
    assert parse_file("node_modules/x/package.json", b'{"version": "1.0.0"}') == ([], [])


def test_malformed_input_is_a_warning_not_a_crash():
    comps, warns = parse_file("package-lock.json", b"{not json")
    assert comps == [] and len(warns) == 1
    comps, warns = parse_file("pnpm-lock.yaml", b"- just\n- a list\n")
    assert comps == [] and warns == []


def test_dedupe_lockfile_plus_installed_keeps_installed_and_both_paths():
    lock = parse_file("app/package-lock.json", (FX / "npm-v3/package-lock.json").read_bytes())[0]
    inst = parse_file("app/node_modules/lodash/package.json",
                      (FX / "installed/node_modules/lodash/package.json").read_bytes())[0]
    merged = {c.purl: c for c in dedupe(lock + inst)}
    c = merged[LODASH]
    assert c.meta["evidence"] == EV_INSTALLED
    assert c.meta["paths"] == ["app/package-lock.json", "app/node_modules/lodash/package.json"]
    assert len(merged) == 18


def test_registered():
    names = {p.name for p in lang.REGISTRY}
    assert {"npm-package-lock", "yarn-lock", "pnpm-lock", "bun-lock", "node-modules"} <= names
    assert js.parse_yarn_lock


# --------------------------------------------------------------------------- review fixes
import subprocess
import sys
import textwrap


@pytest.mark.parametrize("kind", ["pnpm", "berry"])
def test_deeply_nested_yaml_does_not_crash_the_process(kind):
    """L1: libyaml's C parser overflows the C stack (SIGSEGV) on deeply nested input. Run in a
    subprocess so a regression kills the child, not the test suite."""
    code = textwrap.dedent(f"""
        import sys
        from secmonk.collectors.lang import parse_file
        n = 100000
        if "{kind}" == "pnpm":
            path, data = "pnpm-lock.yaml", ("lockfileVersion: '9.0'\\npackages: " + "[" * n + "]" * n + "\\n").encode()
        else:
            path, data = "yarn.lock", ("__metadata:\\n  version: 8\\nx: " + "[" * n + "]" * n + "\\n").encode()
        comps, warns = parse_file(path, data)
        assert comps == [] and len(warns) == 1 and "too deep" in warns[0], warns
        print("OK")
    """)
    r = subprocess.run([sys.executable, "-I", "-c", code], check=False, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "OK" in r.stdout, (r.returncode, r.stderr[-500:])


def test_yaml_depth_estimate_and_moderate_nesting_still_parses():
    assert js.yaml_depth("a: 1\nb:\n  c: 2\n") < 5
    assert js.yaml_depth("x: " + "[" * 500 + "]" * 500) >= 500
    assert js.yaml_depth("- - - - - - x\n") >= 3
    assert js.yaml_depth("a:\n" + " " * 300 + "b: 1\n") > js.MAX_YAML_DEPTH
    nested = "[" * 100 + "]" * 100                               # > fast-loader threshold, < limit
    text = ("lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {integrity: x}\n"
            f"    extra: {nested}\n")
    comps, warns = parse_file("pnpm-lock.yaml", text.encode())
    assert [c.purl for c in comps] == ["pkg:npm/a@1.0.0"] and not warns


def test_yarn_v1_name_split_at_first_at_after_index_zero():
    """L6: git/ssh specs contain further '@' characters."""
    text = ('"left-pad@git+ssh://git@github.com/o/left-pad.git#abc":\n  version "1.3.0"\n\n'
            '"@scope/pkg@^1.0.0":\n  version "1.2.3"\n\n'
            'plain@^2.0.0:\n  version "2.0.1"\n\n'
            '"al@npm:real@^1.0.0":\n  version "1.0.5"\n')
    comps, _ = parse_file("yarn.lock", text.encode())
    assert {c.purl for c in comps} == {"pkg:npm/left-pad@1.3.0", "pkg:npm/%40scope/pkg@1.2.3",
                                       "pkg:npm/plain@2.0.1", "pkg:npm/real@1.0.5"}


def test_yarn_berry_archive_url_suffix_stripped():
    """L13: `resolution: "foo@npm:1.2.3::__archiveUrl=https%3A%2F%2F..."`."""
    text = ('__metadata:\n  version: 8\n\n'
            '"foo@npm:^1.0.0":\n  version: 1.2.3\n'
            '  resolution: "foo@npm:1.2.3::__archiveUrl=https%3A%2F%2Fnpm.example.com%2Ffoo.tgz"\n\n'
            '"@s/bar@npm:^2.0.0":\n  version: 2.0.0\n'
            '  resolution: "@s/bar@npm:2.0.0::__archiveUrl=https%3A%2F%2Fx%2Fbar.tgz#abc"\n')
    comps, warns = parse_file("yarn.lock", text.encode())
    assert {c.purl for c in comps} == {"pkg:npm/foo@1.2.3", "pkg:npm/%40s/bar@2.0.0"} and not warns


def test_npm_bundled_entries_emitted_with_flag_v1_and_v2():
    v1 = {"lockfileVersion": 1, "dependencies": {"b": {"version": "1.0.0", "bundled": True}}}
    (c,) = parse_file("package-lock.json", json.dumps(v1).encode())[0]
    assert c.purl == "pkg:npm/b@1.0.0" and c.meta["bundled"] is True
    v3 = {"lockfileVersion": 3, "packages": {"node_modules/b": {"version": "1.0.0", "inBundle": True},
                                              "node_modules/c": {"version": "1.0.0"}}}
    got = {c.name: c for c in parse_file("package-lock.json", json.dumps(v3).encode())[0]}
    assert got["b"].meta["bundled"] is True and "bundled" not in got["c"].meta


def test_alias_with_empty_or_leading_at_does_not_crash():
    assert js._alias("n", "npm:@") == ("n", "npm:@")
    assert js._alias("n", "npm:real") == ("n", "npm:real")
    assert js._alias("n", "npm:real@1.0.0") == ("real", "1.0.0")
    assert js._alias("n", "npm:@s/real@1.0.0") == ("@s/real", "1.0.0")
