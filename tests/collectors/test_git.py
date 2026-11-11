"""`git` collector: target grammar, hardened clone (file:// from a local bare repository), cache, local working
trees (no git command runs there), project detection on synthetic trees.

Offline: repositories are built at test time with the local `git` binary (tests needing it are skipped without
it); detection trees are synthetic.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from secmonk.collectors import git as g
from secmonk.collectors.base import REGISTRY

HAS_GIT = shutil.which("git") is not None
needs_git = pytest.mark.skipif(not HAS_GIT, reason="git not installed")
SHA = "0123456789abcdef0123456789abcdef01234567"

PACKAGE_LOCK = {
    "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
    "packages": {
        "": {"name": "app", "version": "1.0.0", "dependencies": {"lodash": "^4.17.20"},
             "devDependencies": {"minimist": "^1.2.5"}},
        "node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"},
        "node_modules/minimist": {"version": "1.2.5", "dev": True,
                                  "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz"},
    },
}


# --------------------------------------------------------------------------- helpers

def fixture_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_AUTHOR_NAME": "t",
                "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
                "GIT_COMMITTER_EMAIL": "t@example.invalid"})
    return env


def sh(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(["git", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", *args], cwd=cwd,
                          env=fixture_env(), check=True, capture_output=True, text=True).stdout.strip()


def write(root: Path, files: dict[str, str | bytes | dict]) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, dict):
            content = json.dumps(content)
        p.write_bytes(content if isinstance(content, bytes) else content.encode())


def make_worktree(path: Path, files: dict) -> Path:
    path.mkdir(parents=True)
    sh("init", "-q", str(path))
    write(path, files)
    sh("add", "-A", cwd=path)
    sh("commit", "-q", "-m", "init", cwd=path)
    return path


def make_bare(tmp_path: Path) -> tuple[Path, Path]:
    """(bare repository, its source working tree): main with a package-lock, branch `feature` adding a Cargo.lock,
    tag v1 on the first commit."""
    src = make_worktree(tmp_path / "src", {"package.json": {"name": "app", "version": "1.0.0"},
                                           "package-lock.json": PACKAGE_LOCK})
    sh("tag", "v1", cwd=src)
    sh("checkout", "-q", "-b", "feature", cwd=src)
    write(src, {"Cargo.toml": '[package]\nname = "x"\nversion = "0.1.0"\n',
                "Cargo.lock": 'version = 3\n\n[[package]]\nname = "smallvec"\nversion = "1.6.0"\n'
                              'source = "registry+https://github.com/rust-lang/crates.io-index"\n'})
    sh("add", "-A", cwd=src)
    sh("commit", "-q", "-m", "rust", cwd=src)
    sh("checkout", "-q", "main", cwd=src)
    bare = tmp_path / "repo.git"
    sh("clone", "-q", "--bare", str(src), str(bare))
    return bare, src


class Spy:
    """Records the argv/env of every git command and runs it."""

    def __init__(self, monkeypatch):
        self.calls: list[tuple[list[str], dict]] = []
        real = g._run

        def run(argv, **kw):
            self.calls.append((list(argv), dict(kw.get("env") or {})))
            return real(argv, **kw)
        monkeypatch.setattr(g, "_run", run)

    def find(self, sub: str) -> tuple[list[str], dict]:
        return next(c for c in self.calls if sub in c[0])


def collect(target: str, **opts):
    return g.GitCollector().collect(target, **{"user_config": "false", **opts})


# --------------------------------------------------------------------------- target grammar

@pytest.mark.parametrize("target,kind,shown,key", [
    ("https://GitHub.com/org/repo.git", "https", "https://GitHub.com/org/repo.git", "github.com/org/repo"),
    ("https://github.com/org/repo", "https", "https://github.com/org/repo", "github.com/org/repo"),
    ("git+https://github.com/org/repo.git/", "https", "https://github.com/org/repo.git/", "github.com/org/repo"),
    ("https://user:s3cret@git.example.com:8443/team/app.git?x=1#f", "https", "https://git.example.com:8443/team/app.git",
     "git.example.com:8443/team/app"),
    ("ssh://git@github.com/org/repo.git", "ssh", "ssh://git@github.com/org/repo.git", "github.com/org/repo"),
    ("git+ssh://git@github.com:22/org/repo.git", "ssh", "ssh://git@github.com:22/org/repo.git", "github.com/org/repo"),
    ("ssh://git@git.example.com:2222/team/app.git", "ssh", "ssh://git@git.example.com:2222/team/app.git",
     "git.example.com:2222/team/app"),
    ("git@github.com:org/repo.git", "scp", "git@github.com:org/repo.git", "github.com/org/repo"),
    ("github.com:org/repo", "scp", "github.com:org/repo", "github.com/org/repo"),
    ("deploy@[::1]:srv/app.git", "scp", "deploy@[::1]:srv/app.git", "[::1]/srv/app"),
])
def test_remote_targets(target, kind, shown, key):
    t = g.parse_git_target(target)
    assert (t.kind, t.shown, g.repo_key(t)) == (kind, shown, key)
    assert "s3cret" not in t.shown and "s3cret" not in g.repo_key(t)
    assert g.is_git_target(target)


def test_https_credentials_are_used_but_never_shown():
    t = g.parse_git_target("https://user:s3cret@git.example.com/a/b.git")
    assert t.url == "https://user:s3cret@git.example.com/a/b.git"     # what git fetches from
    assert t.user is None and "user" not in t.shown


def test_file_and_local_targets(tmp_path):
    t = g.parse_git_target(f"file://{tmp_path}/r.git")
    assert t.kind == "file" and g.repo_key(t) == f"file:{tmp_path.resolve()}/r"
    for s in (str(tmp_path), f"git:{tmp_path}", "./x", "x", "~/x"):
        assert g.parse_git_target(s).kind == "local"
    assert g.parse_git_target(f"git:{tmp_path}").path == str(tmp_path.resolve())


@pytest.mark.parametrize("target,msg", [
    ("", "empty"),
    ("-uupload-pack=touch /tmp/x", "must not start with '-'"),
    ("git+-x", "invalid"),
    ("ext::sh -c touch% /tmp/pwned", "remote-helper"),
    ("git+ext::sh -c id", "remote-helper"),
    ("fd::3", "remote-helper"),
    ("http://example.com/a.git", "unsupported"),
    ("git://example.com/a.git", "unsupported"),
    ("ftp://example.com/a.git", "unsupported"),
    ("https://example.com/", "invalid repository path"),
    ("https://-oProxyCommand=x/a.git", "invalid host"),
    ("ssh://-oProxyCommand=x/a.git", "invalid host"),
    ("-oProxyCommand=x:a.git", "must not start"),
    ("ssh://u:pw@example.com/a.git", "passwords are not accepted"),
    ("u:pw@example.com:a.git", "passwords are not accepted"),
    ("host:-x", "invalid repository path"),
    ("https://example.com/a\n.git", "control characters"),
    ("file://remote.example.com/a.git", "must be local"),
])
def test_refused_targets(target, msg):
    with pytest.raises(ValueError, match=msg) as e:
        g.parse_git_target(target)
    assert "pw" not in str(e.value).replace("passwords", "")


@pytest.mark.parametrize("target,expected", [
    ("git+https://h/a", True), ("https://github.com/org/repo", True), ("git@github.com:org/repo.git", True),
    ("git@github.com:org/repo", True), ("ssh://git@h/a.git", True), ("file:///srv/a.git", True),
    ("git:./checkout", True),
    ("deploy@10.0.0.5", False), ("deploy@10.0.0.5:2222", False), ("host:22", False), ("ssh://h", False),
    ("ssh://u@h:2222", False), ("k8s://ctx", False), ("[::1]:22", False), ("local", False),
])
def test_is_git_target(target, expected):
    assert g.is_git_target(target) is expected


def test_check_ref():
    assert g.check_ref(None) == (None, False)
    assert g.check_ref("main") == ("main", False)
    assert g.check_ref("release/1.2") == ("release/1.2", False)
    assert g.check_ref("v1.2.0") == ("v1.2.0", False)
    assert g.check_ref(SHA.upper()) == (SHA, True)
    for bad in ("-x", "--upload-pack=x", "a..b", "a@{1}", "a//b", "a/", "a.lock", "a b", "x;y", "a\n"):
        with pytest.raises(ValueError):
            g.check_ref(bad)


def test_ssh_command_quotes_every_value():
    assert g.ssh_command({}) is None
    cmd = g.ssh_command({"identity": "/tmp/my key;touch x", "known_hosts": "/tmp/kh $(id)",
                         "ssh_option": ["ProxyJump=bastion", "User=a b"], "connect_timeout": "7"})
    argv = shlex.split(cmd)
    assert argv[1:5] == ["-o", "ProxyJump=bastion", "-o", "User=a b"]
    assert "UserKnownHostsFile=/tmp/kh $(id)" in argv and "BatchMode=yes" in argv and "ConnectTimeout=7" in argv
    assert argv[-2:] == ["-i", "/tmp/my key;touch x"]
    insecure = shlex.split(g.ssh_command({"insecure_host_key": True}))
    assert "StrictHostKeyChecking=no" in insecure
    with pytest.raises(ValueError):
        g.ssh_command({"ssh_option": "A=1\nB=2"})


def test_git_env(monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/elsewhere")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.fsmonitor'='touch x'")
    monkeypatch.setenv("GIT_SSL_CAINFO", "/ca.pem")
    env = g.git_env(user_config=True)
    assert "GIT_DIR" not in env and "GIT_CONFIG_PARAMETERS" not in env and env["GIT_SSL_CAINFO"] == "/ca.pem"
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert env["SSH_ASKPASS_REQUIRE"] == "never" and "GIT_CONFIG_GLOBAL" not in env
    iso = g.git_env(user_config=False, ssh_command="ssh -o BatchMode=yes")
    assert iso["GIT_CONFIG_NOSYSTEM"] == "1" and iso["GIT_CONFIG_GLOBAL"] == os.devnull
    assert iso["GIT_SSH_COMMAND"] == "ssh -o BatchMode=yes"


# --------------------------------------------------------------------------- clone

@needs_git
def test_clone_file_url_with_hardening(tmp_path, monkeypatch):
    bare, src = make_bare(tmp_path)
    spy = Spy(monkeypatch)
    inv = collect(f"file://{bare}")
    assert "git" in REGISTRY
    fetch, env = spy.find("fetch")
    for flag in ("core.hooksPath=" + os.devnull, "core.fsmonitor=false", "core.symlinks=false", "protocol.allow=never",
                 "protocol.file.allow=always", "protocol.ext.allow=never", "submodule.recurse=false",
                 "transfer.fsckObjects=true", "fetch.fsckObjects=true"):
        assert flag in fetch, flag
    i = fetch.index("--")
    assert fetch[i + 1:] == [bare.resolve().as_uri(), "HEAD"]
    assert {"--no-tags", "--no-recurse-submodules", "--depth=1"} <= set(fetch[:i])
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_LFS_SKIP_SMUDGE"] == "1"
    init, _ = spy.find("init")
    assert "--template=" in init
    checkout, cenv = spy.find("checkout")
    assert cenv["GIT_CONFIG_GLOBAL"] == os.devnull and checkout[-1] == "FETCH_HEAD"

    a = inv.asset
    assert a.id == f"git:file:{bare.resolve().with_suffix('')}" and a.type == "repo" and a.name == "repo"
    assert a.meta["commit"] == sh("rev-parse", "main", cwd=src) and a.meta["source"] == "clone"
    assert a.meta["projects"][0]["kind"] == "node" and a.meta["projects"][0]["package_manager"] == "npm"
    names = {c.name: c for c in inv.components}
    assert names["lodash"].version == "4.17.20" and names["minimist"].meta.get("dev") is True
    assert list(g.cache_root().iterdir()) == []                        # clone removed


@needs_git
def test_clone_https_refuses_file_protocol(tmp_path, monkeypatch):
    """protocol.file.allow is `never` for remote targets: a server-side redirect / insteadOf to file:// fails."""
    assert "protocol.file.allow=never" in g.hardening_config(allow_file=False)


@needs_git
def test_clone_ref_branch_tag_commit(tmp_path):
    bare, src = make_bare(tmp_path)
    feat = collect(f"file://{bare}", ref="feature")
    assert feat.asset.id.endswith("@feature") and {"rust", "node"} <= set(feat.asset.meta["project_kinds"])
    assert any(c.name == "smallvec" for c in feat.components)
    tag = collect(f"file://{bare}", ref="v1")
    assert not any(c.name == "smallvec" for c in tag.components)
    sha = sh("rev-parse", "feature", cwd=src)
    by_sha = collect(f"file://{bare}", ref=sha, depth="0")
    assert by_sha.asset.meta["commit"] == sha and by_sha.asset.meta["depth"] == 0
    with pytest.raises(g.GitError, match="full 40-hex"):
        collect(f"file://{bare}", ref=sha[:10])
    with pytest.raises(g.GitError, match="fetch"):
        collect(f"file://{bare}", ref="nope")


@needs_git
def test_keep_and_prune(tmp_path):
    bare, _ = make_bare(tmp_path)
    inv = collect(f"file://{bare}", keep="true")
    kept = Path(inv.asset.meta["clone_dir"])
    assert (kept / "package-lock.json").is_file() and kept.parent.parent == g.cache_root()
    assert g.prune_cache(now=time.time() + 10 * g.CACHE_TTL) == []        # keep=true survives pruning
    meta_file = kept.parent / g.META_FILE
    meta = json.loads(meta_file.read_text())
    meta["keep"] = False
    meta_file.write_text(json.dumps(meta))
    assert g.prune_cache(now=time.time() + 10 * g.CACHE_TTL) == [kept.parent.name]
    assert not kept.exists()


@needs_git
def test_failed_clone_leaves_nothing(tmp_path):
    with pytest.raises(g.GitError):
        collect(f"file://{tmp_path}/missing.git")
    assert list(g.cache_root().iterdir()) == []


def test_run_timeout_kills_the_process_group(tmp_path):
    start = time.monotonic()
    with pytest.raises(g.GitError, match="timed out"):
        g._run([sys.executable, "-c", "import time; time.sleep(30)"], env=dict(os.environ), timeout=0.5)
    assert time.monotonic() - start < 10


def test_run_disk_cap(tmp_path):
    out = tmp_path / "w"
    out.mkdir()
    code = f"open({str(out / 'big')!r}, 'wb').write(b'x' * 3_000_000); import time; time.sleep(30)"
    with pytest.raises(g.GitError, match="max_mb"):
        g._run([sys.executable, "-c", code], env=dict(os.environ), timeout=20, watch=out, max_bytes=1_000_000)


def test_clone_without_git(monkeypatch, tmp_path):
    monkeypatch.setattr(g.shutil, "which", lambda name: None)
    with pytest.raises(g.GitError, match="not installed"):
        collect("https://example.com/org/repo.git")
    assert list(g.cache_root().iterdir()) == []


# --------------------------------------------------------------------------- local working trees

@needs_git
def test_local_worktree_runs_no_repo_programs(tmp_path, monkeypatch):
    marker = tmp_path / "PWNED"
    wt = make_worktree(tmp_path / "wt", {"package-lock.json": PACKAGE_LOCK, "package.json": {"name": "app"}})
    sh("remote", "add", "origin", "https://user:tok@git.example.com/team/app.git", cwd=wt)
    script = tmp_path / "evil.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\n")
    script.chmod(0o755)
    sh("config", "core.fsmonitor", str(script), cwd=wt)
    sh("config", "core.hooksPath", str(tmp_path / "hooks"), cwd=wt)
    for hook in ("post-checkout", "post-index-change", "reference-transaction"):
        h = wt / ".git" / "hooks" / hook
        h.write_text(f"#!/bin/sh\ntouch {marker}\n")
        h.chmod(0o755)

    def no_process(*a, **k):
        raise AssertionError(f"a command ran in a local checkout: {a}")
    monkeypatch.setattr(subprocess, "Popen", no_process)
    inv = collect(str(wt))
    assert not marker.exists()
    a = inv.asset
    assert a.id == f"repo:{wt.resolve()}" and a.type == "repo" and a.meta["source"] == "local"
    assert a.meta["url"] == "https://git.example.com/team/app.git" and a.meta["branch"] == "main"
    assert len(a.meta["commit"]) == 40
    assert {c.name for c in inv.components} == {"lodash", "minimist"}
    sub = collect(f"git:{wt}/.git/..")                                 # git: prefix, same tree
    assert sub.asset.id == a.id


@needs_git
def test_local_subdir_bare_and_plain(tmp_path):
    wt = make_worktree(tmp_path / "wt", {"svc/package-lock.json": PACKAGE_LOCK})
    inv = collect(str(wt / "svc"))
    assert inv.asset.meta["worktree"] == str(wt.resolve()) and inv.asset.id == f"repo:{(wt / 'svc').resolve()}"
    bare = tmp_path / "b.git"
    sh("init", "-q", "--bare", str(bare))
    with pytest.raises(ValueError, match="bare repository"):
        collect(str(bare))
    (tmp_path / "plain").mkdir()
    with pytest.raises(ValueError, match="not inside a git working tree"):
        collect(str(tmp_path / "plain"))
    with pytest.raises(NotADirectoryError):
        collect(str(tmp_path / "missing"))


# --------------------------------------------------------------------------- project detection

def by_path(projects: list[dict]) -> dict[tuple[str, str], dict]:
    return {(p["path"], p["kind"]): p for p in projects}


def test_detect_every_kind(tmp_path):
    write(tmp_path, {
        "web/package.json": {"name": "web", "packageManager": "pnpm@9.1.0"},
        "web/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        "cli/package.json": {"name": "cli"},
        "yarnapp/package.json": {"name": "y"}, "yarnapp/yarn.lock": "# yarn lockfile v1\n",
        "bunapp/package.json": {"name": "b"}, "bunapp/bun.lockb": b"\x00bun",
        "rs/Cargo.toml": "[package]\nname='a'\n", "rs/Cargo.lock": "version = 3\n",
        "go/go.mod": "module x\n\ngo 1.22\n",
        "net/App.csproj": "<Project/>", "net/packages.lock.json": "{}",
        "mvn/pom.xml": "<project><modules><module>core</module></modules></project>",
        "gr/build.gradle.kts": "", "gr/settings.gradle.kts": 'include(":app", ":lib")\n',
        "gr/gradle/verification-metadata.xml": "<verification-metadata/>",
        "poetry/pyproject.toml": "[tool.poetry]\nname='p'\n", "poetry/poetry.lock": "",
        "uvp/pyproject.toml": "[project]\nname='u'\n[tool.uv]\n", "uvp/uv.lock": "version = 1\n",
        "pipenv/Pipfile": "", "pipenv/Pipfile.lock": "{}",
        "pdmp/pyproject.toml": "[tool.pdm]\n", "pdmp/pdm.lock": "",
        "pinned/requirements.txt": "requests==2.25.0\nflask==2.0.0 ; python_version>'3'\n# c\n",
        "ranges/requirements.txt": "requests>=2\n",
        "reqdir/requirements/base.txt": "django==4.2.0\n",
        "setup/setup.py": "", "setup/setup.cfg": "",
        "sw/Package.swift": "// swift-tools-version:5.9\n", "sw/Package.resolved": "{}",
        "ios/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved": "{}",
        "ios/Podfile": "", "ios/Podfile.lock": "",
        "dart/pubspec.yaml": "name: d\n", "dart/pubspec.lock": "packages: {}\n",
        "php/composer.json": "{}", "php/composer.lock": "{}",
        "rb/Gemfile": "", "rb/Gemfile.lock": "",
        "node_modules/x/package.json": {"name": "x"}, "vendor/github.com/a/b/go.mod": "module b\n",
        "third_party/lib/package.json": {"name": "copied"},
    })
    p = by_path(g.detect_projects(tmp_path))
    exp = {("web", "node"): "pnpm", ("cli", "node"): "npm", ("yarnapp", "node"): "yarn", ("bunapp", "node"): "bun",
           ("rs", "rust"): "cargo", ("go", "go"): "go", ("net", "dotnet"): "nuget", ("mvn", "java"): "maven",
           ("gr", "java"): "gradle", ("poetry", "python"): "poetry", ("uvp", "python"): "uv",
           ("pipenv", "python"): "pipenv", ("pdmp", "python"): "pdm", ("pinned", "python"): "pip",
           ("ranges", "python"): "pip", ("reqdir", "python"): "pip", ("setup", "python"): "setuptools",
           ("sw", "swift"): "swiftpm", ("dart", "dart"): "pub", ("php", "php"): "composer", ("rb", "ruby"): "bundler"}
    for key, pm in exp.items():
        assert p[key]["package_manager"] == pm, key
    assert not any(path.startswith(("node_modules", "vendor", "third_party")) for path, _ in p)
    missing = {k for k, v in p.items() if v["lockfile_missing"]}
    assert missing == {("cli", "node"), ("mvn", "java"), ("ranges", "python"), ("setup", "python")}
    assert p[("go", "go")]["note"].startswith("go.mod") and p[("pinned", "python")]["note"].startswith("requirements")
    assert p[("gr", "java")]["lockfiles"] == ["gr/gradle/verification-metadata.xml"]
    assert p[("gr", "java")]["workspace"] == {"tool": "gradle-settings", "members": [":app", ":lib"]}
    assert p[("mvn", "java")]["workspace"]["members"] == ["core"]
    assert p[("bunapp", "node")]["unparsed"] == ["bunapp/bun.lockb"]
    assert p[("rb", "ruby")]["unparsed"] == ["rb/Gemfile.lock"]
    ios = [x for x in g.detect_projects(tmp_path) if x["path"] == "ios"]
    assert {x["package_manager"] for x in ios} == {"swiftpm", "cocoapods"}


def test_detect_workspaces(tmp_path):
    write(tmp_path, {
        "package.json": {"name": "mono", "workspaces": ["packages/*"]}, "package-lock.json": "{}",
        "packages/a/package.json": {"name": "a"}, "packages/b/package.json": {"name": "b"},
        "rust/Cargo.toml": '[workspace]\nmembers = ["crates/*"]\n',
        "rust/crates/x/Cargo.toml": "[package]\nname='x'\n",
        "pn/package.json": {"name": "pn"}, "pn/pnpm-workspace.yaml": "packages:\n  - 'apps/*'\n  - libs/*\n",
        "pn/pnpm-lock.yaml": "", "pn/turbo.json": "{}",
        "gw/go.work": "go 1.22\n\nuse (\n\t./svc\n\t./lib\n)\n", "gw/svc/go.mod": "module svc\n",
        "dn/All.sln": 'Project("{FAE}") = "Api", "src\\Api\\Api.csproj", "{1}"\nEndProject\n',
        "dn/src/Api/Api.csproj": "<Project/>",
    })
    p = by_path(g.detect_projects(tmp_path))
    assert p[(".", "node")]["workspace"] == {"tool": "workspaces", "members": ["packages/*"]}
    assert p[("packages/a", "node")]["lockfile_from"] == "." and not p[("packages/a", "node")]["lockfile_missing"]
    assert p[("rust", "rust")]["lockfile_missing"] and p[("rust/crates/x", "rust")]["workspace_root"] == "rust"
    assert p[("pn", "node")]["workspace"] == {"tool": "pnpm-workspace", "members": ["apps/*", "libs/*"],
                                              "tools": ["turbo"]}
    assert p[("gw", "go")]["workspace"] == {"tool": "go.work", "members": ["./svc", "./lib"]}
    assert p[("dn", "dotnet")]["workspace"]["members"] == ["src/Api/Api.csproj"]
    facts, warns = g.tree_facts(tmp_path)
    assert "rust" in facts["lockfile_gaps"] and "rust/crates/x" not in facts["lockfile_gaps"]
    assert any("without a lockfile" in w and "rust (rust/cargo)" in w for w in warns)


def test_tree_facts_vendored_and_submodules(tmp_path):
    write(tmp_path, {".gitmodules": '[submodule "lib"]\n\tpath = deps/lib\n\turl = https://example.com/lib.git\n',
                     "vendor/modules.txt": "# x\n", "go.mod": "module m\n", "Gemfile.lock": ""})
    facts, warns = g.tree_facts(tmp_path)
    assert facts["vendored_dirs"] == ["vendor"] and facts["submodules"] == ["deps/lib"]
    assert any("submodule" in w for w in warns) and any("without a parser" in w for w in warns)


def test_detect_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside"
    write(outside, {"package.json": {"name": "secret", "workspaces": ["x"]}})
    root = tmp_path / "root"
    write(root, {"package.json": {"name": "r"}})
    (root / "link").symlink_to(outside, target_is_directory=True)
    (root / "sub").mkdir()
    (root / "sub" / "package.json").symlink_to(outside / "package.json")
    p = by_path(g.detect_projects(root))
    assert ("link", "node") not in p
    assert "workspace" not in p[("sub", "node")]                       # read_within refused the escape
