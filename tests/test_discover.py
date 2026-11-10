"""Host auto mode (`secmonk.discover`): candidates for local macOS / Linux / Windows and SSH targets.

Offline: the platform, paths and docker probe are monkeypatched; SSH goes through a fake transport whose
output is synthetic (shaped like `harvest.detect_script` + the tool check).
"""

from __future__ import annotations

import pytest

from secmonk import discover as dsc
from secmonk.collectors import docker_engine as de
from secmonk.collectors import harvest
from secmonk.collectors.ssh import Transport

P = harvest.DETECT_PREFIX


def detect_output(kernel="Linux", arch="x86_64", osr='PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian',
                  hostname="srv-01", tools=("dpkg", "docker"), prefixes=()) -> bytes:
    lines = ["motd noise", f"{P}kernel@@", kernel, f"{P}arch@@", arch, f"{P}os-release@@", osr, f"{P}sw_vers@@",
             f"{P}hostname@@", hostname, f"{P}machine-id@@", "0123456789abcdef", f"{P}end@@"]
    lines += [f"{dsc.TOOL_PREFIX}{t}" for t in tools]
    lines += [f"{dsc.TOOL_PREFIX}brew-prefix={p}" for p in prefixes]
    return ("\n".join(lines) + "\n").encode()


class FakeTransport(Transport):
    name = "fake"

    def __init__(self, rc=0, out=b"", err=b""):
        self.rc, self.out, self.err = rc, out, err
        self.calls: list[tuple[str, bytes | None]] = []

    def stream(self, cmd, timeout=60, stdin=None):  # pragma: no cover - run() is overridden
        raise NotImplementedError

    def run(self, cmd, timeout=60, stdin=None):
        self.calls.append((cmd, stdin))
        return self.rc, self.out, self.err


def by_id(res: dict) -> dict[str, dict]:
    return {c["id"]: c for c in res["candidates"]}


OK_PROBE = {"state": "ok", "endpoint": "unix:///var/run/docker.sock", "reason": None,
            "options": ["socket=/var/run/docker.sock"],
            "containers": [{"name": "web", "image": "nginx:1.25", "state": "running"}],
            "images": [{"id": "a" * 12, "tags": ["nginx:1.25", "nginx:latest"]}, {"id": "b" * 12, "tags": ["pg:16"]}]}


@pytest.fixture
def no_docker(monkeypatch):
    monkeypatch.setattr(dsc, "_docker_probe", lambda o, t: {"state": "none", "reason": "not found"})


# --------------------------------------------------------------------------- local

def _local(monkeypatch, os_name, *, prefixes=(), pms=(), plat="darwin"):
    from secmonk.collectors.process import backend

    monkeypatch.setattr(dsc, "_local_os", lambda: os_name)
    monkeypatch.setattr(dsc, "_brew_prefixes", lambda root=None: list(prefixes))
    monkeypatch.setattr(dsc, "_package_managers", lambda root=None: list(pms))
    monkeypatch.setattr(backend, "current_platform", lambda: plat)


def test_local_macos(monkeypatch, no_docker):
    _local(monkeypatch, "macos", prefixes=["/opt/homebrew"])
    res = dsc.discover_host()
    assert res["host"]["kind"] == "local" and res["host"]["target"] is None and res["host"]["os"] == "macos"
    c = by_id(res)
    assert list(c) == ["macos", "homebrew", "process", "fs-home"]
    assert c["macos"]["selected"] and c["process"]["selected"] and c["process"]["available"]
    assert not c["homebrew"]["selected"] and "already part of the macos scan" in c["homebrew"]["reason"]
    assert c["homebrew"]["details"] == {"prefixes": ["/opt/homebrew"]}
    assert c["fs-home"]["collector"] == "fs" and not c["fs-home"]["selected"]
    assert c["fs-home"]["options"] == ["binaries=false"]
    keys = {"id", "collector", "target", "options", "label", "description", "available", "reason", "selected",
            "details"}
    assert all(set(x) == keys for x in res["candidates"])


def test_local_linux(monkeypatch):
    _local(monkeypatch, "linux", prefixes=["/home/linuxbrew/.linuxbrew"], pms=["dpkg"], plat="linux")
    seen = {}

    def probe(o, t):
        seen["opts"] = o
        return OK_PROBE

    monkeypatch.setattr(dsc, "_docker_probe", probe)
    c = by_id(dsc.discover_host("localhost", context="colima"))
    assert list(c) == ["rootfs", "homebrew", "process", "fs-home", "docker", "docker-images"]
    assert c["rootfs"]["target"] == "/" and c["rootfs"]["selected"] and "(dpkg)" in c["rootfs"]["description"]
    assert c["homebrew"]["selected"]                                 # rootfs does not read Linuxbrew
    assert not c["process"]["available"] and not c["process"]["selected"]
    assert c["process"]["reason"] == "no linux process backend yet"
    d = c["docker"]
    assert d["collector"] == "docker-engine" and d["target"] == "*" and d["selected"]
    assert d["options"] == ["socket=/var/run/docker.sock"] and d["details"]["containers"][0]["name"] == "web"
    assert seen["opts"] == {"context": "colima"}
    im = c["docker-images"]
    assert im["collector"] == "docker-engine" and im["target"] == "image:*" and im["available"]
    assert not im["selected"] and im["options"] == ["socket=/var/run/docker.sock"]
    assert im["details"]["tagged_images"] == 3 and im["details"]["unique_ids"] == 2


def test_local_linux_without_package_db(monkeypatch, no_docker):
    _local(monkeypatch, "linux", pms=["pacman"], plat="linux")
    c = by_id(dsc.discover_host("local"))
    assert "pacman is not read" in c["rootfs"]["reason"] and c["rootfs"]["selected"]
    assert "homebrew" not in c and "docker" not in c


def test_local_windows(monkeypatch, no_docker):
    _local(monkeypatch, "windows", plat="windows")
    c = by_id(dsc.discover_host(""))
    assert not c["windows"]["available"] and "secmonk windows-script" in c["windows"]["reason"]
    assert not c["process"]["available"]


def test_docker_states(monkeypatch):
    _local(monkeypatch, "macos")
    monkeypatch.setattr(dsc, "_docker_probe", lambda o, t: {
        "state": "down", "endpoint": "unix:///x.sock", "reason": "cannot talk to Docker engine: refused",
        "options": ["socket=/x.sock"]})
    c = by_id(dsc.discover_host())
    d = c["docker"]
    assert not d["available"] and not d["selected"] and "refused" in d["reason"]
    assert not c["docker-images"]["available"] and "refused" in c["docker-images"]["reason"]
    monkeypatch.setattr(dsc, "_docker_probe", lambda o, t: {**OK_PROBE, "containers": [
        {"name": "old", "image": "x", "state": "exited"}]})
    d = by_id(dsc.discover_host())["docker"]
    assert d["available"] and not d["selected"] and d["reason"] == "no running containers"
    monkeypatch.setattr(dsc, "_docker_probe", lambda o, t: {**OK_PROBE, "images": []})
    im = by_id(dsc.discover_host())["docker-images"]
    assert not im["available"] and im["reason"] == "no tagged images"


def test_docker_probe(monkeypatch):
    def nf(opts):
        raise RuntimeError("Docker engine socket not found: tried /a")
    monkeypatch.setattr(de, "find_endpoint", nf)
    assert dsc._docker_probe({}, 1)["state"] == "none"

    def stale(opts):
        raise RuntimeError("Docker engine socket not found: tried /a; refusing connections (...): /a")
    monkeypatch.setattr(de, "find_endpoint", stale)
    assert dsc._docker_probe({}, 1)["state"] == "down"

    monkeypatch.setattr(de, "find_endpoint", lambda opts: de.Endpoint(unix="/s.sock", context="orb"))

    class Client:
        def __init__(self, ep, timeout):
            assert timeout == 1

        def ping(self):
            return True

        def get_json(self, path):
            if path == "/images/json":
                return [{"Id": "sha256:" + "a" * 64, "RepoTags": ["nginx:1", "nginx:latest"]},
                        {"Id": "sha256:" + "c" * 64, "RepoTags": ["<none>:<none>"]}, "junk"]
            assert path == "/containers/json?all=0"
            return [{"Id": "a" * 64, "Names": ["/" + "w" * 500], "Image": "nginx", "State": "running"}, "junk"]

    monkeypatch.setattr(de, "EngineClient", Client)
    p = dsc._docker_probe({}, 1)
    assert p["state"] == "ok" and p["options"] == ["context=orb"] and len(p["containers"][0]["name"]) == 128
    assert p["images"] == [{"id": "a" * 12, "tags": ["nginx:1", "nginx:latest"]}]       # dangling dropped

    class Down(Client):
        def ping(self):
            raise RuntimeError("permission denied on Docker socket unix:///s.sock")

    monkeypatch.setattr(de, "EngineClient", Down)
    p = dsc._docker_probe({}, 1)
    assert p["state"] == "down" and "permission denied" in p["reason"]


# --------------------------------------------------------------------------- ssh

def test_ssh_linux_with_docker(monkeypatch):
    seen = {}

    def probe(o, t):
        seen.update(o)
        return {**OK_PROBE, "endpoint": "ssh://deploy@srv.example.test:2222", "options": [
            "host=ssh://deploy@srv.example.test:2222"]}

    monkeypatch.setattr(dsc, "_docker_probe", probe)
    tr = FakeTransport(out=detect_output(tools=("dpkg", "docker", "evil;rm", "brew"),
                                         prefixes=("/home/linuxbrew/.linuxbrew", "/etc")))
    res = dsc.discover_host("ssh://deploy@srv.example.test:2222", transport=tr, identity="/keys/id",
                            ssh_option=["ProxyJump=bastion.example.test"], insecure_host_key=True)
    assert res["host"] == {"kind": "ssh", "target": "deploy@srv.example.test:2222", "name": "srv-01",
                           "os": "linux", "os_version": "Debian GNU/Linux 12 (bookworm)", "arch": "x86_64"}
    cmd, stdin = tr.calls[0]
    assert cmd == "sh -s" and stdin.decode().startswith(harvest.detect_script("/")) and len(tr.calls) == 1
    c = by_id(res)
    assert list(c) == ["ssh", "docker", "docker-images", "process"]
    assert c["docker-images"]["options"] == c["docker"]["options"]
    s = c["ssh"]
    assert s["target"] == "deploy@srv.example.test:2222" and s["selected"] and "(dpkg)" in s["description"]
    assert s["options"] == ["identity=/keys/id", "insecure_host_key=true",
                            "ssh_option=ProxyJump=bastion.example.test"]           # transport object not copied
    assert s["details"]["brew_prefixes"] == ["/home/linuxbrew/.linuxbrew"]       # /etc is not a known prefix
    assert "evil;rm" not in s["details"]["tools"]
    d = c["docker"]
    assert d["options"] == ["host=ssh://deploy@srv.example.test:2222", "identity=/keys/id",
                            "insecure_host_key=true", "ssh_option=ProxyJump=bastion.example.test"]
    assert seen["host"] == "ssh://deploy@srv.example.test:2222" and seen["identity"] == "/keys/id"
    assert not c["process"]["available"] and c["process"]["reason"] == "processes are only collected locally"


def test_ssh_docker_unreachable_and_podman(monkeypatch):
    monkeypatch.setattr(dsc, "_docker_probe", lambda o, t: {
        "state": "down", "endpoint": None, "reason": "cannot talk to Docker engine at ssh://srv: permission denied"})
    c = by_id(dsc.discover_host("srv.example.test", transport=FakeTransport(out=detect_output())))
    assert not c["docker"]["available"] and "permission denied" in c["docker"]["reason"]
    c = by_id(dsc.discover_host("srv.example.test", transport=FakeTransport(out=detect_output(tools=("podman",
                                                                                                    "rpm")))))
    assert not c["docker"]["available"] and "only podman" in c["docker"]["reason"]
    c = by_id(dsc.discover_host("srv.example.test", transport=FakeTransport(out=detect_output(tools=("apk",)))))
    assert "docker" not in c and "(apk)" in c["ssh"]["description"]


def test_ssh_macos(no_docker):
    out = detect_output(kernel="Darwin", arch="arm64", osr="", tools=("brew",), prefixes=("/opt/homebrew",))
    out = out.replace(f"{P}sw_vers@@\n".encode(), f"{P}sw_vers@@\nProductName: macOS\nProductVersion: 26.1\n".encode())
    res = dsc.discover_host("mac.example.test", transport=FakeTransport(out=out))
    assert res["host"]["os"] == "macos" and res["host"]["os_version"] == "macOS 26.1"
    assert "remote Mac" in by_id(res)["ssh"]["description"]


def test_ssh_errors(no_docker):
    with pytest.raises(ValueError, match="contains ':'"):
        dsc.discover_host("user:pw@srv.example.test")
    with pytest.raises(ValueError):
        dsc.discover_host("-oProxyCommand=x")
    with pytest.raises(RuntimeError, match="cannot reach srv.example.test over ssh \\(rc=255\\): "
                                           "ssh: Connection refused"):
        dsc.discover_host("srv.example.test", transport=FakeTransport(rc=255, err=b"ssh: Connection refused\n"))

    class Slow(FakeTransport):
        def run(self, cmd, timeout=60, stdin=None):
            raise TimeoutError("remote command timed out after 60s")

    with pytest.raises(RuntimeError, match="timed out"):
        dsc.discover_host("srv.example.test", transport=Slow())


def test_ssh_unrecognised_output_is_a_warning(no_docker):
    tr = FakeTransport(rc=0, out=b"x" * (dsc.MAX_PROBE_OUTPUT * 4))
    res = dsc.discover_host("srv.example.test", transport=tr)
    assert res["host"]["os"] == "unknown" and "not recognised" in res["warnings"][0]
    assert not by_id(res)["ssh"]["selected"]
    assert tr.calls[1][0].startswith("powershell")             # the ssh collector's Windows check was tried


# --------------------------------------------------------------------------- review fixes (2026-11-11)

def test_local_probe_forwards_tls_and_ssh_options(monkeypatch):
    _local(monkeypatch, "linux", pms=["dpkg"], plat="linux")
    seen = {}

    def probe(o, t):
        seen.update(o)
        return {**OK_PROBE, "options": ["host=tcp://engine.example.test:2376"]}

    monkeypatch.setattr(dsc, "_docker_probe", probe)
    c = by_id(dsc.discover_host(host="tcp://engine.example.test:2376", tls_ca="/c/ca.pem", tls_cert="/c/cert.pem",
                                tls_key="/c/key.pem", tls_verify=True, timeout="20", identity="/k/id"))
    assert seen == {"host": "tcp://engine.example.test:2376", "tls_ca": "/c/ca.pem", "tls_cert": "/c/cert.pem",
                    "tls_key": "/c/key.pem", "tls_verify": True, "timeout": "20", "identity": "/k/id"}
    want = ["host=tcp://engine.example.test:2376", "tls_ca=/c/ca.pem", "tls_cert=/c/cert.pem", "tls_key=/c/key.pem",
            "tls_verify=true", "identity=/k/id", "timeout=20"]
    assert c["docker"]["options"] == want and c["docker-images"]["options"] == want


def test_ssh_probe_timeout_covers_ssh_startup(monkeypatch):
    got = {}

    class Client:
        def __init__(self, ep, timeout):
            got["timeout"] = timeout

        def ping(self):
            raise RuntimeError("stop")

    monkeypatch.setattr(de, "EngineClient", Client)
    dsc._docker_probe({"host": "ssh://srv.example.test", "connect_timeout": "20"}, 5)
    assert got["timeout"] == 25
    dsc._docker_probe({"host": "ssh://srv.example.test"}, 5)
    assert got["timeout"] == 20                                    # default connect timeout 15 + 5


def test_remote_mac_docker_off_path(monkeypatch):
    seen = {}

    def probe(o, t):
        seen.update(o)
        return OK_PROBE

    monkeypatch.setattr(dsc, "_docker_probe", probe)
    out = detect_output(kernel="Darwin", arch="arm64", osr="", tools=("brew",))
    out += (f"{dsc.TOOL_PREFIX}docker-path=/opt/homebrew/bin/docker\n"
            f"{dsc.TOOL_PREFIX}docker-path=/tmp/evil/docker\n").encode()
    c = by_id(dsc.discover_host("mac.example.test", transport=FakeTransport(out=out)))
    assert seen["remote_docker"] == "/opt/homebrew/bin/docker"
    assert "remote_docker=/opt/homebrew/bin/docker" in c["docker"]["options"]
    assert "for p in /usr/local/bin/docker /opt/homebrew/bin/docker" in dsc.TOOLS_SCRIPT
    ep = de.find_endpoint({"host": "ssh://mac.example.test", "remote_docker": "/opt/homebrew/bin/docker"})
    from secmonk.collectors.docker_transport import ssh_argv
    assert ssh_argv(ep)[-1] == "/opt/homebrew/bin/docker system dial-stdio"
    with pytest.raises(ValueError, match="remote_docker must be one of"):
        de.find_endpoint({"host": "ssh://mac.example.test", "remote_docker": "/tmp/evil/docker"})
