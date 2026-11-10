"""docker-engine: endpoint resolution (contexts, host, env), TLS, ssh:// dial-stdio, container selectors.

Everything is offline: Docker contexts are built in a temp $DOCKER_CONFIG (tests/collectors/conftest.py isolates
the env), ssh is a fake process, TLS runs against a local 127.0.0.1 server with throwaway certificates.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import ipaddress
import json
import ssl
import subprocess
import sys
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from secmonk.collectors import docker_engine as de
from secmonk.collectors import docker_transport as dt_
from secmonk.collectors.base import REGISTRY

FX = Path(__file__).parent.parent / "fixtures" / "collectors" / "docker" / "engine"
ROWS = json.loads((FX / "containers-json.json").read_text())


# --------------------------------------------------------------------------- helpers

def write_context(cfg: Path, name: str, host: str | None, *, desc: str = "", skip: bool | None = None,
                  tls: dict[str, bytes] | None = None) -> Path:
    cid = hashlib.sha256(name.encode()).hexdigest()
    d = cfg / "contexts" / "meta" / cid
    d.mkdir(parents=True)
    docker: dict = {}
    if host is not None:
        docker["Host"] = host
    if skip is not None:
        docker["SkipTLSVerify"] = skip
    (d / "meta.json").write_text(json.dumps({"Name": name, "Metadata": {"Description": desc},
                                             "Endpoints": {"docker": docker}}))
    if tls:
        t = cfg / "contexts" / "tls" / cid / "docker"
        t.mkdir(parents=True)
        for k, v in tls.items():
            (t / f"{k}.pem").write_bytes(v)
    return d


@pytest.fixture
def cfg(monkeypatch, tmp_path) -> Path:
    d = tmp_path / "dockercfg"
    d.mkdir()
    monkeypatch.setenv("DOCKER_CONFIG", str(d))
    return d


@pytest.fixture
def local_sock(monkeypatch, tmp_path) -> str:
    """A well-known socket candidate that exists and accepts (so discovery picks it)."""
    p = tmp_path / "local.sock"
    p.write_text("")
    monkeypatch.setattr(de, "candidate_sockets", lambda opts=None: [str(p)])
    monkeypatch.setattr(de, "_refuses", lambda path: False)
    return str(p)


def make_tar(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for n, data in members:
            ti = tarfile.TarInfo(n)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


OSR = b'ID=alpine\nVERSION_ID=3.20.1\n'
APK = b"P:musl\nV:1.2.5-r0\nA:x86_64\no:musl\n\n"


# --------------------------------------------------------------------------- contexts and precedence

def test_list_contexts_reads_meta_and_marks_current(cfg, local_sock):
    write_context(cfg, "build", "ssh://deploy@build-01.example.test:2222", desc="build box")
    write_context(cfg, "prod", "tcp://user:pw@engine.example.test:2376", skip=True)
    bad = cfg / "contexts" / "meta" / ("0" * 64)
    bad.mkdir()
    (bad / "meta.json").write_text("[1, 2]")
    (cfg / "config.json").write_text(json.dumps({"currentContext": "build", "auths": {}}))

    ctxs = {c["name"]: c for c in de.list_contexts()}
    assert ctxs["default"] == {"name": "default", "host": f"unix://{local_sock}",
                               "description": "Local engine (well-known socket)", "current": False}
    assert ctxs["build"]["current"] and ctxs["build"]["description"] == "build box"
    assert ctxs["build"]["host"] == "ssh://build-01.example.test:2222"        # no user in listings
    assert ctxs["prod"]["host"] == "tcp://engine.example.test:2376"           # no credentials
    assert ctxs["0" * 64]["host"] is None and "not a JSON object" in ctxs["0" * 64]["description"]
    assert [c["name"] for c in de.list_contexts(context="prod") if c["current"]] == ["prod"]
    assert not any(c["current"] for c in de.list_contexts(host="tcp://h:1"))


def test_list_contexts_without_config(cfg, local_sock):
    assert de.list_contexts() == [{"name": "default", "host": f"unix://{local_sock}",
                                   "description": "Local engine (well-known socket)", "current": True}]


def test_endpoint_precedence(cfg, local_sock, monkeypatch, tmp_path):
    other = tmp_path / "other.sock"
    other.write_text("")
    write_context(cfg, "ctx-opt", "tcp://opt.example.test:2375")
    write_context(cfg, "ctx-env", "tcp://env.example.test:2375")
    write_context(cfg, "ctx-cur", "ssh://cur.example.test")
    (cfg / "config.json").write_text(json.dumps({"currentContext": "ctx-cur"}))
    monkeypatch.setenv("DOCKER_HOST", "tcp://dockerhost.example.test:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "ctx-env")

    opts = {"socket": str(other), "host": "tcp://hostopt.example.test", "context": "ctx-opt"}
    assert de.find_endpoint(opts).unix == str(other)
    opts.pop("socket")
    assert de.find_endpoint(opts).host == "hostopt.example.test"
    opts.pop("host")
    ep = de.find_endpoint(opts)
    assert (ep.host, ep.context) == ("opt.example.test", "ctx-opt")
    assert de.find_endpoint({}).host == "dockerhost.example.test"
    monkeypatch.delenv("DOCKER_HOST")
    assert de.find_endpoint({}).host == "env.example.test"
    monkeypatch.delenv("DOCKER_CONTEXT")
    ep = de.find_endpoint({})
    assert ep.scheme == "ssh" and ep.ssh.host == "cur.example.test" and ep.context == "ctx-cur"
    (cfg / "config.json").write_text(json.dumps({"currentContext": "default"}))
    assert de.find_endpoint({}).unix == local_sock
    # "default" asks for the local engine even when another context is current
    (cfg / "config.json").write_text(json.dumps({"currentContext": "ctx-cur"}))
    assert de.find_endpoint({"context": "default"}).unix == local_sock


def test_requested_endpoint_is_never_replaced(cfg, local_sock, monkeypatch):
    with pytest.raises(RuntimeError, match="context 'nope' not found.*--context"):
        de.find_endpoint({"context": "nope"})
    monkeypatch.setenv("DOCKER_CONTEXT", "gone")
    with pytest.raises(RuntimeError, match="'gone' not found.*DOCKER_CONTEXT"):
        de.find_endpoint({})
    monkeypatch.delenv("DOCKER_CONTEXT")
    (cfg / "config.json").write_text(json.dumps({"currentContext": "vanished"}))
    with pytest.raises(RuntimeError, match="'vanished' not found.*currentContext"):
        de.find_endpoint({})
    (cfg / "config.json").write_text("{not json")
    with pytest.raises(RuntimeError, match="cannot read Docker config"):
        de.find_endpoint({})
    (cfg / "config.json").write_text("{}")
    write_context(cfg, "k8s-only", None)
    with pytest.raises(RuntimeError, match="no docker endpoint"):
        de.find_endpoint({"context": "k8s-only"})
    write_context(cfg, "local-missing", "unix:///nonexistent/docker.sock")
    with pytest.raises(RuntimeError, match="does not exist"):
        de.find_endpoint({"context": "local-missing"})
    with pytest.raises(RuntimeError, match="Unsupported Docker host 'npipe://"):
        de.find_endpoint({"host": "npipe:////./pipe/docker_engine"})
    with pytest.raises(RuntimeError, match="invalid ssh host"):
        de.find_endpoint({"host": "ssh://-oProxyCommand=touch_x"})
    with pytest.raises(RuntimeError, match="invalid ssh host"):
        de.find_endpoint({"host": "ssh://user@-oProxyCommand=x"})


def test_oversized_and_mistyped_context_meta(cfg):
    d = write_context(cfg, "big", "tcp://h:1")
    (d / "meta.json").write_bytes(b" " * (dt_.MAX_JSON + 1))
    with pytest.raises(RuntimeError, match="larger than"):
        de.find_endpoint({"context": "big"})
    d = write_context(cfg, "typed", "tcp://h:1")
    (d / "meta.json").write_text(json.dumps({"Name": "typed", "Endpoints": {"docker": {"Host": 42}}}))
    with pytest.raises(RuntimeError, match="no docker endpoint"):
        de.find_endpoint({"context": "typed"})
    d = write_context(cfg, "liar", "tcp://h:1")
    (d / "meta.json").write_text(json.dumps({"Name": "someone-else", "Endpoints": {"docker": {"Host": "tcp://h"}}}))
    with pytest.raises(RuntimeError, match="names 'someone-else'"):
        de.find_endpoint({"context": "liar"})


# --------------------------------------------------------------------------- tcp + TLS resolution

def test_tcp_ports_and_tls_sources(cfg, monkeypatch, tmp_path):
    ep = de.find_endpoint({"host": "tcp://engine.example.test"})
    assert (ep.port, ep.tls) == (2375, None) and ep.label == "engine.example.test:2375"
    ep = de.find_endpoint({"host": "tcp://engine.example.test", "tls_verify": "true"})
    assert ep.port == 2376 and ep.tls == dt_.TLSConfig(verify=True)
    ep = de.find_endpoint({"host": "tcp://engine.example.test", "tls_ca": "/x/ca.pem", "tls_verify": "false"})
    assert ep.tls == dt_.TLSConfig(ca="/x/ca.pem", verify=False)
    with pytest.raises(ValueError, match="tls_verify"):
        de.find_endpoint({"host": "tcp://h", "tls_verify": "maybe"})

    certs = tmp_path / "certs"
    certs.mkdir()
    for k in ("ca", "cert", "key"):
        (certs / f"{k}.pem").write_text("x")
    monkeypatch.setenv("DOCKER_HOST", "tcp://[fd00::5]")
    monkeypatch.setenv("DOCKER_CERT_PATH", str(certs))
    assert de.find_endpoint({}).tls is None                     # cert path alone does not enable TLS (Docker CLI)
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "1")
    ep = de.find_endpoint({})
    assert ep.tls == dt_.TLSConfig(ca=str(certs / "ca.pem"), cert=str(certs / "cert.pem"),
                                   key=str(certs / "key.pem"), verify=True)
    assert ep.port == 2376 and ep.label == "[fd00::5]:2376" and str(ep) == "tcp://[fd00::5]:2376"

    write_context(cfg, "tls", "tcp://ctx.example.test:2376", tls={"ca": b"x", "cert": b"y", "key": b"z"})
    write_context(cfg, "insecure", "tcp://ins.example.test", skip=True)
    write_context(cfg, "plain", "tcp://plain.example.test")
    tdir = cfg / "contexts" / "tls" / hashlib.sha256(b"tls").hexdigest() / "docker"
    ep = de.find_endpoint({"context": "tls"})
    assert ep.tls == dt_.TLSConfig(ca=str(tdir / "ca.pem"), cert=str(tdir / "cert.pem"), key=str(tdir / "key.pem"))
    ep = de.find_endpoint({"context": "insecure"})
    assert ep.tls == dt_.TLSConfig(verify=False) and ep.port == 2376
    assert de.find_endpoint({"context": "plain"}).tls is None   # DOCKER_TLS_VERIFY applies to DOCKER_HOST only
    ep = de.find_endpoint({"context": "tls", "tls_cert": "/o/c.pem", "tls_verify": False})
    assert ep.tls.cert == "/o/c.pem" and ep.tls.ca == str(tdir / "ca.pem") and ep.tls.verify is False


def test_tls_context_construction(tmp_path):
    ctx = dt_.TLSConfig(verify=False).ssl_context()
    assert ctx.verify_mode == ssl.CERT_NONE and not ctx.check_hostname
    ctx = dt_.TLSConfig().ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    with pytest.raises(RuntimeError, match="TLS CA file .*missing.pem"):
        dt_.TLSConfig(ca=str(tmp_path / "missing.pem")).ssl_context()
    (tmp_path / "junk.pem").write_text("not a certificate")
    with pytest.raises(RuntimeError, match="invalid TLS material"):
        dt_.TLSConfig(ca=str(tmp_path / "junk.pem")).ssl_context()
    with pytest.raises(RuntimeError, match="is not a regular file"):
        dt_.TLSConfig(ca=str(tmp_path)).ssl_context()


def _pki(tmp_path: Path) -> dict[str, Path]:
    """Throwaway CA, server cert for 127.0.0.1 and client cert (sample: synthetic, generated per test run)."""
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.UTC)

    def cert(cn: str, key, issuer_key, issuer_name, *, ca=False, san=None):
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
             .issuer_name(issuer_name or x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(hours=1))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if san:
            b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
        if ca:
            b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                              content_commitment=False, key_encipherment=False,
                                              data_encipherment=False, key_agreement=False,
                                              encipher_only=False, decipher_only=False), critical=True)
            b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        else:
            b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                                critical=False)
        return b.sign(issuer_key, hashes.SHA256())

    out: dict[str, Path] = {}

    def save(name: str, obj) -> None:
        p = tmp_path / f"{name}.pem"
        if hasattr(obj, "private_bytes"):
            p.write_bytes(obj.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
        else:
            p.write_bytes(obj.public_bytes(serialization.Encoding.PEM))
        out[name] = p

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = cert("test-ca", ca_key, ca_key, None, ca=True)
    srv_key, cli_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    srv = cert("engine", srv_key, ca_key, ca.subject,
               san=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    cli = cert("client", cli_key, ca_key, ca.subject)
    for n, o in (("ca", ca), ("server-cert", srv), ("server-key", srv_key), ("cert", cli), ("key", cli_key)):
        save(n, o)
    return out


def test_https_round_trip_with_client_cert(tmp_path, cfg):
    pki = _pki(tmp_path)
    seen: list[str] = []

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a) -> None:
            pass

        def do_GET(self) -> None:
            seen.append(self.path)
            body = json.dumps(ROWS[:1]).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    try:
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    except OSError as e:  # pragma: no cover - sandbox without loopback tcp
        pytest.skip(f"no loopback tcp: {e}")
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(pki["server-cert"], pki["server-key"])
    sctx.load_verify_locations(pki["ca"])
    sctx.verify_mode = ssl.CERT_REQUIRED                       # the engine demands a client certificate
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        port = srv.server_address[1]
        write_context(cfg, "tls", f"tcp://127.0.0.1:{port}",
                      tls={k: pki[k].read_bytes() for k in ("ca", "cert", "key")})
        rows = de.list_containers(context="tls")
        assert rows[0]["Names"] == ["/web"] and seen == ["/containers/json?all=0"]
        # the system trust store does not know the throwaway CA
        with pytest.raises(RuntimeError, match="cannot talk to Docker engine at tcp://127.0.0.1"):
            de.list_containers(host=f"tcp://127.0.0.1:{port}", tls_cert=str(pki["cert"]), tls_key=str(pki["key"]))
    finally:
        srv.shutdown()
        srv.server_close()


# --------------------------------------------------------------------------- ssh:// over dial-stdio

# A Python stand-in for `ssh ... docker system dial-stdio`, run as a real child process on OS pipes.
# argv: <state dir> <mode>. Routes: <state dir>/routes.json {path: file}; requests are appended to requests.log;
# <state dir>/stderr.txt is written to stderr. Modes: serve | hang (never answers) | stall (headers, then nothing)
# | die (stderr only, exit 127).
_STAND_IN = r"""
import json, sys, time
from pathlib import Path
d, mode = Path(sys.argv[1]), sys.argv[2]
err = d / "stderr.txt"
if err.exists():
    sys.stderr.write(err.read_text()); sys.stderr.flush()
if mode == "die":
    sys.exit(127)
req = b""
while b"\r\n\r\n" not in req:
    c = sys.stdin.buffer.read(1)
    if not c:
        sys.exit(1)
    req += c
with open(d / "requests.log", "ab") as f:
    f.write(req)
if mode == "hang":
    time.sleep(60)
path = req.split(b" ", 2)[1].decode().split("?")[0]
routes = json.loads((d / "routes.json").read_text())
if path not in routes:
    sys.exit(0)                     # hang up without answering
body = Path(routes[path]).read_bytes()
out = sys.stdout.buffer
out.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body))
if mode == "stall":
    out.flush(); time.sleep(60)
out.write(body)
out.flush()
sys.stdin.buffer.read()            # stay up like dial-stdio until killed or stdin closes
"""


class StandIn:
    def __init__(self, d: Path):
        self.dir, self.mode, self.procs, self.argvs = d, "serve", [], []

    def spawn(self, argv):
        self.argvs.append(argv)
        p = subprocess.Popen([sys.executable, "-I", "-c", _STAND_IN, str(self.dir), self.mode],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.procs.append(p)
        return p

    def requests(self) -> bytes:
        log = self.dir / "requests.log"
        return log.read_bytes() if log.exists() else b""


@pytest.fixture
def fake_ssh(monkeypatch, tmp_path):
    d = tmp_path / "standin"
    d.mkdir()
    export = d / "export.tar"
    export.write_bytes(make_tar([("etc/os-release", OSR), ("lib/apk/db/installed", APK)]))
    (d / "containers.json").write_text(json.dumps(ROWS))
    (d / "routes.json").write_text(json.dumps({
        "/containers/json": str(d / "containers.json"),
        "/containers/web/json": str(FX / "container-inspect.json"),
        "/containers/8dfafdbc3a40a1f7c0a2a8e5d4a0b4a3c2f1e0d9c8b7a69584736251403f2e1d/export": str(export),
    }))
    st = StandIn(d)
    monkeypatch.setattr(dt_, "_spawn", st.spawn)
    yield st
    for p in st.procs:
        if p.poll() is None:
            p.kill()
            p.wait()


def test_ssh_argv_is_fixed(cfg):
    ep = de.find_endpoint({"host": "ssh://deploy@build-01.example.test:2222", "identity": "/keys/id_ed25519",
                           "ssh_bin": "/usr/bin/ssh", "connect_timeout": "7"})
    argv = dt_.ssh_argv(ep)
    assert argv[0] == "/usr/bin/ssh" and argv[-3:] == ["--", "build-01.example.test", "docker system dial-stdio"]
    for a, b in (("-p", "2222"), ("-l", "deploy"), ("-i", "/keys/id_ed25519"), ("-o", "BatchMode=yes"),
                 ("-o", "ConnectTimeout=7")):
        assert any(argv[i:i + 2] == [a, b] for i in range(len(argv) - 1)), (a, b)
    assert ep.label == "build-01.example.test:2222" and str(ep) == "ssh://deploy@build-01.example.test:2222"
    ep = de.find_endpoint({"host": "ssh://build-01.example.test:22"})
    assert ep.label == "build-01.example.test" and "-l" not in dt_.ssh_argv(ep)


def test_ssh_collector_options(cfg):
    ep = de.find_endpoint({"host": "ssh://h.example.test", "ssh_option": ["ProxyJump=bastion.example.test"],
                           "known_hosts": "/kh/known hosts", "insecure_host_key": "true"})
    argv = dt_.ssh_argv(ep)
    for opt in ("ProxyJump=bastion.example.test", 'UserKnownHostsFile="/kh/known hosts"',
                "StrictHostKeyChecking=no"):
        assert ["-o", opt] in [argv[i:i + 2] for i in range(len(argv) - 1)], opt
    assert argv.index("ProxyJump=bastion.example.test") < argv.index("BatchMode=yes")
    with pytest.raises(ValueError, match="allow_agent, ssh_config apply to the paramiko"):
        de.find_endpoint({"host": "ssh://h.example.test", "allow_agent": False, "ssh_config": "/x"})
    with pytest.raises(ValueError, match="transport=paramiko is not supported"):
        de.find_endpoint({"host": "ssh://h.example.test", "transport": "paramiko"})
    with pytest.raises(ValueError, match="known_hosts path"):
        de.find_endpoint({"host": "ssh://h.example.test", "known_hosts": '/a"b'})
    with pytest.raises(ValueError, match="newlines"):
        de.find_endpoint({"host": "ssh://h.example.test", "ssh_option": "A=b\nProxyCommand=x"})


def test_http_over_ssh_pipe_and_container_asset(fake_ssh, cfg):
    rows = de.list_containers(host="ssh://deploy@build-01.example.test")
    assert [r["Names"][0] for r in rows] == ["/web", "/db", "/old-job"]
    req = fake_ssh.requests()
    assert req.startswith(b"GET /containers/json?all=0 HTTP/1.1\r\n") and b"Host: docker\r\n" in req
    assert fake_ssh.procs[0].poll() is not None                # one process per connection, ended on close

    inv = REGISTRY["docker-engine"]().collect("web", host="ssh://deploy@build-01.example.test")
    assert inv.asset.id == "container:build-01.example.test/web"
    assert inv.asset.meta["engine"] == "ssh://build-01.example.test"          # no user in stored data
    assert {c.name for c in inv.components if c.category == "os-package"} == {"musl"}
    assert not inv.partial
    assert len(fake_ssh.procs) == 3 and all(p.poll() is not None for p in fake_ssh.procs)
    assert all(p.stderr.closed and p.stdout.closed for p in fake_ssh.procs)
    c = REGISTRY["docker-engine"]()
    assert c.expand_targets("re:^(web|db)$", host="ssh://build-01.example.test") == ["web", "db"]


def test_ssh_failure_reports_stderr_quickly(fake_ssh, cfg):
    (fake_ssh.dir / "stderr.txt").write_text("bash: line 1: docker: command not found\n")
    fake_ssh.mode = "die"
    t0 = time.monotonic()
    with pytest.raises(RuntimeError, match=r"ssh://build-01.*\(ssh: bash: line 1: docker: command not found\)"):
        de.list_containers(host="ssh://build-01.example.test")
    assert time.monotonic() - t0 < 3


@pytest.mark.parametrize("mode", ["hang", "stall"])
def test_ssh_read_timeout(fake_ssh, cfg, mode):
    """A remote engine that stops answering ends in a clear error after `timeout`, not a hang."""
    fake_ssh.mode = mode
    t0 = time.monotonic()
    with pytest.raises(RuntimeError, match="no data from the remote engine for 0.5s"):
        de.list_containers(host="ssh://build-01.example.test", timeout="0.5")
    assert time.monotonic() - t0 < 4
    assert fake_ssh.procs[0].poll() is not None and fake_ssh.procs[0].stderr.closed


def test_context_with_ssh_host(fake_ssh, cfg):
    write_context(cfg, "remote", "ssh://ops@build-02.example.test:2200")
    inv = REGISTRY["docker-engine"]().collect("web", context="remote")
    assert inv.asset.id == "container:build-02.example.test:2200/web"
    assert inv.asset.meta["engine_context"] == "remote"
    assert fake_ssh.argvs[0][-2:] == ["build-02.example.test", "docker system dial-stdio"]


def test_asset_id_labels():
    assert de.Endpoint(unix="/var/run/docker.sock").label is None
    assert de.Endpoint(host="10.0.0.5", port=2375).label == "10.0.0.5:2375"
    assert de.Endpoint(ssh=dt_.parse_target("u@[fd00::1]:2200")).label == "[fd00::1]:2200"

    class Client:
        endpoint = de.Endpoint(host="engine.example.test", port=2376)

        def get_json(self, path):
            return {"Id": "c" * 64, "Name": "/api", "Config": {}, "State": {}, "HostConfig": {}}

        def open(self, path):
            class Conn:
                def close(self):
                    pass
            return Conn(), io.BytesIO(make_tar([("etc/os-release", OSR)]))

    inv = de.DockerEngineCollector()._collect_container(Client(), "api")
    assert inv.asset.id == "container:engine.example.test:2376/api"
    assert inv.asset.meta["engine"] == "tcp://engine.example.test:2376"


# --------------------------------------------------------------------------- selectors

def test_select_containers_patterns():
    sel = de.select_containers
    assert sel("web, db ,,web", ROWS) == ["web", "db"]                 # exact: as given, deduped
    assert sel("nosuch", ROWS) == ["nosuch"]                           # exact names are not checked
    assert sel("*", ROWS) == ["web", "db", "old-job"]
    assert sel("old-*,w?b", ROWS) == ["old-job", "web"]
    assert sel("re:^(web|db)$", ROWS) == ["web", "db"]
    assert sel("re:job", ROWS) == ["old-job"]
    assert sel("1b2c3d4e5f60", ROWS) == ["1b2c3d4e5f60"]               # id, exact: passes through
    assert sel("1b2c*", ROWS) == ["db"]                                # 12-char id matched by a glob
    assert sel("re:^ffee", ROWS) == ["old-job"]
    assert sel("[dw]*", ROWS) == ["web", "db"]
    assert sel("image:nginx:1.25,w*", ROWS) == ["image:nginx:1.25", "web"]
    assert sel("WEB*", [{"Id": "a" * 64, "Names": ["/WEB1"]}, {"Id": "b" * 64, "Names": ["/web2"]}]) == ["WEB1"]


def test_select_containers_errors():
    with pytest.raises(ValueError, match=r"no container matches 'api-\*'; available: web, db, old-job"):
        de.select_containers("web,api-*", ROWS)
    with pytest.raises(ValueError, match="invalid regular expression '\\(unclosed'"):
        de.select_containers("re:(unclosed", ROWS)
    with pytest.raises(ValueError, match="longer than 256"):
        de.select_containers("re:" + "a" * 300, ROWS)
    with pytest.raises(ValueError, match="empty regular expression"):
        de.select_containers("re:", ROWS)
    with pytest.raises(ValueError, match="available: none"):
        de.select_containers("*", [])


class _ListClient:
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.endpoint = de.Endpoint(unix="/x")

    def get_json(self, path: str):
        self.paths.append(path)
        return ROWS if path.endswith("all=1") else ROWS[:2]


def test_expand_targets():
    c = REGISTRY["docker-engine"]()
    client = _ListClient()
    assert c.expand_targets("web", client=client) == ["web"]
    assert c.expand_targets("web,db,web", client=client) == ["web", "db"]
    assert c.expand_targets(None, client=client) == [None]
    assert client.paths == []                                          # no pattern -> no listing
    # an image the engine cannot resolve passes through (collect reports it); images are always resolved
    assert c.expand_targets("web,image:alpine:3.20", client=client) == ["web", "image:alpine:3.20"]
    assert client.paths == ["/images/alpine:3.20/json"]
    client.paths.clear()
    assert c.expand_targets("re:.", client=client) == ["web", "db"]   # running only
    assert client.paths == ["/containers/json?all=0"]
    assert c.expand_targets("*-job", client=client, all="true") == ["old-job"]
    with pytest.raises(ValueError, match="no container matches 'old-\\*'"):
        c.expand_targets("old-*", client=client)


# --------------------------------------------------------------------------- review fixes (2026-11-10)

@pytest.mark.parametrize("host", ["tcp://user:s3cret@h.example.test:notaport", "tcp://user:s3cret@-h:1",
                                  "ssh://user:s3cret@h.example.test", "ssh://user:s3cret@-oProxyCommand=x",
                                  "npipe://user:s3cret@x/pipe"])
def test_errors_never_echo_credentials(cfg, host):
    with pytest.raises((RuntimeError, ValueError)) as ei:
        de.find_endpoint({"host": host})
    assert "s3cret" not in str(ei.value)


def test_ssh_parse_target_hides_password():
    from secmonk.collectors.ssh import parse_target

    with pytest.raises(ValueError, match="contains ':'") as ei:
        parse_target("user:pw@host.example.test")
    assert "pw" not in str(ei.value).replace("passwords", "")


def test_regex_selectors_are_bounded():
    hostile = [{"Id": "e" * 64, "Names": ["/" + "a" * 28 + "!"]}, {"Id": "f" * 64, "Names": ["/" + "a" * 4000]}]
    for pat in ("re:^(a+)+$", "re:(a|aa)*$", "re:(x[a-z]*)*", "re:.*.*.*.*!"):
        with pytest.raises(ValueError, match="catastrophic|repeating quantifiers"):
            de.select_containers(pat, hostile)
    t0 = time.monotonic()
    with pytest.raises(ValueError, match="no container matches"):
        de.select_containers("re:^a*a*a*$", hostile)       # allowed; the 4000-char name is never tested
    assert time.monotonic() - t0 < 1
    assert de.select_containers("re:^(web|db)-[0-9]+$,re:(ab)+", [{"Id": "1" * 64, "Names": ["/web-1"]},
                                                                {"Id": "2" * 64, "Names": ["/xabab"]}]) == ["web-1", "xabab"]
    with pytest.raises(ValueError, match="available: " + "a" * 64 + ","):
        de.select_containers("nomatch*", hostile[::-1])     # untrusted names are shortened in messages


def test_timeouts_are_coerced(cfg, monkeypatch, tmp_path):
    sock = tmp_path / "s.sock"
    sock.write_text("")
    assert de._client({"socket": str(sock), "timeout": "2.5"}).timeout == 2.5
    assert de._client({"socket": str(sock)}).timeout == 30
    for bad in ("soon", "0", "-1", "inf"):
        with pytest.raises(ValueError, match="timeout must be a"):
            de._client({"socket": str(sock), "timeout": bad})
    assert de.find_endpoint({"host": "ssh://h.example.test", "connect_timeout": "7.9"}).connect_timeout == 7
    with pytest.raises(ValueError, match="connect_timeout must be a number"):
        de.find_endpoint({"host": "ssh://h.example.test", "connect_timeout": "x"})
