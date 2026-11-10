"""Generate _design/mock/data.js: the payloads the web UI renders, produced by the real code on the test fixtures.

    uv run python scripts/design_mock.py            # rewrite _design/mock/data.js

Everything happens in a temporary directory; the payloads are built by the objects behind `secmonk ui`
(`ProcessMonitor`, `DataApi`, `JobRunner`) and by `secmonk.reports`, so the design renders real shapes.

Process monitor: `ProcessMonitor` on tests/fixtures/collectors/process/snapshot.json with the fixture tree, then one
simulated watch tick (a new binary, a replaced binary, a changed launch item).

Mirror: the source fixtures imported by the real sources (KEV, EPSS, cvelist, NVD, EUVD, OSV: Log4Shell and the
Alpine xz backdoor), plus hand-added records: GO-2022-1059 (golang.org/x/text < 0.3.8), CVE-2024-6197 / CVE-2024-7264
(curl) and the npm advisories GHSA-35jh-r3h4-6jhm (lodash), GHSA-xvch-5gv4-984h (minimist), GHSA-c2qf-rxjj-qqgw
(semver) are real records with their real ranges; MOCK-2026-0001 is fictional (fictional product "ExampleUpdater").
The EPSS fixture is a synthetic sample (illustrative scores).

Assets, scanned with the real collectors from copies of the fixtures under /srv (paths rewritten from the temporary
directory): payments-api (tests/fixtures/lang/java: log4j-core 2.14.1), web-frontend (lang/javascript/npm-v3, rescanned
by a scan job after a lodash upgrade, so one finding is `fixed`), alpine-rootfs (docker/alpine-3.20 + xz-libs
5.6.0-r0, scanned by the CLI so the history has a `cli` run), macbook (collectors/macos/root) and process:fixture-mac
(saved by the process monitor).

Docker engine: a fake engine on a Unix socket serving tests/fixtures/collectors/docker/engine (containers web, db,
old-job; only `web` can be inspected and exported, as the alpine rootfs), found by auto-discovery (the socket is shown
as /var/run/docker.sock). A scan job with the selector `web,d*` and `all=true` gives a multi-target result with one
failed target (status partial). Docker contexts: two synthetic contexts in a temporary DOCKER_CONFIG
(`build-01`, ssh, and `staging`, tcp + TLS); container listing = `ops.docker_containers(all=True)`. The engine also
serves two images (tags from engine/images-json.json; `docker save` = tests/fixtures/collectors/docker/alpine-mini.tar
with an image title label added, so each has its own config digest = image Id, as the collector verifies; synthetic):
job 5 scans `image:nginx:latest`, job 6 is a host-mode batch (the container `web` and
`image:*`) in which nginx is reused (same image Id) and postgres collected.

Host auto mode (`discover`): the real discovery code with the platform facts patched: a synthetic macOS host
"alice-mbp" (15.1, arm64, no Full Disk Access, Homebrew in /opt/homebrew, the fake engine) and a synthetic Ubuntu
host reached over a fake ssh transport (dpkg + docker; the remote engine probe answers with the fixture listing).
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import socketserver
import sys
import tarfile
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from secmonk import discover as dsc
from secmonk import ops, reports
from secmonk.cli import app as cli_app
from secmonk.collectors import docker_engine, harvest
from secmonk.collectors.process import backend as proc_backend
from secmonk.collectors.process import snapshot as snapfile
from secmonk.collectors.process.model import LaunchItem
from secmonk.collectors.ssh import Transport
from secmonk.db import connect
from secmonk.engine.match import canonical_ids, match_asset
from secmonk.engine.scoring import DEFERRED_TRIAGE, MINOR_TRIAGE
from secmonk.sources.base import SyncOptions, add_affected, add_alias, upsert_vulnerability
from secmonk.web.api import ProcessMonitor
from secmonk.web.data import DataApi
from secmonk.web.jobs import JobRunner

FIX = REPO / "tests/fixtures"
SRC = FIX / "sources"
OUT = REPO / "_design/mock/data.js"
MOCK_DB = "~/.local/share/secmonk/secmonk.db"


def build_root(tmp: Path) -> Path:
    """The shared fixture tree (tests/fixtures/collectors/process/fixture_root.py, also used by the tests)."""
    spec = importlib.util.spec_from_file_location("process_fixture_root", FIX / "collectors/process/fixture_root.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_root(tmp / "root")


def build_mirror(db: Path, files: Path) -> None:
    """Fixture records through the real sources, then hand-added real advisories (see the module docstring)."""
    reg = ops.sources_registry()
    c = connect(db)
    for name, rel in (("epss", "epss/epss_scores-sample.csv"), ("osv", "osv/maven-GHSA-jfh8-c2jp-5v3q.json"),
                      ("osv", "osv/alpine-ALPINE-CVE-2024-3094.json"), ("cvelist", "cvelist/CVE-2021-44228.json"),
                      ("nvd", "nvd/cve-2021-44228.json"), ("euvd", "euvd/exploited-sample.json")):
        f = files / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(SRC / rel, f)
        res, _ = ops.sync_source(c, name, reg[name], SyncOptions(path=f))
        assert res.status == "ok", (name, res)
    upsert_vulnerability(c, "osv", "GO-2022-1059", summary="golang.org/x/text: denial of service via crafted Accept-Language",
                         severity="HIGH", cvss_score=7.5)
    add_affected(c, "osv", "GO-2022-1059", ecosystem="Go", package="golang.org/x/text", range_type="SEMVER",
                 events=[{"introduced": "0"}, {"fixed": "0.3.8"}])
    for cve, intro, fixed, sev, score in (("CVE-2024-6197", "8.6.0", "8.9.0", "MEDIUM", 7.5),
                                          ("CVE-2024-7264", "7.32.0", "8.9.1", "MEDIUM", 6.5)):
        upsert_vulnerability(c, "cvelist", cve, summary=f"curl {cve}", severity=sev, cvss_score=score)
        add_affected(c, "cvelist", cve, vendor="haxx", product="curl", range_type="CVE",
                     events=[{"introduced": intro}, {"fixed": fixed}])
    npm = (("GHSA-35jh-r3h4-6jhm", "CVE-2021-23337", "lodash", "Command Injection in lodash", "HIGH", 7.2,
            [[{"introduced": "0"}, {"fixed": "4.17.21"}]]),
           ("GHSA-xvch-5gv4-984h", "CVE-2021-44906", "minimist", "Prototype Pollution in minimist", "CRITICAL", 9.8,
            [[{"introduced": "0"}, {"fixed": "0.2.4"}], [{"introduced": "1.0.0"}, {"fixed": "1.2.6"}]]),
           ("GHSA-c2qf-rxjj-qqgw", "CVE-2022-25883", "semver", "semver vulnerable to Regular Expression Denial of Service",
            "HIGH", 7.5, [[{"introduced": "0"}, {"fixed": "5.7.2"}], [{"introduced": "6.0.0"}, {"fixed": "6.3.1"}],
                          [{"introduced": "7.0.0"}, {"fixed": "7.5.2"}]]))
    for ghsa, cve, pkg, summary, sev, score, ranges in npm:
        upsert_vulnerability(c, "osv", ghsa, summary=summary, severity=sev, cvss_score=score)
        add_alias(c, "osv", ghsa, cve)
        for events in ranges:
            add_affected(c, "osv", ghsa, ecosystem="npm", package=pkg, purl=f"pkg:npm/{pkg}", range_type="SEMVER",
                         events=events)
    upsert_vulnerability(c, "cvelist", "MOCK-2026-0001", summary="Fictional advisory for the design mock",
                         severity="CRITICAL", cvss_score=9.8)
    add_affected(c, "cvelist", "MOCK-2026-0001", vendor="example", product="exampleupdater", range_type="CVE",
                 events=[{"introduced": "0"}, {"fixed": "2.5.0"}])
    c.commit()
    c.close()


def scan(db: Path, collector: str, target: Path) -> str:
    inv = ops.collect(collector, str(target), {})
    c = connect(db)
    try:
        ops.save_and_match(c, inv)
    finally:
        c.close()
    return inv.asset.id


def run_job(runner: JobRunner, body: dict, status: str = "ok") -> dict:
    job = runner.start(body)
    for _ in range(600):
        j = runner.get(job["id"])
        if j["status"] != "running":
            assert j["status"] == status, j
            return j
        time.sleep(0.05)
    raise SystemExit(f"job did not finish: {job}")


def cli_scan(db: Path, collector: str, target: Path) -> None:
    """A scan through the real CLI (`secmonk scan`): recorded in the run history with origin `cli`."""
    from typer.testing import CliRunner

    res = CliRunner().invoke(cli_app, ["scan", collector, str(target), "--db", str(db), "-q"])
    assert res.exit_code == 0, res.output


ENGINE = FIX / "collectors/docker/engine"


def saved_variant(archive: bytes, title: str) -> tuple[str, bytes]:
    """The fixture `docker save` archive with a label added to its image config: (new image Id, archive). The OCI
    manifest, index.json and manifest.json are rewritten to the new digests, the layer is unchanged."""
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        members = [m for m in tar.getmembers() if m.isfile()]
        files = {m.name: tar.extractfile(m).read() for m in members}
    legacy = json.loads(files["manifest.json"])
    index = json.loads(files["index.json"])
    cfg_name, man_name = legacy[0]["Config"], "blobs/sha256/" + index["manifests"][0]["digest"].removeprefix("sha256:")
    cfg = json.loads(files[cfg_name])
    cfg["config"].setdefault("Labels", {})["org.opencontainers.image.title"] = title
    cfg_b = json.dumps(cfg, separators=(",", ":")).encode()
    cfg_d = hashlib.sha256(cfg_b).hexdigest()
    man = json.loads(files[man_name])
    man["config"].update(digest=f"sha256:{cfg_d}", size=len(cfg_b))
    man_b = json.dumps(man, separators=(",", ":")).encode()
    man_d = hashlib.sha256(man_b).hexdigest()
    index["manifests"][0].update(digest=f"sha256:{man_d}", size=len(man_b))
    legacy[0]["Config"] = f"blobs/sha256/{cfg_d}"
    renamed = {cfg_name: (f"blobs/sha256/{cfg_d}", cfg_b), man_name: (f"blobs/sha256/{man_d}", man_b),
               "index.json": ("index.json", json.dumps(index).encode()),
               "manifest.json": ("manifest.json", json.dumps(legacy).encode())}
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        for m in members:
            name, data = renamed.get(m.name, (m.name, files[m.name]))
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return f"sha256:{cfg_d}", out.getvalue()


def fake_engine(sock: str, rootfs: Path) -> socketserver.BaseServer:
    """Docker Engine API subset on a Unix socket: list, inspect and export of the fixture container `web`."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for rel in ("etc/os-release", "lib/apk/db/installed"):
            tar.add(rootfs / rel, arcname=rel)
    inspect = json.loads((ENGINE / "container-inspect.json").read_text())
    rows = json.loads((ENGINE / "containers-json.json").read_text())
    archive = (FIX / "collectors/docker/alpine-mini.tar").read_bytes()
    images, saved = [], {}
    for im in json.loads((ENGINE / "images-json.json").read_text()):
        if im["RepoTags"]:                       # tagged images get an archive whose config digest is their Id
            iid, saved_tar = saved_variant(archive, im["RepoTags"][0])
            saved[iid] = saved_tar
            im = {**im, "Id": iid}
        images.append(im)

    def image(ref: str) -> dict | None:
        """GET /images/{ref}/...: by tag (name -> name:latest), full Id or Id prefix."""
        for im in images:
            iid = im["Id"]
            if ref in im["RepoTags"] or f"{ref}:latest" in im["RepoTags"] or ref == iid or \
                    (len(ref.removeprefix("sha256:")) >= 4 and iid.removeprefix("sha256:").startswith(ref.removeprefix("sha256:"))):
                return im
        return None
    routes = {"/_ping": b"OK", "/version": (ENGINE / "version.json").read_bytes(),
              "/containers/web/json": json.dumps(inspect).encode(),
              f"/containers/{inspect['Id']}/export": buf.getvalue()}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def address_string(self) -> str:
            return "unix"

        def log_message(self, *a) -> None:
            pass

        def do_GET(self) -> None:
            path, _, query = self.path.partition("?")
            if path == "/containers/json":
                body = json.dumps([r for r in rows if "all=1" in query or r["State"] == "running"]).encode()
                code = 200
            elif path == "/images/json":
                code, body = 200, json.dumps(images).encode()
            elif path.startswith("/images/") and (im := image(unquote(path[len("/images/"):].rsplit("/", 1)[0]))):
                code, body = 200, (saved[im["Id"]] if path.endswith("/get") else json.dumps({**im, "Architecture": "amd64"}).encode())
            else:
                name = path.split("/")[2] if path.startswith("/containers/") else path
                code, body = (200, routes[path]) if path in routes else \
                    (404, json.dumps({"message": f"No such container: {name}"}).encode())
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = socketserver.ThreadingUnixStreamServer(sock, Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def docker_config(cfg: Path) -> None:
    """Two contexts as `docker context create` writes them (meta.json under a sha256 of the name)."""
    for name, host, desc in (("build-01", "ssh://deploy@build-01.example.internal", "CI builder (over ssh)"),
                             ("staging", "tcp://staging.example.internal:2376", "Staging engine (TLS)")):
        d = cfg / "contexts/meta" / hashlib.sha256(name.encode()).hexdigest()
        d.mkdir(parents=True)
        (d / "meta.json").write_text(json.dumps({"Name": name, "Metadata": {"Description": desc},
                                                 "Endpoints": {"docker": {"Host": host}}}))


class FakeSSH(Transport):
    """Answers the one discovery probe (`sh -s`) like an Ubuntu host with dpkg and docker (synthetic output in the
    harvest.detect_script format, as tests/test_discover.py builds it)."""
    name = "fake"

    def stream(self, cmd, timeout=60, stdin=None):
        raise NotImplementedError

    def run(self, cmd, timeout=60, stdin=None):
        p = harvest.DETECT_PREFIX
        lines = [f"{p}kernel@@", "Linux", f"{p}arch@@", "x86_64", f"{p}os-release@@",
                 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nVERSION_ID="24.04"', f"{p}sw_vers@@", f"{p}hostname@@",
                 "build-01", f"{p}machine-id@@", "0123456789abcdef", f"{p}end@@",
                 *(f"{dsc.TOOL_PREFIX}{t}" for t in ("dpkg", "docker"))]
        return 0, ("\n".join(lines) + "\n").encode(), b""


def discover_payloads() -> dict:
    """GET /api/discover for this machine (synthetic macOS facts, the fake engine) and for an ssh Linux host."""
    saved = (dsc._local_os, dsc._local_host, dsc._brew_prefixes, dsc.os, dsc._docker_probe, proc_backend.current_platform)

    class NoFullDiskAccess:                       # the TCC check of the macos candidate, deterministic
        def __getattr__(self, name):
            return getattr(os, name)

        def listdir(self, path):
            raise PermissionError(path)

    try:
        dsc._local_os = lambda: "macos"
        dsc._local_host = lambda os_name: {"kind": "local", "target": None, "name": "alice-mbp", "os": "macos",
                                           "os_version": "15.1", "arch": "arm64"}
        dsc._brew_prefixes = lambda root=None: ["/opt/homebrew"]
        dsc.os = NoFullDiskAccess()
        proc_backend.current_platform = lambda: "darwin"
        local = ops.discover_host(None, {})
        engine = json.loads((ENGINE / "containers-json.json").read_text())
        images = json.loads((ENGINE / "images-json.json").read_text())
        dsc._docker_probe = lambda o, t: {
            "state": "ok", "endpoint": "ssh://deploy@build-01.example.internal", "reason": None,
            "options": ["host=ssh://deploy@build-01.example.internal"],
            "containers": [{"name": c["Names"][0].lstrip("/"), "image": c["Image"], "state": c["State"]}
                           for c in engine if c["State"] == "running"],
            "images": [{"id": i["Id"].removeprefix("sha256:")[:12], "tags": i["RepoTags"]} for i in images if i["RepoTags"]]}
        remote = ops.discover_host("ssh://deploy@build-01.example.internal",
                                   {"transport": FakeSSH(), "identity": "~/.ssh/id_ed25519"})
    finally:
        (dsc._local_os, dsc._local_host, dsc._brew_prefixes, dsc.os, dsc._docker_probe,
         proc_backend.current_platform) = saved
    text = json.dumps({"local": local, "ssh": remote}).replace(str(Path.home()), "/Users/alice")
    return json.loads(text)


def monitor_payloads(tmp: Path, root: Path, db: Path) -> tuple[dict, list]:
    src = FIX / "collectors/process/snapshot.json"
    mon = ProcessMonitor(db_path=db, target=str(src), opts={"root": str(root)})
    snapshot = mon.payload()
    mon.save()                                                # asset process:fixture-mac

    # watch events: a second monitor starts from a baseline in which pid 404 runs zsh (not the Go binary), then
    # one tick sees hello start, syncd replaced on disk, the updater plist re-pointed and a new LaunchAgent
    base = snapfile.load(src)
    next(p for p in base.processes if p.pid == 404).exe = "/bin/zsh"
    snapfile.dump(base, tmp / "base.json")
    later = snapfile.load(src)
    later.launch_items[0].program = "/Users/alice/Downloads/updater-helper"
    later.launch_items.append(LaunchItem("launchd-agent", "com.example.newagent", "/Users/alice/.local/bin/agent",
                                         source="/Users/alice/Library/LaunchAgents/com.example.newagent.plist",
                                         scope="user:alice", run_at_load=True))
    snapfile.dump(later, tmp / "later.json")
    w = ProcessMonitor(db_path=db, target=str(tmp / "base.json"), opts={"root": str(root)})
    w.watch()                                                 # baseline
    (root / "Users/alice/Library/Application Support/Sync/syncd").write_text("#!/bin/sh\n# replaced\nexec sleep 1\n")
    w.target = str(tmp / "later.json")
    return snapshot, w.watch()["events"]


def main() -> None:
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        db = tmp / "mirror.db"
        root = build_root(tmp)
        srv = tmp / "srv"
        runner = JobRunner(db)
        kev = tmp / "files/kev/known_exploited_vulnerabilities.json"
        kev.parent.mkdir(parents=True)
        shutil.copy(SRC / "kev/known_exploited_vulnerabilities.json", kev)
        run_job(runner, {"kind": "sync", "sources": ["kev"], "path": str(kev)})      # job 1, creates the mirror
        build_mirror(db, tmp / "files")
        snapshot, events = monitor_payloads(tmp, root, db)

        shutil.copytree(FIX / "lang/java", srv / "payments-api")
        shutil.copytree(FIX / "lang/javascript/npm-v3", srv / "web-frontend")
        shutil.copytree(FIX / "collectors/docker/alpine-3.20/rootfs", srv / "alpine-rootfs")
        with (srv / "alpine-rootfs/lib/apk/db/installed").open("a") as fh:
            fh.write("P:xz-libs\nV:5.6.0-r0\nA:x86_64\no:xz\n\n")
        shutil.copytree(FIX / "collectors/macos/root", srv / "macbook")
        for collector, target in (("fs", "payments-api"), ("fs", "web-frontend"), ("macos", "macbook")):
            scan(db, collector, srv / target)
        cli_scan(db, "rootfs", srv / "alpine-rootfs")                                   # job 2, from the CLI
        lock = srv / "web-frontend/package-lock.json"
        text = lock.read_text()
        assert text.count('"version": "4.17.20"') == 1
        lock.write_text(text.replace('"version": "4.17.20"', '"version": "4.17.21"'))
        run_job(runner, {"kind": "scan", "collector": "fs", "target": str(srv / "web-frontend")})   # job 3: lodash fixed

        # docker engine: auto-discovered fake socket, two contexts; job 4 = selector over two containers, one fails
        sock = str(tmp / "engine.sock")
        engine = fake_engine(sock, srv / "alpine-rootfs")
        for var in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
            os.environ.pop(var, None)
        os.environ["DOCKER_CONFIG"] = str(tmp / "dockercfg")
        docker_config(tmp / "dockercfg")
        docker_engine.candidate_sockets = lambda opts=None: [sock]
        docker_engine._refuses = lambda path: False
        run_job(runner, {"kind": "scan", "collector": "docker-engine", "target": "web,d*", "options": ["all=true"]},
                status="partial")
        docker = {"contexts": ops.docker_contexts(), "containers": ops.docker_containers(all=True)}
        run_job(runner, {"kind": "scan", "collector": "docker-engine", "target": "image:nginx:latest"})   # job 5
        discovered = discover_payloads()
        by_id = {c["id"]: c for c in discovered["local"]["candidates"]}
        items = [{**{k: by_id["docker"][k] for k in ("id", "collector", "options")}, "target": "web"},    # narrowed
                 {k: by_id["docker-images"][k] for k in ("id", "collector", "target", "options")}]
        run_job(runner, {"kind": "scan", "items": items, "host": None})              # job 6: nginx image reused
        engine.shutdown()
        engine.server_close()

        c = connect(db)
        try:
            assets = reports.asset_rows(c)
            details = {}
            for a in assets:
                stats = match_asset(c, a["id"], min_confidence=0.5)
                details[a["id"]] = {**reports.asset_detail(c, a["id"]), "match_stats": stats}
            # every id the pages can ask for (records, findings, matched advisories) -> canonical id, as the server resolves it
            vulns, vuln_ids = {}, {}
            asked = {r[0] for r in c.execute("SELECT id FROM vulnerability UNION SELECT vuln_id FROM finding")}
            asked |= {a for f in reports.findings(c, include_closed=True, limit=5000) for a in f["advisory_ids"]}
            for vid in sorted(asked):
                canon = canonical_ids(c, vid)[0]
                if canon not in vulns:
                    d = reports.vuln_detail(c, canon, raw=True)
                    if d is None:
                        continue
                    vulns[canon] = d
                vuln_ids[vid] = canon
            index = []
            for eco, pkg in c.execute("SELECT DISTINCT ecosystem, package FROM affected WHERE package IS NOT NULL"):
                index += reports.vuln_search(c, ecosystem=eco, package=pkg, limit=1000)
            for (prod,) in c.execute("SELECT DISTINCT product FROM affected WHERE product IS NOT NULL"):
                index += reports.vuln_search(c, product=prod, limit=1000)
            data_api = DataApi(db)
            overview = reports.overview(c, MOCK_DB)
            sources = data_api.sources()
            sources["db"]["path"] = sources["status"]["db"] = MOCK_DB
            data = {
                "meta": {"version": "0.1.0", "mode": "snapshot", "platform": "darwin", "bind": "http://127.0.0.1:8765",
                         "db": {"path": MOCK_DB, "exists": True},
                         "features": ["processes", "overview", "assets", "findings", "vulns", "sources", "scan", "jobs"],
                         "actions": True},
                "snapshot": snapshot, "events": events,
                "overview": overview, "assets": assets, "asset_details": details,
                "unmatched": reports.unmatched_rows(c),
                "findings": reports.findings(c, include_closed=True, limit=5000),
                "triage": {"minor": sorted(MINOR_TRIAGE), "deferred": sorted(DEFERRED_TRIAGE)},
                "vulns": vulns, "vuln_ids": vuln_ids, "vuln_index": index, "sources": sources,
                "collectors": data_api.collectors(),
                "jobs": [runner.get(j["id"]) for j in runner.list()],
                "docker": docker,
                "discover": discovered,
            }
        finally:
            c.close()
        text = json.dumps(data, indent=1, default=str).replace(sock, "/var/run/docker.sock").replace(str(tmp), "")
    for leak in (str(tmp), str(REPO), str(Path.home())):
        if leak in text:
            raise SystemExit(f"local path leaked into the mock: {leak}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("/* Generated by scripts/design_mock.py from the test fixtures: do not edit by hand. */\n"
                   f"window.SECMONK_MOCK = {text};\n")
    print(f"wrote {OUT.relative_to(REPO)} ({len(text) // 1024} KiB): {len(snapshot['processes'])} processes, "
          f"{len(events)} events, {len(assets)} assets, {len(data['findings'])} findings, {len(vulns)} vulnerabilities, "
          f"{len(data['jobs'])} jobs, {len(docker['containers']['containers'])} containers")


if __name__ == "__main__":
    main()
