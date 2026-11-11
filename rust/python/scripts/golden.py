"""Golden cases: run the modules on the repo fixtures and record / compare normalized outputs in rust/golden/.

    uv run python scripts/golden.py            # compare with the stored goldens (exit 1 on a difference)
    uv run python scripts/golden.py --update   # rewrite them (review the diff!)

Layout: rust/golden/<method>/<case>.params.json (placeholders `<fixtures>`, `<repo>`) and `<case>.out.json`:
`{"result": ...}` unary, `{"items"|..., "end": ...}` stream (merged, see rust/golden/normalize.json), `{"error":
{code, error}}` for a refused call. Cases that need a database use the standard store of tests/dbfactory.py.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
GOLDEN = ROOT.parent / "golden"
sys.path.insert(0, str(GOLDEN))

from normalize import dumps, normalize

from secmonk_modules.client import ModuleClient, Reply, isolated_env
from tests import dbfactory

FX = dbfactory.FIX
REPO = dbfactory.REPO
LANG = "<fixtures>/lang"
SRC = "<fixtures>/sources"
COL = "<fixtures>/collectors"


@dataclass
class Case:
    id: str
    module: str
    method: str
    params: dict[str, Any]
    options: dict[str, Any] = field(default_factory=dict)      # module settings


def collect(cid: str, collector: str, target: str | None, *options: str) -> Case:
    return Case(cid, "py-probe", "collector.collect",
                {"collector": collector, "target": target, "options": list(options)})


def sync_case(cid: str, source: str, path: str, **opts: Any) -> Case:
    o = {"path": path, "ecosystems": [], "ids": [], "since": None, "full": False, "limit": None, **opts}
    return Case(cid, "py-sources", "source.sync", {"source": source, "options": o})


def match_params(**kw: Any) -> dict[str, Any]:
    return {"min_confidence": 0.5, "view_limit": 50, **kw}


STD = "dir:/srv/payments-api"
INV_LOG4J = {"schema": "secmonk-inventory/1", "classified": False, "collector": "fs", "warnings": [], "partial": False,
             "partial_reason": None, "asset": {"id": "dir:/srv/scratch", "type": "directory", "name": "scratch",
                                               "meta": {}},
             "components": [{"name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "category": "library",
                             "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "ecosystem": "Maven",
                             "meta": {}},
                            {"name": "left-pad", "version": "1.3.0", "category": "library",
                             "purl": "pkg:npm/left-pad@1.3.0", "meta": {}}]}

CASES: list[Case] = [
    # ---- py-probe (fixture trees only: nothing of the machine running the test is read)
    collect("fs-npm-v1", "fs", f"{LANG}/javascript/npm-v1"),
    collect("fs-npm-v3", "fs", f"{LANG}/javascript/npm-v3"),
    collect("fs-pnpm-v9", "fs", f"{LANG}/javascript/pnpm-v9"),
    collect("fs-yarn-v1", "fs", f"{LANG}/javascript/yarn-v1"),
    collect("fs-python-poetry", "fs", f"{LANG}/python/poetry"),
    collect("fs-python-requirements", "fs", f"{LANG}/python/requirements"),
    collect("fs-go-binaries", "fs", f"{LANG}/go", "binaries=true"),
    collect("fs-java", "fs", f"{LANG}/java"),
    collect("fs-dotnet", "fs", f"{LANG}/dotnet"),
    collect("fs-php-composer2", "fs", f"{LANG}/php/composer2"),
    collect("rootfs-alpine-3.20", "rootfs", f"{COL}/docker/alpine-3.20/rootfs"),
    collect("rootfs-debian-12", "rootfs", f"{COL}/docker/debian-12/rootfs"),
    collect("sbom-cyclonedx", "sbom", "<fixtures>/sbom/synthetic.cdx.json"),
    collect("sbom-spdx", "sbom", "<fixtures>/sbom/synthetic.spdx.json"),
    collect("windows-osquery", "windows", None, "osquery=<fixtures>/collectors/windows/osquery-win11.json"),
    collect("windows-inventory", "windows", "<fixtures>/collectors/windows/inventory-win11.json"),
    collect("homebrew-prefix", "homebrew", f"{COL}/homebrew/prefix"),
    Case("fs-dir", "py-probe", "collector.expand_targets",
         {"collector": "fs", "target": f"{LANG}/go", "options": []}),
    Case("process-snapshot-file", "py-probe", "process.snapshot",
         {"collector": "process", "target": f"{COL}/process/snapshot.json", "options": []}),
    Case("none", "py-probe", "docker.contexts", {}),
    Case("none", "py-probe", "k8s.kubeconfigs", {}),
    Case("unknown-collector", "py-probe", "collector.expand_targets",
         {"collector": "nope", "target": None, "options": []}),
    # ---- py-sources (each on a fresh staging database)
    sync_case("kev", "kev", f"{SRC}/kev/known_exploited_vulnerabilities.json"),
    sync_case("epss", "epss", f"{SRC}/epss/epss_scores-sample.csv"),
    sync_case("osv-zip", "osv", f"{SRC}/osv/sample-all.zip"),
    sync_case("cvelist-record", "cvelist", f"{SRC}/cvelist/CVE-2021-44228.json"),
    sync_case("nvd", "nvd", f"{SRC}/nvd/cve-2021-44228.json"),
    sync_case("euvd", "euvd", f"{SRC}/euvd/exploited-sample.json"),
    sync_case("msrc", "msrc", f"{SRC}/msrc/cvrf-2024-Aug.synthetic.json"),
    sync_case("debian-tracker", "debian-tracker", f"{SRC}/debian-tracker/repo"),
    sync_case("kev-missing-file", "kev", "<fixtures>/sources/kev/absent.json"),
    # ---- py-engine (standard store)
    Case("log4j", "py-engine", "engine.classify",
         {"components": [c for c in INV_LOG4J["components"]] + [
             {"name": "Visual Studio Code", "version": "1.95.0", "category": "application", "meta": {}}]}),
    Case("persisted", "py-engine", "engine.match", match_params(mode="persisted", asset_id=STD)),
    Case("persisted-high-confidence", "py-engine", "engine.match",
         match_params(mode="persisted", asset_id=STD, min_confidence=1.0, view_limit=0)),
    Case("ephemeral", "py-engine", "engine.match", match_params(mode="ephemeral", inventory=INV_LOG4J)),
    Case("unknown-asset", "py-engine", "engine.match", match_params(mode="persisted", asset_id="dir:/nope")),
    Case("semver", "py-engine", "versions.compare", {"a": "1.2.0", "b": "1.10.0", "scheme": "semver"}),
    Case("debian", "py-engine", "versions.compare", {"a": "1:2.0-1", "b": "2.0-1~bpo1", "scheme": "deb"}),
    Case("pep440", "py-engine", "versions.compare", {"a": "1.0rc1", "b": "1.0", "scheme": "pypi"}),
    Case("range-hit", "py-engine", "versions.in_range",
         {"version": "2.14.1", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}], "scheme": "maven"}),
    Case("range-miss", "py-engine", "versions.in_range",
         {"version": "2.15.0", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}], "scheme": "maven"}),
    Case("first-fixed", "py-engine", "versions.first_fixed",
         {"version": "2.14.1", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}, {"fixed": "2.16.0"}],
          "scheme": "maven"}),
    Case("debian12", "py-engine", "versions.scheme", {"ecosystem": "Debian:12"}),
    Case("none", "py-engine", "versions.scheme", {"ecosystem": None}),
    Case("kev-prod", "py-engine", "scoring.priority",
         {"cvss": 9.8, "epss": 0.9, "kev": True, "asset_meta": {"env": "prod"}, "triage": None, "severity": "CRITICAL"}),
    Case("minor-triage", "py-engine", "scoring.priority",
         {"cvss": 7.5, "epss": 0.01, "kev": False, "asset_meta": None, "triage": "unimportant", "severity": None}),
    Case("standard", "py-engine", "reports.overview", {}),
    Case("standard", "py-engine", "reports.assets", {}),
    Case("standard", "py-engine", "reports.asset_detail", {"id": STD}),
    Case("unknown", "py-engine", "reports.asset_detail", {"id": "dir:/nope"}),
    Case("standard", "py-engine", "reports.unmatched", {}),
    Case("open", "py-engine", "reports.findings", {"limit": 50}),
    Case("p1-fixable", "py-engine", "reports.findings", {"limit": 50, "priority": "P1", "fixable": True}),
    Case("cve", "py-engine", "reports.vuln_detail", {"id": "CVE-2021-44228"}),
    Case("cve-raw", "py-engine", "reports.vuln_detail", {"id": "GHSA-jfh8-c2jp-5v3q", "raw": True}),
    Case("unknown", "py-engine", "reports.vuln_detail", {"id": "CVE-1999-0000"}),
    Case("package", "py-engine", "reports.vuln_search",
         {"package": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven", "version": "2.14.1", "limit": 10}),
    Case("no-filter", "py-engine", "reports.vuln_search", {"limit": 10}),
    Case("standard", "py-engine", "reports.status", {}),
    Case("with-vulns", "py-engine", "reports.sbom", {"asset_id": STD, "with_vulns": True}),
    # ---- py-procmon (a snapshot file target: nothing of this machine is read)
    Case("snapshot-file", "py-procmon", "procmon.payload", {"refresh": True},
         {"process": {"target": f"{COL}/process/snapshot.json", "options": []}}),
    Case("snapshot-file", "py-procmon", "procmon.watch", {},
         {"process": {"target": f"{COL}/process/snapshot.json", "options": []}}),
    Case("snapshot-file", "py-procmon", "procmon.inventory", {},
         {"process": {"target": f"{COL}/process/snapshot.json", "options": []}}),
]


def case_file(c: Case) -> str:
    return f"{c.method}/{c.id}"


def expand(v: Any, roots: dict[str, str]) -> Any:
    if isinstance(v, str):
        return v.replace("<fixtures>", roots["fixtures"]).replace("<repo>", roots["repo"])
    if isinstance(v, list):
        return [expand(x, roots) for x in v]
    if isinstance(v, dict):
        return {k: expand(x, roots) for k, x in v.items()}
    return v


class Runner:
    """Owns a throw-away data_dir, the standard store and the module processes."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="secmonk-golden-")
        self.data_dir = Path(self._tmp.name).resolve()
        self.roots = {"data_dir": str(self.data_dir), "fixtures": str(FX), "repo": str(REPO)}
        self.env = isolated_env(self.data_dir)
        self.grant = dbfactory.make_store(self.data_dir / "db")
        self.clients: dict[tuple, ModuleClient] = {}
        self.stack = contextlib.ExitStack()
        self.n = 0

    def close(self) -> None:
        self.stack.close()
        self._tmp.cleanup()

    def client(self, c: Case) -> ModuleClient:
        if c.module == "py-sources":                                   # fresh staging per case
            self.n += 1
            mc = ModuleClient(c.module, env=self.env, settings={"module_dir": str(self.data_dir / f"src{self.n}")})
            return self.stack.enter_context(mc)
        key = (c.module, json.dumps(c.options, sort_keys=True))
        if key not in self.clients:
            grants = {"db_read": self.grant} if c.module in ("py-engine", "py-procmon") else {}
            settings = expand(c.options, self.roots)
            self.clients[key] = self.stack.enter_context(
                ModuleClient(c.module, env=self.env, grants=grants, settings=settings))
        return self.clients[key]

    def run(self, c: Case) -> tuple[dict[str, Any], dict[str, Any], Reply]:
        params = expand(c.params, self.roots)
        r = self.client(c).request(c.method, params, timeout=300)
        return params, shape(c.method, r), r

    def out(self, c: Case) -> tuple[dict, dict]:
        """(params as stored, normalized out)."""
        params, raw, _ = self.run(c)
        return normalize(params, self.roots), normalize(raw, self.roots)


def shape(method: str, r: Reply) -> dict[str, Any]:
    """A reply as a golden out document (see rust/golden/normalize.json "stream")."""
    if r.error is not None:
        return {"error": {"code": r.error["code"], "error": r.error["error"]}}
    if method == "collector.collect":
        return {"asset": r.items[0]["asset"],
                "components": [c for i in r.items if i["kind"] == "components" for c in i["components"]],
                "warnings": [i["message"] for i in r.items if i["kind"] == "warning"], "end": r.result}
    if method in ("source.sync", "source.export"):
        return {"ops": [o for i in r.items for o in i["ops"]], "end": {**r.result, "batches": len(r.items)}}
    return {"result": r.result}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--update", action="store_true")
    ap.add_argument("--only", help="substring of method/case")
    args = ap.parse_args()
    runner, bad = Runner(), 0
    try:
        for c in CASES:
            name = case_file(c)
            if args.only and args.only not in name:
                continue
            params, out = runner.out(c)
            pf, of = GOLDEN / f"{name}.params.json", GOLDEN / f"{name}.out.json"
            if args.update:
                of.parent.mkdir(parents=True, exist_ok=True)
                pf.write_text(dumps(params))
                of.write_text(dumps(out))
                print("recorded", name)
            elif not of.exists() or of.read_text() != dumps(out):
                bad += 1
                print("DIFFERS ", name)
    finally:
        runner.close()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
