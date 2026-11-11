"""Conformance: every call of every catalog method has contract-valid params, items, end and result (or a contract-valid
error). Cases are the golden cases (scripts/golden.py) plus a few that cannot be recorded (live machine, no engine)."""

from __future__ import annotations

import pytest

from scripts import golden

from . import contracts


@pytest.fixture(scope="module")
def runner():
    r = golden.Runner()
    yield r
    r.close()


def validate_reply(method: str, params: dict, reply, *, check_params: bool = True) -> None:
    spec = contracts.catalog()[method]
    if check_params:
        contracts.check(spec["params"], params)
    for f in reply.frames:
        contracts.check("wire/envelope.schema.json", f)
    if reply.error is not None:
        assert reply.error["code"] in __import__("secmonk_modules.errors", fromlist=["CODES"]).CODES
        assert "Traceback" not in reply.error["error"]
        return
    if spec["call"] == "stream":
        assert reply.seqs == list(range(1, len(reply.items) + 1))
        for it in reply.items:
            contracts.check(spec["result"], it)
        contracts.check(spec["end"], reply.result)
    else:
        contracts.check(spec["result"], reply.result)


CASES = golden.CASES


@pytest.mark.parametrize("case", CASES, ids=[golden.case_file(c) for c in CASES])
def test_case_conforms(runner, case):
    params, _, reply = runner.run(case)
    expect_refused = case.id in ("unknown-collector", "unknown-asset", "unknown", "no-filter")
    validate_reply(case.method, params, reply, check_params=not expect_refused)
    assert (reply.error is not None) == expect_refused, reply.error


def test_collect_item_shapes(runner):
    """Chunks are within the contract (≤ 1000 components), the asset is unclassified, the end counts match."""
    c = next(c for c in CASES if c.id == "fs-dotnet")
    _, _, r = runner.run(c)
    kinds = [i["kind"] for i in r.items]
    assert kinds[0] == "asset" and r.items[0]["classified"] is False
    n = sum(len(i["components"]) for i in r.items if i["kind"] == "components")
    assert n == r.result["components"] == 336
    assert all(len(i["components"]) <= 1000 for i in r.items if i["kind"] == "components")


def test_collect_chunks_large_inventories(runner, tmp_path):
    """A tree with more than 1000 components streams in chunks of 1000."""
    import json

    deps = {f"pkg{i}": {"version": "1.0.0"} for i in range(2300)}
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 1, "dependencies": deps}))
    (tmp_path / "package.json").write_text('{"name":"big","version":"1.0.0"}')
    c = runner.client(golden.CASES[0])
    r = c.request("collector.collect", {"collector": "fs", "target": str(tmp_path), "options": []}).ok()
    sizes = [len(i["components"]) for i in r.items if i["kind"] == "components"]
    assert sizes == [1000, 1000, 300] and r.result["components"] == 2300
    for i in r.items:
        contracts.check("inventory/collect-item.schema.json", i)


# ---- methods that cannot be golden cases ------------------------------------------------------------------------

def test_live_or_unreachable_methods(runner):
    probe = runner.client(CASES[0])
    for method, params, codes in [
        ("docker.containers", {"host": "tcp://127.0.0.1:1", "options": ["timeout=1"]}, {"engine-unreachable"}),
        ("docker.containers", {"options": ["bogus"]}, {"invalid-params"}),
        ("discover.host", {"target": "k8s://no-such-context", "options": []}, {"host-unreachable", "collect-error"}),
        ("discover.host", {"options": ["bogus"]}, {"invalid-params"}),
    ]:
        r = probe.request(method, params, timeout=120)
        validate_reply(method, params, r, check_params=False)
        assert r.error and r.error["code"] in codes, (method, r.error)
    # docker.image_check: nothing is reachable -> a result with `error`, never an err
    params = {"target": "image:sha256:" + "0" * 64, "options": ["host=tcp://127.0.0.1:1", "timeout=1"]}
    r = probe.request("docker.image_check", params, timeout=120).ok()
    validate_reply("docker.image_check", params, r)
    assert r.result["asset_id"] == "image:@sha256:" + "0" * 64 and r.result["error"] and r.result["meta"] is None
    r = probe.request("docker.image_check", {"target": "alpine:3", "options": []}).ok()
    assert r.result["asset_id"] is None


def test_discover_local_host_is_contract_valid(runner):
    """This machine, read-only commands only (an isolated HOME: no ssh, kube or docker configuration)."""
    probe = runner.client(CASES[0])
    r = probe.request("discover.host", {"options": []}, timeout=180)
    validate_reply("discover.host", {"options": []}, r)
    assert r.error is None and r.result["host"]["kind"] == "local"


def test_source_ack_and_export(runner):
    kev = next(c for c in CASES if c.method == "source.sync" and c.id == "kev")
    from secmonk_modules.client import ModuleClient

    cli = ModuleClient("py-sources", env=runner.env, settings={"module_dir": str(runner.data_dir / "ack")}).start()
    try:
        params = golden.expand(kev.params, runner.roots)
        r = cli.request("source.sync", params).ok()
        last = r.result["last_seq"]
        validate_reply("source.sync", params, r)
        ack = {"source": "kev", "through_seq": last}
        a = cli.request("source.ack", ack)
        validate_reply("source.ack", ack, a)
        assert a.result == {}
        exp = {"source": "kev", "through_seq": 0}
        e = cli.request("source.export", exp)
        validate_reply("source.export", exp, e)
        assert e.result["ops"] == sum(len(i["ops"]) for i in e.items) > 0
        bad = cli.request("source.ack", {"source": "nope", "through_seq": 1})
        assert bad.error["code"] == "unknown-source"
    finally:
        cli.close()


def test_every_catalog_method_is_exercised(runner):
    used = {c.method for c in CASES} | {"docker.containers", "docker.image_check", "discover.host", "source.ack",
                                        "source.export"}
    assert used == set(contracts.catalog())
