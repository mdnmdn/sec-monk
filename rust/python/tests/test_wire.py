"""Protocol tests of the shared server (secmonk-wire/1): framing, caps, cancel, crash and garbage behaviour."""

from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path

import pytest

from secmonk_modules.client import ModuleClient, isolated_env
from secmonk_modules.errors import WireError
from secmonk_modules.wire import MethodTable, ModuleDef, Server

from . import contracts

HELPER = str(Path(__file__).with_name("helper_server.py"))


@pytest.fixture
def server(tmp_path):
    made = []

    def make(*, max_frame: int | None = None, host_max_frame: int = 16 * 1024 * 1024, hello: bool = True):
        env = isolated_env(tmp_path)
        if max_frame:
            env["TEST_MAX_FRAME"] = str(max_frame)
        c = ModuleClient("py-probe", env=env, cmd=[sys.executable, HELPER], host_max_frame=host_max_frame,
                         send_host_hello=hello).start()
        made.append(c)
        return c

    yield make
    for c in made:
        c.close()


def check_frames(c: ModuleClient, reply) -> None:
    for f in reply.frames:
        contracts.check("wire/envelope.schema.json", f)


def test_hello_first_and_valid(server):
    c = server()
    contracts.check("wire/envelope.schema.json", c.hello)
    assert c.hello["role"] == "module" and c.hello["protocol"] == "secmonk-wire/1.0"
    assert c.hello["pid"] == c.proc.pid and c.hello["runtime"] == "python"
    assert c.hello["limits"]["max_frame"] == 65536 * 4
    assert c.hello["provides"]["methods"][0].startswith("t.")


def test_request_before_host_hello_is_a_protocol_error(server):
    c = server(hello=False)
    c.start_request("t.echo", {})
    f = c.recv(10)
    assert f["type"] == "err" and f["id"] is None and f["code"] == "protocol-error"
    assert c.close() == 3


def test_unary_and_envelope(server):
    c = server()
    r = c.request("t.echo", {"value": {"a": [1, 2.5, None, "é"]}}).ok()
    assert r.result == {"value": {"a": [1, 2.5, None, "é"]}}
    check_frames(c, r)


def test_unknown_method_and_invalid_params(server):
    c = server()
    assert c.request("t.nope", {}).error["code"] == "unknown-method"
    r = c.request("t.sleep", {"seconds": "x"})
    assert r.error["code"] == "invalid-params"
    assert c.request("t.sleep", {"seconds": True}).error["code"] == "invalid-params"
    assert c.request("t.sleep", {"seconds": 0.0, "extra": 1}).error["code"] == "invalid-params"
    assert c.request("t.sleep", {}).error["code"] == "invalid-params"
    c.send({"type": "req", "id": 99, "method": "t.echo", "params": [1]})
    assert c.collect(99).error["code"] == "invalid-params"
    assert c.request("t.echo", {}).ok()                       # still serving
    check_frames(c, c.request("t.wire_error", {}))


def test_wire_error_carries_hint_and_data(server):
    c = server()
    e = c.request("t.wire_error", {}).error
    assert (e["code"], e["hint"], e["data"]) == ("unknown-asset", "a hint", {"why": "test"})
    contracts.check("wire/envelope.schema.json", e)


def test_internal_error_has_no_traceback_and_no_secret(server):
    c = server()
    e = c.request("t.boom", {}).error
    assert e["code"] == "internal"
    assert e["error"].startswith("ValueError: bad thing")
    assert "hunter2" not in e["error"] and "token=abc" not in e["error"] and "Traceback" not in e["error"]
    assert any("Traceback" in line or "ValueError" in line for line in c.stderr_lines)   # the detail is in the log


def test_stray_stdout_writes_do_not_corrupt_frames(server):
    c = server()
    r = c.request("t.noisy", {}, timeout=60).ok()
    assert r.result == {"ok": True}
    err = "\n".join(c.stderr_lines)
    assert "stray print to stdout" in err and "raw write to fd 1" in err and "child stdout" in err
    assert c.request("t.echo", {"value": 1}).ok().result == {"value": 1}
    assert not c.stray


def test_logs_are_single_lines_on_stderr(server):
    c = server()
    c.request("t.noisy", {}, timeout=60).ok()
    logs = [x for x in c.stderr_lines if x.startswith("INFO helper:")]
    assert logs == ["INFO helper: line one\\nline two"]


def test_progress_and_notify_log(server):
    c = server()
    r = c.request("t.progress", {}).ok()
    assert r.progress[0]["message"] == "step 1" and r.progress[0]["total"] == 2
    assert r.notifies[0]["method"] == "log"
    contracts.check("wire/notify-log.schema.json", r.notifies[0]["params"])
    assert r.notifies[0]["params"]["request"] == r.id
    check_frames(c, r)


def test_stream_events_end_and_seq(server):
    c = server()
    r = c.request("t.stream", {"n": 5}).ok()
    assert [i["i"] for i in r.items] == [0, 1, 2, 3, 4] and r.seqs == [1, 2, 3, 4, 5]
    assert r.result == {"count": 5}
    check_frames(c, r)


def test_cancel_unary(server):
    c = server()
    rid = c.start_request("t.sleep", {"seconds": 60})
    time.sleep(0.3)
    c.send({"type": "cancel", "id": rid, "reason": "test"})
    t0 = time.monotonic()
    r = c.collect(rid, 10)
    assert r.error["code"] == "cancelled" and time.monotonic() - t0 < 3
    assert c.request("t.echo", {}).ok()                       # the module is still usable


def test_cancel_stream_and_unknown_id(server):
    c = server()
    rid = c.start_request("t.stream", {"n": 1000, "delay": 0.05})
    time.sleep(0.4)
    c.send({"type": "cancel", "id": 424242})                  # unknown: ignored
    c.send({"type": "cancel", "id": rid})
    r = c.collect(rid, 10)
    assert r.error["code"] == "cancelled" and 0 < len(r.items) < 1000


def test_deadline_is_a_timeout(server):
    c = server()
    r = c.request("t.sleep", {"seconds": 30}, deadline_ms=300, timeout=10)
    assert r.error["code"] == "timeout"


def test_max_inflight_busy(server):
    c = server()                                              # the helper module allows one request at a time
    first = c.start_request("t.sleep", {"seconds": 5})
    time.sleep(0.2)
    second = c.start_request("t.echo", {})
    assert c.collect(second, 10).error["code"] == "busy"
    c.send({"type": "cancel", "id": first})
    assert c.collect(first, 10).error["code"] == "cancelled"


class _FinalFrameProbe(io.RawIOBase):
    """A stdout that records, for each final frame (res / end / err), whether its request was still in flight."""

    def __init__(self) -> None:
        self.server: Server | None = None
        self.seen: list[tuple[str, bool]] = []

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:
        frame = json.loads(bytes(data)[4:])
        if frame["type"] in ("res", "end", "err") and self.server is not None:
            self.seen.append((frame["type"], frame["id"] in self.server.inflight))
        return len(data)


def test_inflight_slot_is_free_before_the_final_frame():
    # regression: the slot was freed after the final frame, so a host calling again at once got `busy`
    table = MethodTable()

    @table.unary("t.echo", {})
    def _echo(ctx, p):
        return {}

    @table.stream("t.stream", {})
    def _stream(ctx, p):
        yield {"i": 1}
        return {"count": 1}

    @table.unary("t.fail", {})
    def _fail(ctx, p):
        raise WireError("unknown-asset", "no such asset")

    out = _FinalFrameProbe()
    srv = Server(ModuleDef(name="py-probe", kind="probe", description="t", capabilities=[], methods=table,
                           max_inflight=1), io.BytesIO(), out)
    out.server = srv
    for rid, method in enumerate(["t.echo", "t.stream", "t.fail"], start=1):
        srv._on_req({"type": "req", "id": rid, "method": method, "params": {}})
        for t in srv.threads:
            t.join(5)
    assert out.seen == [("res", False), ("end", False), ("err", False)]


def test_back_to_back_calls_with_max_inflight_one_are_never_busy(server):
    c = server()                                              # the helper module allows one request at a time
    for _ in range(50):
        assert c.request("t.echo", {}).ok()


def test_eof_on_stdin_exits_cleanly_even_with_a_request_in_flight(server):
    c = server()
    c.start_request("t.sleep", {"seconds": 60})
    time.sleep(0.2)
    t0 = time.monotonic()
    assert c.close(timeout=15) == 0
    assert time.monotonic() - t0 < 10


def test_eof_exits_when_idle(server):
    c = server()
    assert c.close() == 0


@pytest.mark.parametrize("raw,why", [
    (b"\x00\x00\x00\x05{bad}", "invalid JSON"),
    (b"\x00\x00\x00\x02\xff\xfe", "invalid UTF-8"),
    (b"\x00\x00\x00\x02[]", "not an object"),
    (b"\x00\x00\x00\x0f" + b'{"type":"bogus"}'[:15], "unknown message type"),
])
def test_garbage_is_a_protocol_error(server, raw, why):
    c = server()
    c.send_raw(raw)
    f = c.recv(10)
    assert f["type"] == "err" and f["id"] is None and f["code"] == "protocol-error", why
    contracts.check("wire/envelope.schema.json", f)
    assert c.close() == 3


def test_oversize_frame_is_refused_without_reading_it(server):
    c = server()
    c.send_raw((64 * 1024 * 1024).to_bytes(4, "big"))         # announces 64 MiB, sends nothing
    f = c.recv(10)
    assert f["code"] == "protocol-error" and "max_frame" in f["error"]
    assert c.close() == 3


def test_truncated_frame_then_eof(server):
    c = server()
    c.send_raw((100).to_bytes(4, "big") + b'{"type"')
    c.proc.stdin.close()
    assert c.proc.wait(10) == 3


def test_duplicate_and_bad_ids(server):
    c = server()
    assert c.request("t.echo", {}).ok()
    c.send({"type": "req", "id": 1, "method": "t.echo", "params": {}})   # id 1 was used
    assert c.recv(10)["code"] == "protocol-error"
    assert c.close() == 3
    c2 = server()
    c2.send({"type": "req", "id": 0, "method": "t.echo"})
    assert c2.recv(10)["code"] == "protocol-error"


def test_result_larger_than_max_frame_is_an_internal_error_and_the_module_survives(server):
    c = server()
    e = c.request("t.big", {"bytes": 2_000_000}).error
    assert e["code"] == "internal" and "max_frame" in e["error"]
    assert c.request("t.echo", {"value": "alive"}).ok().result == {"value": "alive"}


def test_the_smaller_max_frame_wins(server):
    c = server(host_max_frame=65536)
    assert c.request("t.big", {"bytes": 1000}).ok()
    assert c.request("t.big", {"bytes": 70000}).error["code"] == "internal"
    c.send_raw((70000).to_bytes(4, "big") + b"x" * 70000)     # inbound cap is the module's own announcement
    assert c.recv(10) is not None


def test_crash_is_visible_as_eof_and_exit_code(server):
    c = server()
    rid = c.start_request("t.crash", {})
    with pytest.raises(EOFError):
        c.collect(rid, 10)
    assert c.proc.wait(10) == 7


def test_no_forbidden_state_in_the_environment(server):
    c = server()
    r = c.request("t.cwd", {}).ok().result
    assert {"SECMONK_HOME", "SECMONK_CACHE"} <= set(r["env"])  # the host's redirections reach the module
    assert r["stdin"] == 0                                    # fd 0 is the null device, never the frames


def test_protocol_major_mismatch(server):
    c = server(hello=False)
    c.send_hello(protocol="secmonk-wire/2.0")
    f = c.recv(10)
    assert f["code"] == "protocol-error"
    assert c.close() == 3
