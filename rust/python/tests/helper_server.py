"""A test-only module served with the real protocol server (run as a script by tests/test_wire.py)."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time

from secmonk_modules.errors import WireError
from secmonk_modules.wire import MethodTable, ModuleDef, claim_stdio, run_stdio

T = MethodTable()


@T.unary("t.echo", {"value?": object})
def echo(ctx, p):
    return {"value": p.get("value")}


@T.unary("t.noisy", {})
def noisy(ctx, p):
    print("stray print to stdout")
    sys.stdout.write("another stray write\n")
    os.write(1, b"raw write to fd 1\n")
    subprocess.run([sys.executable, "-c", "import sys; print('child stdout'); sys.stdin.read()"], check=False,
                   timeout=20)      # a child that inherited fd 0 / fd 1 must neither read frames nor write to them
    logging.getLogger("helper").info("line one\nline two")
    return {"ok": True}


@T.unary("t.sleep", {"seconds": float})
def sleep(ctx, p):
    end = time.monotonic() + p["seconds"]
    while time.monotonic() < end:
        ctx.check()
        time.sleep(0.01)
    return {"slept": True}


@T.stream("t.stream", {"n": int, "delay?": float})
def stream(ctx, p):
    for i in range(p["n"]):
        time.sleep(p.get("delay", 0))
        yield {"i": i}
    return {"count": p["n"]}


@T.unary("t.big", {"bytes": int})
def big(ctx, p):
    return {"blob": "x" * p["bytes"]}


@T.unary("t.boom", {})
def boom(ctx, p):
    raise ValueError("bad thing at https://user:hunter2@example.invalid/path?token=abc")


@T.unary("t.wire_error", {})
def wire_error(ctx, p):
    raise WireError("unknown-asset", "unknown asset 'x'", "a hint", {"why": "test"})


@T.unary("t.crash", {})
def crash(ctx, p):
    os._exit(7)


@T.unary("t.progress", {})
def progress(ctx, p):
    ctx.progress("step 1", done=1, total=2, unit="steps")
    ctx.log("info", "hello from the request")
    return {}


@T.unary("t.cwd", {})
def cwd(ctx, p):
    return {"env": sorted(k for k in os.environ if k.startswith("SECMONK")), "stdin": os.fstat(0).st_size}


def main() -> int:
    claim_stdio()
    mod = ModuleDef(name="py-probe", kind="probe", capabilities=["read-target"], methods=T, max_inflight=1,
                    description="test module")
    return run_stdio(mod, max_frame=int(os.environ.get("TEST_MAX_FRAME", str(65536 * 4))))


if __name__ == "__main__":
    sys.exit(main())
