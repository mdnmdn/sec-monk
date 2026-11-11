"""Tiny secmonk-wire/1 module for the modhost tests (stdlib only, Python >= 3.9). Synthetic stand-in for the
real modules of rust/python; not a reference implementation.

Usage: python -I echo_module.py <name> [--no-hello] [--claim-extra] [--bad-protocol]

Methods: echo.unary (returns params), echo.stream {n} (n events, end {count}), echo.sleep {seconds}
(honours cancel), echo.hang (ignores cancel), echo.crash (exit 3), echo.log (stderr line + notify log),
echo.print (stray print to stdout), echo.garbage (invalid frame), echo.big {bytes}, echo.pid,
collector.collect / collector.expand_targets / engine.classify / versions.compare (fixed answers).
"""
import json
import os
import struct
import subprocess
import sys
import threading
import time

# Frames go to a private copy of fd 1; fd 1 and sys.stdout point at stderr, so a stray print cannot
# corrupt the stream (the rule of the real server).
FRAME_OUT = os.fdopen(os.dup(1), "wb", buffering=0)
os.dup2(2, 1)
sys.stdout = sys.stderr
FRAME_IN = sys.stdin.buffer

NAME = sys.argv[1] if len(sys.argv) > 1 else "echo"
FLAGS = set(sys.argv[2:])
LOCK = threading.Lock()
CANCELLED = set()
METHODS = ["echo.unary", "echo.stream", "echo.sleep", "echo.hang", "echo.crash", "echo.log", "echo.print",
           "echo.garbage", "echo.big", "echo.pid", "echo.spawn_child", "echo.flood", "collector.collect", "collector.expand_targets",
           "engine.classify", "versions.compare"]


def send(obj):
    body = json.dumps(obj).encode("utf-8")
    with LOCK:
        FRAME_OUT.write(struct.pack(">I", len(body)) + body)


def read():
    head = FRAME_IN.read(4)
    if len(head) < 4:
        return None
    (n,) = struct.unpack(">I", head)
    body = FRAME_IN.read(n)
    if len(body) < n:
        return None
    return json.loads(body.decode("utf-8"))


def res(i, result):
    send({"type": "res", "id": i, "result": result})


def err(i, code, msg):
    send({"type": "err", "id": i, "code": code, "error": msg, "hint": None})


def handle(req):
    i, m, p = req["id"], req["method"], req.get("params") or {}
    if m == "echo.unary":
        res(i, p)
    elif m == "echo.stream":
        n = int(p.get("n", 3))
        for k in range(n):
            send({"type": "event", "id": i, "seq": k, "data": {"k": k}})
        send({"type": "end", "id": i, "result": {"count": n}})
    elif m == "echo.sleep":
        end = time.time() + float(p.get("seconds", 1))
        while time.time() < end:
            if i in CANCELLED:
                err(i, "cancelled", "request %d cancelled" % i)
                return
            send({"type": "progress", "id": i, "message": "sleeping", "done": 1, "total": None, "unit": None})
            time.sleep(0.02)
        res(i, {"slept": p.get("seconds", 1)})
    elif m == "echo.hang":
        time.sleep(3600)
    elif m == "echo.crash":
        os._exit(3)
    elif m == "echo.log":
        sys.stderr.write("stderr line https://user:pw@example.invalid/x?token=1\n")
        sys.stderr.flush()
        send({"type": "notify", "method": "log", "params": {"level": "info", "message": "hello log", "request": i}})
        res(i, {"ok": True})
    elif m == "echo.print":
        print("stray print that must not reach the frame channel")
        res(i, {"printed": True})
    elif m == "echo.garbage":
        with LOCK:
            FRAME_OUT.write(struct.pack(">I", 5) + b"\xff\xfe{]x")
    elif m == "echo.big":
        res(i, {"data": "x" * int(p.get("bytes", 1000))})
    elif m == "echo.spawn_child":
        # a grandchild (like ssh/kubectl under a collector) that outlives a plain kill of this process
        child = subprocess.Popen(["sleep", "300"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        res(i, {"child_pid": child.pid})
    elif m == "echo.flood":
        for k in range(int(p.get("n", 100))):
            send({"type": "event", "id": i, "seq": k, "data": {"k": k}})
        time.sleep(3600)
    elif m == "echo.pid":
        res(i, {"pid": os.getpid()})
    elif m == "collector.expand_targets":
        res(i, {"targets": [p.get("target")]})
    elif m == "collector.collect":
        asset = {"id": "dir:/x", "type": "directory", "name": "x", "os_name": None, "os_version": None,
                 "platform": None, "meta": {}}
        send({"type": "event", "id": i, "seq": 0, "data": {"kind": "asset", "schema": "secmonk-inventory/1",
                                                           "collector": p["collector"], "classified": False,
                                                           "asset": asset}})
        comps = [{"name": "c%d" % k, "version": "1.0", "category": "library", "purl": None, "cpe": None,
                  "vendor": None, "ecosystem": None, "source_path": None, "meta": {}} for k in range(3)]
        send({"type": "event", "id": i, "seq": 1, "data": {"kind": "components", "components": comps}})
        send({"type": "event", "id": i, "seq": 2, "data": {"kind": "warning", "message": "w1"}})
        send({"type": "end", "id": i, "result": {"partial": False, "partial_reason": None, "components": 3,
                                                 "warnings": 1}})
    elif m == "engine.classify":
        res(i, {"components": p["components"]})
    elif m == "versions.compare":
        a, b = p["a"], p["b"]
        res(i, {"result": (a > b) - (a < b)})
    else:
        err(i, "unknown-method", "unknown method %r" % m)


def main():
    if "--no-hello" in FLAGS:
        time.sleep(3600)
    methods = METHODS + (["extra.method"] if "--claim-extra" in FLAGS else [])
    send({"type": "hello", "protocol": "secmonk-wire/9.0" if "--bad-protocol" in FLAGS else "secmonk-wire/1.0",
          "role": "module", "name": NAME, "version": "0.0.1", "runtime": "python",
          "runtime_version": sys.version.split()[0], "pid": os.getpid(), "codecs": ["json"],
          "limits": {"max_frame": 16777216, "max_inflight": 8},
          "provides": {"collectors": [{"name": "echo-fs", "description": "test collector"}], "methods": methods},
          "capabilities": []})
    host = read()
    if not host or host.get("type") != "hello":
        sys.exit(2)
    while True:
        msg = read()
        if msg is None:
            return  # stdin EOF: the host is gone
        t = msg.get("type")
        if t == "req":
            threading.Thread(target=handle, args=(msg,), daemon=True).start()
        elif t == "cancel":
            CANCELLED.add(msg["id"])


if __name__ == "__main__":
    main()
