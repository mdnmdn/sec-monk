"""`secmonk-process-snapshot/1`: the JSON form of a `Snapshot`.

A snapshot file is untrusted input (it may come from another machine): every field is type-checked,
unknown keys are ignored, sizes are capped, and command lines are re-redacted on load.

    {
      "schema": "secmonk-process-snapshot/1",
      "platform": "darwin", "host": "mbp", "taken_at": "2026-11-07T10:00:00+00:00",
      "os": {"name": "macOS", "version": "14.5", "build": "23F79"},
      "processes": [{"pid": 1, "ppid": 0, "uid": 0, "user": "root", "exe": "/sbin/launchd",
                     "started": "...", "args": ["/sbin/launchd"], "label": null}],
      "launch_items": [{"mechanism": "launchd-daemon", "label": "com.example.d", "program": "/usr/local/bin/d",
                        "args": [], "source": "/Library/LaunchDaemons/com.example.d.plist", "scope": "system",
                        "run_at_load": true, "keep_alive": true, "disabled": null}],
      "executables": {"/usr/local/bin/d": {"sha256": "...", "signature": {...}, "quarantine": {...}}}
    }
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..base import redact_command, strip_url_secrets
from .model import LaunchItem, ProcessRecord, Snapshot

SCHEMA = "secmonk-process-snapshot/1"
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_PROCESSES = 100_000
MAX_ARGS = 64


def _str(v: Any) -> str | None:
    return v if isinstance(v, str) and v else None


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _bool(v: Any) -> bool | None:
    return v if isinstance(v, bool) else None


def _args(v: Any) -> list[str]:
    if not isinstance(v, list):
        return []
    return list(redact_command([a for a in v[:MAX_ARGS] if isinstance(a, str)]) or [])


# --------------------------------------------------------------------------- executable facts
# Facts arrive from another machine: only known keys survive, each with its type checked, and every URL is
# stripped of credentials / query again (a pre-signed download URL is a secret).

def _url(v: Any) -> str | None:
    return strip_url_secrets(v) if isinstance(v, str) and v else None


def _scalars(d: Any, spec: dict[str, type | tuple[type, ...]]) -> dict[str, Any]:
    if not isinstance(d, dict):
        return {}
    out: dict[str, Any] = {}
    for k, t in spec.items():
        v = d.get(k)
        if isinstance(v, t) and not (isinstance(v, bool) and t is int):
            out[k] = v[:4096] if isinstance(v, str) else v
    return out


_SIG = {"signed": bool, "adhoc": bool, "identifier": str, "team_id": str, "timestamp": str, "hardened_runtime": bool,
        "apple": bool, "mac_app_store": bool, "developer_id": bool, "verified": bool, "error": str, "unknown": str}
_QUAR = {"raw_flags": str, "time": str, "agent": str, "event_id": str, "user_approved": bool, "on": str}
_EVENT = {"time": str, "agent_bundle_id": str, "agent": str, "sender": str}
_IDENT = {"name": str, "version": str, "category": str, "purl": str, "bundle_id": str, "vendor_hint": str,
          "product_hint": str, "file_version": str, "company": str, "os": bool}
_TOP = {"exists": bool, "size": int, "mtime": str, "created": str, "owner_uid": int, "world_writable": bool,
        "sha256": str}


def clean_facts(f: dict[str, Any]) -> dict[str, Any]:
    out = _scalars(f, _TOP)
    raw_sig = f.get("signature") if isinstance(f.get("signature"), dict) else {}
    sig = _scalars(raw_sig, _SIG)
    for k, cap in (("authority", 8), ("flags", 16)):
        if isinstance(raw_sig.get(k), list):
            sig[k] = [a for a in raw_sig[k][:cap] if isinstance(a, str)]
    if sig:
        out["signature"] = sig
    q = f.get("quarantine")
    if isinstance(q, dict):
        qc = _scalars(q, _QUAR)
        if isinstance(q.get("event"), dict):
            ev = _scalars(q["event"], _EVENT)
            ev.update({k: u for k in ("data_url", "origin_url") if (u := _url(q["event"].get(k)))})
            if ev:
                qc["event"] = ev
        if qc:
            out["quarantine"] = qc
    wf = f.get("where_froms")
    if isinstance(wf, list):
        urls = [u for u in (_url(x) for x in wf[:4]) if u]
        if urls:
            out["where_froms"] = urls
    gk = _scalars(f.get("gatekeeper"), {"accepted": bool, "source": str})
    if gk:
        out["gatekeeper"] = gk
    ident = _scalars(f.get("identity"), _IDENT)
    if isinstance(ident.get("name"), str):
        out["identity"] = ident
    return out


def to_dict(s: Snapshot) -> dict[str, Any]:
    return {"schema": SCHEMA, **asdict(s)}


def dump(s: Snapshot, path: str | Path) -> None:
    Path(path).write_text(json.dumps(to_dict(s), indent=2, default=str))


def from_dict(d: dict[str, Any]) -> Snapshot:
    if not isinstance(d, dict):
        raise ValueError("process snapshot: top level is not an object")  # noqa: TRY004 (COLLECT_ERRORS)
    if d.get("schema") != SCHEMA:
        raise ValueError(f"process snapshot: schema {d.get('schema')!r}, expected {SCHEMA!r}")
    procs: list[ProcessRecord] = []
    raw_procs = d.get("processes")
    if not isinstance(raw_procs, list):
        raise ValueError("process snapshot: 'processes' must be a list")  # noqa: TRY004
    for p in raw_procs[:MAX_PROCESSES]:
        if not isinstance(p, dict) or _int(p.get("pid")) is None:
            continue
        procs.append(ProcessRecord(
            pid=p["pid"], ppid=_int(p.get("ppid")) or 0, exe=_str(p.get("exe")), uid=_int(p.get("uid")),
            user=_str(p.get("user")), started=_str(p.get("started")), args=_args(p.get("args")),
            name=_str(p.get("name")), label=_str(p.get("label"))))
    items: list[LaunchItem] = []
    for i in d.get("launch_items") or []:
        if not isinstance(i, dict) or not _str(i.get("label")) or not _str(i.get("mechanism")):
            continue
        items.append(LaunchItem(
            mechanism=i["mechanism"], label=i["label"], program=_str(i.get("program")), args=_args(i.get("args")),
            source=_str(i.get("source")), scope=_str(i.get("scope")), run_at_load=_bool(i.get("run_at_load")),
            keep_alive=_bool(i.get("keep_alive")), disabled=_bool(i.get("disabled")),
            meta=i["meta"] if isinstance(i.get("meta"), dict) else {}))
    exes = d.get("executables") if isinstance(d.get("executables"), dict) else {}
    return Snapshot(
        platform=_str(d.get("platform")) or "unknown", host=_str(d.get("host")) or "unknown",
        taken_at=_str(d.get("taken_at")) or "", processes=procs, launch_items=items,
        os=d["os"] if isinstance(d.get("os"), dict) else {},
        executables={k: clean_facts(v) for k, v in list(exes.items())[:MAX_PROCESSES]
                     if isinstance(k, str) and isinstance(v, dict)},
        warnings=[w for w in d.get("warnings") or [] if isinstance(w, str)])


def load(path: str | Path) -> Snapshot:
    p = Path(path)
    if p.stat().st_size > MAX_SNAPSHOT_BYTES:
        raise ValueError(f"{p}: process snapshot larger than {MAX_SNAPSHOT_BYTES} bytes")
    return from_dict(json.loads(p.read_text()))
