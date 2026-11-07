"""Process monitor views for the CLI (`secmonk procs`): process tree rows joined with findings, and the
`--watch` differ that reports new executables and new launch items between snapshots.

Kept out of cli.py so it can be tested without Typer. See _docs/features/process-monitor.md.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

from .collectors.process.backend import Inspector
from .collectors.process.collector import ProcessView, build_views
from .collectors.process.model import LaunchItem, Snapshot
from .engine import queries

PRIORITY_ORDER = ("P1", "P2", "P3", "P4")


# --------------------------------------------------------------------------- findings join

def findings_by_component(conn: sqlite3.Connection, asset_id: str) -> dict[tuple[str, str | None], list[dict]]:
    """(component name, version) -> open findings (priority order)."""
    out: dict[tuple[str, str | None], list[dict]] = {}
    for r in queries.findings(conn, asset=asset_id, limit=100_000):
        out.setdefault((r["name"], r["version"]), []).append(
            {"vuln_id": r["vuln_id"], "priority": r["priority"], "kev": bool(r["kev"]),
             "fixed_version": r["fixed_version"], "cvss_score": r["cvss_score"]})
    return out


def _view_findings(v: ProcessView, fmap: dict[tuple[str, str | None], list[dict]]) -> list[dict]:
    """Findings of every component the executable resolved to (app + embedded runtime + Go modules ...)."""
    if v.resolution is None:
        return []
    seen: set[str] = set()
    out: list[dict] = []
    for c in v.resolution.components:
        for f in fmap.get((c.name, c.version), []):
            if f["vuln_id"] not in seen:
                seen.add(f["vuln_id"])
                out.append({**f, "component": c.name})
    out.sort(key=lambda f: (f["priority"] or "P9", not f["kev"], -(f["cvss_score"] or 0)))
    return out


def summarize_findings(fs: list[dict]) -> str:
    if not fs:
        return ""
    counts: dict[str, int] = {}
    for f in fs:
        counts[f["priority"] or "?"] = counts.get(f["priority"] or "?", 0) + 1
    parts = [f"{p}x{counts[p]}" for p in PRIORITY_ORDER if p in counts]
    kev = sum(1 for f in fs if f["kev"])
    return " ".join(parts) + (f" KEV:{kev}" if kev else "")


# --------------------------------------------------------------------------- rows

def _identity(v: ProcessView) -> str:
    c = v.identity
    if c is None:
        return ""
    return f"{c.name} {c.version}" if c.version else c.name


def _launch(v: ProcessView) -> str:
    li = v.launch
    s = li.kind
    if li.label and not li.label.startswith("application."):
        s += f" ({li.label})"
    elif li.mechanism and li.mechanism not in ("spawn", "init", "launchservices"):
        s += f" ({li.mechanism})"
    return s


def view_row(v: ProcessView, fmap: dict | None = None, depth: int = 0) -> dict[str, Any]:
    fs = _view_findings(v, fmap or {})
    p = v.proc
    name = (p.exe or p.name or "?").rsplit("/", 1)[-1]
    return {
        "pid": p.pid, "ppid": p.ppid, "user": p.user, "depth": depth, "process": name, "exe": p.exe,
        "launch": v.launch.kind, "launch_detail": _launch(v), "label": v.launch.label, "launch_source": v.launch.source,
        "via": v.launch.via, "evidence": v.launch.evidence, "started": p.started, "script": v.script,
        "identity": _identity(v), "identity_method": v.resolution.method if v.resolution else None,
        "category": v.identity.category if v.identity else None,
        "findings": summarize_findings(fs), "findings_detail": fs[:20], "flags": list(v.flags),
        "provenance": {k: v.facts[k] for k in ("quarantine", "where_froms", "signature", "created", "sha256")
                       if k in v.facts},
    }


def tree_rows(views: list[ProcessView], fmap: dict | None = None) -> list[dict]:
    """Depth-first by parent pid; orphans (parent not in the snapshot) become roots."""
    by_pid = {v.proc.pid: v for v in views}
    children: dict[int, list[ProcessView]] = {}
    roots: list[ProcessView] = []
    for v in views:
        if v.proc.ppid in by_pid and v.proc.ppid != v.proc.pid:
            children.setdefault(v.proc.ppid, []).append(v)
        else:
            roots.append(v)
    out: list[dict] = []
    seen: set[int] = set()

    def walk(v: ProcessView, depth: int) -> None:
        if v.proc.pid in seen:
            return
        seen.add(v.proc.pid)
        out.append(view_row(v, fmap, depth))
        for c in sorted(children.get(v.proc.pid, []), key=lambda x: x.proc.pid):
            walk(c, depth + 1)

    for r in sorted(roots, key=lambda x: x.proc.pid):
        walk(r, 0)
    for v in views:                                   # cycles: never lose a process
        if v.proc.pid not in seen:
            walk(v, 0)
    return out


def interesting(row: dict) -> bool:
    return bool(row["findings"] or row["flags"])


# --------------------------------------------------------------------------- watch

@dataclass
class Event:
    kind: str                         # new-executable | new-launch-item | removed-launch-item
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Watcher:
    """Diffs successive snapshots. One inspector is kept for the whole session, so identity and provenance of
    an executable are computed once (codesign, hashing and binary parsing are the expensive parts)."""

    inspector: Inspector
    seen_exes: set[str] = field(default_factory=set)
    launch_items: dict[tuple[str, str | None], LaunchItem] = field(default_factory=dict)
    primed: bool = False

    def tick(self, snap: Snapshot) -> tuple[list[ProcessView], list[Event]]:
        self.inspector.snap = snap
        views = build_views(snap, self.inspector)
        events: list[Event] = []
        items = {(it.label, it.source): it for it in snap.launch_items}
        if self.primed:
            fresh: set[str] = set()
            for v in views:
                if v.proc.exe and v.proc.exe not in self.seen_exes and v.proc.exe not in fresh:
                    fresh.add(v.proc.exe)
                    events.append(Event("new-executable", {"view": v}))
            for key, it in items.items():
                if key not in self.launch_items:
                    events.append(Event("new-launch-item", {"item": it}))
            for key, it in self.launch_items.items():
                if key not in items:
                    events.append(Event("removed-launch-item", {"item": it}))
        self.seen_exes.update(v.proc.exe for v in views if v.proc.exe)
        self.launch_items = items
        self.primed = True
        return views, events
