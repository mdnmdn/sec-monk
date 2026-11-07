"""`process` collector: what is running, how it was started, what software it is, where it came from.

Target:
  (none)            live snapshot of this machine (macOS today)
  <snapshot.json>   a `secmonk-process-snapshot/1` file taken elsewhere (`-o root=<dir>` to resolve its
                    executables against a copied tree; without it nothing on this machine is read)

Output: a normal `Inventory` (asset `process:<host>`), so `scan process` matches the running software against
the mirror with the shared engine. Each component carries `meta.process` (pids, users, launch kinds,
executables, provenance, risk flags); executables without a package identity become `executable` components
(never matched, kept for the monitor view). The full process tree is in `asset.meta.processes`.

See _docs/tech/collectors/process.md and _docs/features/process-monitor.md.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...models import CAT_EXECUTABLE, Asset, Component, Inventory
from ..base import Collector, register
from . import snapshot as snapfile
from .backend import Inspector, Resolution, backend_for, current_platform
from .launch import LaunchClassifier
from .model import (
    LAUNCH_AGENT,
    LAUNCH_LOGIN_ITEM,
    LAUNCH_SERVICE,
    LaunchInfo,
    ProcessRecord,
    Snapshot,
)

MAX_PROCS_PER_COMPONENT = 50
MAX_TREE = 5000
PERSISTENT = (LAUNCH_SERVICE, LAUNCH_AGENT, LAUNCH_LOGIN_ITEM)


@dataclass
class ProcessView:
    """One process with everything the monitor knows about it (also used by the CLI tree)."""

    proc: ProcessRecord
    launch: LaunchInfo
    resolution: Resolution | None = None
    facts: dict[str, Any] = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)
    script: str | None = None

    @property
    def identity(self) -> Component | None:
        return self.resolution.primary if self.resolution else None


def risk_flags(p: ProcessRecord, launch: LaunchInfo, res: Resolution | None, facts: dict[str, Any],
               inspector: Inspector) -> list[str]:
    """Platform-neutral trust heuristics over the facts a backend collected. Informational, not findings."""
    flags: list[str] = []
    exe = p.exe or ""
    if facts.get("exists") is False:
        flags.append("exe-missing")             # deleted or replaced on disk while running (updates, droppers)
    sig = facts.get("signature") or {}
    if sig.get("signed") is False:
        flags.append("unsigned")
    elif sig.get("adhoc"):
        flags.append("adhoc-signed")
    if sig.get("verified") is False:
        flags.append("signature-invalid")       # only from a real check (`codesign --verify`, -o verify=true)
    if facts.get("quarantine"):
        flags.append("downloaded")
    if facts.get("world_writable"):
        flags.append("world-writable")
    if exe and "/AppTranslocation/" in exe:
        flags.append("translocated")            # run straight from a disk image / Downloads
    if exe and inspector.user_writable(exe):
        flags.append("user-writable-path")
        if p.uid == 0:
            flags.append("root-from-user-path")
        if launch.kind in PERSISTENT:
            flags.append("persistent-from-user-path")
    if res is not None and res.method == "none":
        flags.append("unidentified")
    return flags


def build_views(snap: Snapshot, inspector: Inspector) -> list[ProcessView]:
    classifier = LaunchClassifier(snap)
    views: list[ProcessView] = []
    for p in snap.processes:
        launch = classifier.classify(p)
        v = ProcessView(p, launch, script=inspector.script_of(p))
        if p.exe:
            v.resolution = inspector.resolve(p.exe)
            v.facts = inspector.facts(p.exe)
            v.flags = risk_flags(p, launch, v.resolution, v.facts, inspector)
        views.append(v)
    return views


def _proc_entry(v: ProcessView) -> dict[str, Any]:
    p, li = v.proc, v.launch
    d = {"pid": p.pid, "ppid": p.ppid, "user": p.user, "started": p.started, "exe": p.exe,
         "launch": li.kind, "mechanism": li.mechanism, "label": li.label, "launch_source": li.source,
         "via": li.via, "parent_exe": li.parent_exe, "script": v.script}
    return {k: x for k, x in d.items() if x is not None}


def _provenance(v: ProcessView) -> dict[str, Any]:
    """The 'how / when did it get here' subset of the facts, plus identity-level install facts."""
    f = v.facts
    out = {k: f[k] for k in ("quarantine", "where_froms", "signature", "gatekeeper", "created", "mtime", "sha256",
                             "size", "owner_uid") if k in f}
    c = v.identity
    if c is not None:
        for k in ("installed_at", "poured_from_bottle", "installed_on_request", "install_date", "mas", "also_cask",
                  "sparkle_feed", "tap"):
            if c.meta.get(k) not in (None, False):
                out[f"identity_{k}"] = c.meta[k]
    if v.resolution and v.resolution.notes.get("pkg_install_time"):
        out["pkg_install_time"] = v.resolution.notes["pkg_install_time"]
    return out


def to_components(views: list[ProcessView]) -> list[Component]:
    """One component per software identity; process facts merged into `meta.process`."""
    by_key: dict[str, Component] = {}
    order: list[str] = []
    for v in views:
        if v.resolution is None:
            continue
        for i, c in enumerate(v.resolution.components):
            key = c.key if c.category != CAT_EXECUTABLE else f"exe:{c.source_path}"
            comp = by_key.get(key)
            if comp is None:
                comp = Component(name=c.name, version=c.version, category=c.category, purl=c.purl, cpe=c.cpe,
                                 vendor=c.vendor, ecosystem=c.ecosystem, source_path=c.source_path,
                                 meta=dict(c.meta))
                comp.meta["process"] = {"processes": [], "executables": [], "launch": [], "users": [],
                                        "flags": [], "resolution": v.resolution.method}
                by_key[key] = comp
                order.append(key)
            pm = comp.meta["process"]
            exe = v.proc.exe
            if exe and exe not in pm["executables"]:
                pm["executables"].append(exe)
                if i == 0:
                    prov = _provenance(v)
                    if prov:
                        pm.setdefault("provenance", {})[exe] = prov
            if i > 0:
                pm["via_executable"] = pm.get("via_executable") or exe   # runtime / dependency of the binary
            if len(pm["processes"]) < MAX_PROCS_PER_COMPONENT:
                pm["processes"].append(_proc_entry(v))
            else:
                pm["processes_truncated"] = True
            for k, val in (("launch", v.launch.kind), ("users", v.proc.user)):
                if val and val not in pm[k]:
                    pm[k].append(val)
            for fl in v.flags:
                if fl not in pm["flags"]:
                    pm["flags"].append(fl)
            for nk in ("helper", "os_binary", "identity"):
                if v.resolution.notes.get(nk):
                    pm[nk] = v.resolution.notes[nk]
    comps = [by_key[k] for k in order]
    for c in comps:
        pm = c.meta["process"]
        pm["count"] = len(pm["processes"])
        if c.category == CAT_EXECUTABLE:
            c.meta["paths"] = pm["executables"][1:]
    return comps


def process_tree(views: list[ProcessView]) -> list[dict[str, Any]]:
    out = []
    for v in views[:MAX_TREE]:
        e = _proc_entry(v)
        c = v.identity
        if c is not None:
            e["identity"] = f"{c.name}@{c.version}" if c.version else c.name
            e["category"] = c.category
        if v.flags:
            e["flags"] = v.flags
        out.append(e)
    return out


def missing_launch_programs(snap: Snapshot, inspector: Inspector) -> list[dict[str, Any]]:
    """Configured launch items whose program does not exist (stale persistence, or a removed payload)."""
    out = []
    local = getattr(inspector, "local", None)
    if not getattr(inspector, "fs", False) or local is None:
        return out
    for it in snap.launch_items:
        if it.program and it.program.startswith("/") and it.disabled is not True:
            try:
                exists = os.path.lexists(local(it.program))     # never follow a link out of a copied tree
            except (OSError, ValueError):
                continue
            if not exists:
                out.append({"label": it.label, "program": it.program, "source": it.source, "mechanism": it.mechanism})
    return out


@register
class ProcessCollector(Collector):
    name = "process"
    description = "Running processes: launch origin (service/agent/app/shell...), software identity + version, provenance"

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        snap, inspector, views = self.analyse(target, **opts)
        return self.inventory(snap, inspector, views, opts)

    # split so the CLI monitor can reuse the views without re-reading the machine
    def analyse(self, target: str | None = None, **opts: Any) -> tuple[Snapshot, Inspector, list[ProcessView]]:
        snap = self.snapshot(target, **opts)
        root = Path(opts["root"]) if opts.get("root") else (Path("/") if not target else None)
        if root is not None and not root.is_dir():
            raise ValueError(f"process: root {root} is not a directory")
        warnings = list(snap.warnings)
        inspector = backend_for(snap.platform).inspector(snap, root, opts, warnings)
        views = build_views(snap, inspector)
        snap.warnings = warnings
        return snap, inspector, views

    @staticmethod
    def snapshot(target: str | None = None, **opts: Any) -> Snapshot:
        if target:
            return snapfile.load(target)
        plat = current_platform()
        backend = backend_for(plat)
        if backend.take_snapshot is None:
            raise RuntimeError(f"process: live snapshots are not implemented on {plat} yet "
                               f"(analyse a {snapfile.SCHEMA} file instead)")
        snap = backend.take_snapshot(Path(opts.get("root") or "/"), opts)
        if opts.get("snapshot_out"):
            snapfile.dump(snap, opts["snapshot_out"])
        return snap

    def inventory(self, snap: Snapshot, inspector: Inspector, views: list[ProcessView],
                  opts: dict[str, Any]) -> Inventory:
        comps = to_components(views)
        osc = inspector.os_component()
        if osc is not None and not any(c is osc or (c.category == osc.category and c.name == osc.name) for c in comps):
            comps.insert(0, osc)
        host = opts.get("hostname") or snap.host
        missing = missing_launch_programs(snap, inspector)
        kinds: dict[str, int] = {}
        for v in views:
            kinds[v.launch.kind] = kinds.get(v.launch.kind, 0) + 1
        meta: dict[str, Any] = {
            "taken_at": snap.taken_at, "process_count": len(snap.processes),
            "launch_items": len(snap.launch_items), "launch_kinds": kinds,
            "without_exe": sum(1 for v in views if not v.proc.exe),
            "processes": process_tree(views),
        }
        if missing:
            meta["launch_items_missing_program"] = missing
        if len(views) > MAX_TREE:
            meta["processes_truncated"] = True
        asset = Asset(id=f"process:{host}", type="host-processes", name=host,
                      os_name=snap.os.get("name"), os_version=snap.os.get("version"), platform=snap.platform,
                      meta=meta)
        return Inventory(asset=asset, collector=self.name, components=comps, warnings=snap.warnings)
