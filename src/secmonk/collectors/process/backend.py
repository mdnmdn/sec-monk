"""Backend interface of the process monitor: one per OS.

A backend has two halves:

* ``take_snapshot(root, opts) -> Snapshot``: the live process list + launch items (OS-specific APIs).
* an ``Inspector``: executable path -> software identity (`Resolution`) and provenance facts.

The base `Inspector` works on any snapshot without touching the filesystem: it honours identities and facts
precomputed in ``snapshot.executables[path]`` (``identity``: name/version/category/purl/bundle_id/vendor_hint)
and otherwise reports the executable as unidentified. Platform inspectors add real lookups.

Adding Linux or Windows = a module with `take_snapshot` + an `Inspector` subclass, registered in `BACKENDS`
(see _docs/tech/collectors/process.md "Porting").
"""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...engine import purl as purls
from ...models import CAT_APPLICATION, CAT_EXECUTABLE, CAT_OS, CATEGORIES, Component
from .model import ProcessRecord, Snapshot

INTERPRETERS = re.compile(r"^(python[\d.]*|node|ruby|perl[\d.]*|php[\d.]*|java|osascript|deno|bun|"
                          r"pwsh|powershell|wscript|cscript)(\.exe)?$", re.IGNORECASE)


class UnsupportedPlatformError(RuntimeError):
    """No live process backend for this OS (analyse a snapshot file instead)."""


@dataclass
class Resolution:
    """Software identity of one executable."""

    method: str          # brew-keg | brew-cask | app-bundle | os | pkgutil | info-plist | go-binary | rust-binary
                         # | snapshot | path-only | none
    components: list[Component] = field(default_factory=list)   # primary first
    anchor: str | None = None          # bundle / keg path whose provenance applies (quarantine is on the bundle)
    notes: dict[str, Any] = field(default_factory=dict)

    @property
    def primary(self) -> Component | None:
        return self.components[0] if self.components else None


def _basename(path: str) -> str:
    return posixpath.basename(path.replace("\\", "/")) or path


class Inspector:
    """Filesystem-free inspector: snapshot-provided identity/facts, otherwise unidentified."""

    def __init__(self, snap: Snapshot, opts: dict[str, Any], warnings: list[str]):
        self.snap = snap
        self.opts = opts
        self.warnings = warnings
        self._res: dict[str, Resolution] = {}
        self._os: Component | None = None

    # ------------------------------------------------------------------ identity
    def os_component(self) -> Component | None:
        o = self.snap.os
        if self._os is None and o.get("version"):
            meta = {k: v for k, v in {"build": o.get("build")}.items() if v}
            self._os = Component(name=str(o.get("name") or self.snap.platform), version=str(o["version"]),
                                 category=CAT_OS, vendor=o.get("vendor") or ("apple" if self.snap.platform == "darwin"
                                                                             else None), meta=meta)
        return self._os

    def resolve(self, exe: str) -> Resolution:
        if exe not in self._res:
            res = self._from_snapshot(exe)
            if res is None:
                try:
                    res = self._resolve(exe)
                except Exception as e:  # noqa: BLE001 - one odd binary must not stop the monitor
                    self.warnings.append(f"cannot identify {exe}: {type(e).__name__}: {e}")
                    res = Resolution("none", [self.unidentified(exe)])
            self._res[exe] = res
        return self._res[exe]

    def _resolve(self, exe: str) -> Resolution:
        return Resolution("none", [self.unidentified(exe)])

    def _from_snapshot(self, exe: str) -> Resolution | None:
        ident = (self.snap.executables.get(exe) or {}).get("identity")
        if not isinstance(ident, dict) or not isinstance(ident.get("name"), str):
            return None
        if ident.get("os"):
            osc = self.os_component()
            return Resolution("os", [osc] if osc else [], notes={"os_binary": True})
        version = ident.get("version") if isinstance(ident.get("version"), str) else None
        cat = ident.get("category") if ident.get("category") in CATEGORIES else CAT_APPLICATION
        purl = ident.get("purl") if isinstance(ident.get("purl"), str) and purls.parse(ident["purl"]) else None
        meta = {k: ident[k] for k in ("bundle_id", "vendor_hint", "product_hint", "file_version", "company")
                if isinstance(ident.get(k), str)}
        meta["evidence"] = "snapshot"
        return Resolution("snapshot", [Component(name=ident["name"], version=version, category=cat, purl=purl,
                                                 source_path=exe, meta=meta)])

    @staticmethod
    def unidentified(path: str) -> Component:
        return Component(name=_basename(path), version=None, category=CAT_EXECUTABLE, source_path=path,
                         meta={"identity": "none"})

    def forget(self, exe: str) -> None:
        """Drop cached identity/facts of `exe` (the file changed on disk; used by --watch)."""
        self._res.pop(exe, None)

    def stamp(self, exe: str) -> tuple | None:
        """Change marker of the file at `exe`; None when this inspector cannot see files."""
        return None

    # ------------------------------------------------------------------ provenance
    def facts(self, exe: str) -> dict[str, Any]:
        f = dict(self.snap.executables.get(exe) or {})
        f.pop("identity", None)
        return f

    def user_writable(self, path: str) -> bool:
        return False

    # ------------------------------------------------------------------ misc
    @staticmethod
    def script_of(p: ProcessRecord) -> str | None:
        """For interpreters (python, node, java -jar ...), the script / jar actually being run."""
        base = _basename(p.exe or p.name or "")
        if not INTERPRETERS.match(base) or len(p.args) < 2:
            return None
        args = p.args[1:]
        if base.lower().startswith("java") and "-jar" in args:
            i = args.index("-jar")
            return args[i + 1] if i + 1 < len(args) else None
        for a in args:
            if a in ("-c", "-e", "-m", "-Command", "-EncodedCommand"):
                return None          # inline code / module: nothing on disk to point at
            if not a.startswith("-"):
                return a
        return None


@dataclass
class Backend:
    platform: str
    take_snapshot: Callable[[Path, dict[str, Any]], Snapshot] | None
    inspector: Callable[[Snapshot, Path | None, dict[str, Any], list[str]], Inspector]


def _generic(snap: Snapshot, root: Path | None, opts: dict[str, Any], warnings: list[str]) -> Inspector:
    return Inspector(snap, opts, warnings)


def _macos() -> Backend:
    from . import macos

    def inspector(snap: Snapshot, root: Path | None, opts: dict[str, Any], warnings: list[str]) -> Inspector:
        return macos.MacOSInspector(snap, root, opts, warnings)

    return Backend("darwin", macos.take_snapshot, inspector)


BACKENDS: dict[str, Callable[[], Backend]] = {"darwin": _macos}


def backend_for(platform: str) -> Backend:
    """Backend for a platform; unknown platforms get the snapshot-only inspector and no live snapshot."""
    factory = BACKENDS.get(platform)
    return factory() if factory else Backend(platform, None, _generic)


def current_platform() -> str:
    import sys

    return {"darwin": "darwin", "win32": "windows"}.get(sys.platform, "linux" if os.name == "posix" else sys.platform)
