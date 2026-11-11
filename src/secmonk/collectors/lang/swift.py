"""Swift Package Manager: Package.resolved (v1, v2, v3).

PURL type ``swift`` with namespace = ``<host>/<owner path>`` and name = repository
(``pkg:swift/github.com/apple/swift-nio@2.58.0``), OSV ecosystem ``SwiftURL``, whose package name is the
repository URL without scheme and ``.git`` (``github.com/apple/swift-nio``; checked against the OSV
``SwiftURL/all.zip`` on 2026-11-11). The component name is that same string, so the engine's exact
``osv-package`` lookup works unchanged (names are compared lowercased).

* v1: ``object.pins[]`` with ``package``, ``repositoryURL``, ``state.{version,revision,branch}``.
* v2 / v3: ``pins[]`` with ``identity``, ``kind``, ``location``, ``state.{version,revision,branch}``
  (v3 only adds a top-level ``originHash``).
* Pins without a version (branch or revision only) become components with ``version=None`` and
  ``meta.revision`` / ``meta.branch``: inventoried, not matchable by version (one warning per file).
* Skipped: local pins (``fileSystem`` / ``localSourceControl`` kinds, file paths: the project's own code)
  and registry pins (``kind: registry``, identity ``scope.name``: OSV has no data keyed by registry id).
* ``Package.swift`` is not parsed: it is Swift code and its requirements (``from:``, ranges) are unpinned;
  only the lockfile tells what was resolved.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from ...models import Component
from ..base import strip_url_secrets
from .base import EV_LOCKFILE, LangParser, basename, push, register, safe_library

ECOSYSTEM = "SwiftURL"
MAX_RESOLVED_BYTES = 16 * 1024 * 1024
_SCP = re.compile(r"^[\w.+-]+@([A-Za-z0-9.-]+):(?!/)(.+)$")       # git@github.com:owner/repo.git
_V_PREFIX = re.compile(r"^[vV](?=\d)")
_REMOTE_SCHEMES = ("https", "http", "ssh", "git", "git+ssh", "ssh+git")
_LOCAL_KINDS = ("fileSystem", "localSourceControl")


def repo_id(location: str | None) -> str | None:
    """Repository URL -> OSV SwiftURL package name: ``host/path`` without scheme, user, port and ``.git``.
    None for local paths and anything that is not a remote git URL."""
    if not isinstance(location, str) or not location.strip():
        return None
    loc = location.strip()
    m = _SCP.match(loc)
    if m:
        host, path = m[1], m[2]
    else:
        try:
            u = urlparse(loc)
            host = u.hostname
        except ValueError:
            return None
        if u.scheme.lower() not in _REMOTE_SCHEMES or not host:
            return None
        path = u.path
    path = path.strip("/")
    if path.lower().endswith(".git"):
        path = path[:-4].rstrip("/")
    if not path or "/" not in path or any(p in ("", ".", "..") for p in path.split("/")):
        return None                                        # needs at least owner/repo
    return f"{host.lower().rstrip('.')}/{path}"


def _pins(doc: dict) -> tuple[list, int | None]:
    version = doc.get("version") if isinstance(doc.get("version"), int) else None
    if isinstance(doc.get("object"), dict):                # v1
        pins = doc["object"].get("pins")
    else:                                                  # v2 / v3
        pins = doc.get("pins")
    return (pins if isinstance(pins, list) else []), version


def parse_package_resolved(path: str, data: bytes) -> tuple[list[Component], list[str]]:
    doc = json.loads(data)
    if not isinstance(doc, dict):
        return [], []
    pins, lock_version = _pins(doc)
    out: list[Component] = []
    unversioned: list[str] = []
    registry = 0
    for pin in pins:
        if not isinstance(pin, dict):
            continue
        kind = pin.get("kind") if isinstance(pin.get("kind"), str) else None
        if kind in _LOCAL_KINDS:
            continue
        if kind == "registry":
            registry += 1
            continue
        location = pin.get("location") or pin.get("repositoryURL")
        rid = repo_id(location)
        if rid is None:
            continue                                       # local path or unrecognized location
        state = pin.get("state") if isinstance(pin.get("state"), dict) else {}
        raw = state.get("version") if isinstance(state.get("version"), str) else None
        version = _V_PREFIX.sub("", raw.strip()) if raw and raw.strip() else None
        revision = state.get("revision") if isinstance(state.get("revision"), str) else None
        branch = state.get("branch") if isinstance(state.get("branch"), str) else None
        namespace, _, name = rid.rpartition("/")
        identity = pin.get("identity") or pin.get("package")
        comp = safe_library("swift", name, version, path=path, evidence=EV_LOCKFILE, parser="swift-package-resolved",
                            namespace=namespace, lock_version=lock_version,
                            identity=identity if isinstance(identity, str) else None,
                            location=strip_url_secrets(location) if "://" in location else location,
                            revision=revision, branch=branch if version is None else None,
                            raw_version=raw if raw and raw != version else None)
        push(out, comp)
        if comp is not None and version is None:
            unversioned.append(rid)
    warns = []
    if unversioned:
        warns.append(f"{len(unversioned)} Swift pin(s) without a version (branch/revision only), "
                     f"not matchable by version: {', '.join(unversioned[:5])}"
                     + (" ..." if len(unversioned) > 5 else ""))
    if registry:
        warns.append(f"{registry} Swift registry pin(s) skipped (no OSV data keyed by registry identity)")
    return out, warns


register(LangParser("swift-package-resolved", ECOSYSTEM, EV_LOCKFILE,
                    lambda p: basename(p) == "Package.resolved", parse_package_resolved,
                    max_bytes=MAX_RESOLVED_BYTES))
