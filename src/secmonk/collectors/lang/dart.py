"""Dart / Flutter: pubspec.lock.

PURL type ``pub`` (``pkg:pub/<name>@<version>``), OSV ecosystem ``Pub`` (package name = the pub.dev name,
always lowercase ``[a-z0-9_]``; checked against the OSV ``Pub/all.zip`` on 2026-11-11).

``packages.<name>`` entries carry ``dependency`` (``direct main`` | ``direct dev`` | ``direct overridden``
| ``transitive``), ``source`` (``hosted`` | ``git`` | ``path`` | ``sdk``), ``description`` and ``version``.

* hosted from pub.dev (or its legacy host / known mirrors) -> component; ``direct`` from ``dependency``,
  ``dev`` for ``direct dev``, ``overridden`` for ``direct overridden``. The lockfile does not tell which
  transitive packages are reachable only from dev dependencies: transitives are never flagged ``dev``.
* hosted from another server (self-hosted / private repository) -> skipped: OSV's Pub data describes
  pub.dev packages, a same-named private package would be a false positive (same rule as Cargo).
* git -> component with the version of the package's pubspec at that ref, plus ``meta.git_url`` /
  ``meta.resolved_ref``; matched like hosted (same name + version is the same code in practice).
* path (the project's own packages) and sdk (``flutter``, ``flutter_test``: version ``0.0.0``) -> skipped.
* ``pubspec.yaml`` is not parsed: its constraints (``^1.2.0``) are unpinned.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from ...models import Component
from ..base import strip_url_secrets
from .base import EV_LOCKFILE, LangParser, basename, push, register, safe_library
from .javascript import load_yaml

ECOSYSTEM = "Pub"
MAX_LOCK_BYTES = 16 * 1024 * 1024
# pub.dev, its legacy host and the public mirrors that serve the same packages (PUB_HOSTED_URL)
PUB_DEV_HOSTS = frozenset({"pub.dev", "pub.dartlang.org", "pub.flutter-io.cn"})


def _hosted_on_pub_dev(desc: Any) -> bool:
    if not isinstance(desc, dict):
        return True                         # very old locks: `description: <name>` -> default server
    url = desc.get("url")
    if not isinstance(url, str) or not url:
        return True
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return host in PUB_DEV_HOSTS


def parse_pubspec_lock(path: str, data: bytes) -> list[Component]:
    doc = load_yaml(data)
    if not isinstance(doc, dict) or not isinstance(doc.get("packages"), dict):
        return []
    sdks = doc.get("sdks") if isinstance(doc.get("sdks"), dict) else {}
    dart_sdk = sdks.get("dart") if isinstance(sdks.get("dart"), str) else None
    out: list[Component] = []
    for name, p in doc["packages"].items():
        if not isinstance(name, str) or not isinstance(p, dict):
            continue
        source, version = p.get("source"), p.get("version")
        if not isinstance(version, str) or not version.strip():
            continue
        desc = p.get("description")
        meta: dict[str, Any] = {}
        if source == "hosted":
            if not _hosted_on_pub_dev(desc):
                continue
        elif source == "git":
            d = desc if isinstance(desc, dict) else {}
            url = d.get("url") if isinstance(d.get("url"), str) else None
            meta.update(source="git", git_url=strip_url_secrets(url) if url and "://" in url else url,
                        resolved_ref=d.get("resolved-ref") if isinstance(d.get("resolved-ref"), str) else None,
                        git_path=d.get("path") if isinstance(d.get("path"), str) and d["path"] != "." else None)
        else:
            continue                                # path, sdk, unknown sources
        dep = p.get("dependency") if isinstance(p.get("dependency"), str) else ""
        direct = dep.startswith("direct")
        push(out, safe_library("pub", name, version.strip(), path=path, evidence=EV_LOCKFILE,
                               parser="pubspec-lock", direct=direct,
                               dev=True if dep == "direct dev" else None,
                               overridden=True if dep == "direct overridden" else None,
                               dart_sdk=dart_sdk, **meta))
    return out


register(LangParser("pubspec-lock", ECOSYSTEM, EV_LOCKFILE, lambda p: basename(p) == "pubspec.lock",
                    parse_pubspec_lock, max_bytes=MAX_LOCK_BYTES))
