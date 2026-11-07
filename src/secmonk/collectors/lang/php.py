"""PHP / Composer parsers: composer.lock and vendor/composer/installed.json.

PURL type `composer` (vendor -> namespace), OSV ecosystem `Packagist`. A leading `v` on the version
(`v1.43.0`) is stripped: OSV Packagist ECOSYSTEM range events are bare (`1.43.0`).
See _docs/references/package-formats/php.md.
"""

from __future__ import annotations

import json
import re

from ...models import Component
from .base import EV_INSTALLED, EV_LOCKFILE, LangParser, basename, register, safe_library

_V_PREFIX = re.compile(r"^[vV](?=\d)")


def _norm_version(v: str) -> tuple[str | None, str | None]:
    """-> (version, dev_branch). `dev-main`, `1.x-dev`, `dev-master#abc` are branches, not releases."""
    v = v.strip()
    if v.startswith("dev-") or v.endswith("-dev"):
        return None, v
    return _V_PREFIX.sub("", v), None


def _component(p: dict, path: str, evidence: str, parser: str, dev: bool | None) -> Component | None:
    name, ver = p.get("name"), p.get("version")
    if not isinstance(name, str) or "/" not in name or not isinstance(ver, str):
        return None
    vendor, _, pkg = name.partition("/")
    version, branch = _norm_version(ver)
    src = p.get("source") or {}
    lic = p.get("license")
    return safe_library("composer", pkg, version, path=path, evidence=evidence, parser=parser, namespace=vendor,
                   dev=True if dev else None, dev_branch=branch,
                   raw_version=ver if ver != version else None,
                   reference=(src.get("reference") if isinstance(src, dict) else None) or None,
                   license=",".join(lic) if isinstance(lic, list) else None,
                   abandoned=True if p.get("abandoned") else None,
                   package_type=p.get("type") if p.get("type") not in (None, "library") else None)


def parse_composer_lock(path: str, data: bytes) -> list[Component]:
    d = json.loads(data)
    out: list[Component] = []
    if not isinstance(d, dict):
        return out
    for key, dev in (("packages", False), ("packages-dev", True)):
        for p in d.get(key) or []:
            if isinstance(p, dict) and (c := _component(p, path, EV_LOCKFILE, "composer-lock", dev)):
                out.append(c)
    return out


def parse_installed_json(path: str, data: bytes) -> list[Component]:
    d = json.loads(data)
    if isinstance(d, list):                       # Composer 1
        pkgs, dev_names = d, set()
    elif isinstance(d, dict):                     # Composer 2
        pkgs, dev_names = d.get("packages") or [], set(d.get("dev-package-names") or [])
    else:
        return []
    out = []
    for p in pkgs:
        if isinstance(p, dict) and (c := _component(p, path, EV_INSTALLED, "composer-installed",
                                                    p.get("name") in dev_names)):
            out.append(c)
    return out


register(LangParser("composer-lock", "Packagist", EV_LOCKFILE, lambda p: basename(p) == "composer.lock",
                    parse_composer_lock))
register(LangParser("composer-installed", "Packagist", EV_INSTALLED,
                    lambda p: p.split("/")[-2:] == ["composer", "installed.json"], parse_installed_json))
