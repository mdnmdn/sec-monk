"""Python parsers: installed dist-info / egg-info, conda-meta, poetry / Pipfile / uv / pdm lockfiles and
pinned requirements files.

PURL type `pypi` with PEP 503 normalized names (OSV ecosystem `PyPI`); conda packages are `pkg:conda/...`
and carry no OSV ecosystem. See _docs/references/package-formats/python.md.
"""

from __future__ import annotations

import json
import re
import tomllib
from email.parser import HeaderParser

from ...models import Component
from .base import (
    EV_INSTALLED,
    EV_LOCKFILE,
    EV_MANIFEST,
    LangParser,
    basename,
    push,
    register,
    safe_library,
)

_SP_DIRS = ("site-packages", "dist-packages")
_REQ_NAME_RE = re.compile(r"^(?:requirements|constraints)(?:[-_.][^/]*)?\.txt$|^[^/]*[-_]requirements\.txt$", re.IGNORECASE)


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _pypi(name: str, version: str | None, *, path: str, evidence: str, parser: str, **meta) -> Component | None:
    c = safe_library("pypi", pep503(name), version, path=path, evidence=evidence, parser=parser, **meta)
    if c is not None:
        c.name = name.strip()              # keep the spelling the package uses for display
    return c


def _venv_root(path: str) -> str | None:
    """Venv/prefix root from the layout `<root>/lib/pythonX.Y/site-packages` or `<root>/Lib/site-packages`."""
    parts = path.split("/")
    for i, p in enumerate(parts):
        if p in _SP_DIRS:
            j = i - 1
            if j >= 0 and re.fullmatch(r"python\d+(\.\d+)*", parts[j]):
                j -= 1
            if j >= 0 and parts[j] in ("lib", "lib64", "Lib"):
                return "/".join(parts[:j]) or "/"
            return None
    return None


# --------------------------------------------------------------------------- installed


def _match_dist_info(p: str) -> bool:
    parts = p.split("/")
    return (len(parts) >= 3 and parts[-1] == "METADATA" and parts[-2].endswith(".dist-info")
            and parts[-3] in _SP_DIRS)


def _match_egg_dir(p: str) -> bool:
    parts = p.split("/")
    return (len(parts) >= 3 and parts[-1] == "PKG-INFO" and parts[-2].endswith(".egg-info")
            and parts[-3] in _SP_DIRS)


def _match_egg_file(p: str) -> bool:
    parts = p.split("/")
    return len(parts) >= 2 and parts[-1].endswith(".egg-info") and parts[-2] in _SP_DIRS


def parse_core_metadata(path: str, data: bytes) -> list[Component]:
    """RFC 822 core metadata (`METADATA`, `PKG-INFO`, single-file `.egg-info`)."""
    text = data.decode("utf-8", "replace")
    msg = HeaderParser().parsestr(text, headersonly=True)
    name, version = msg.get("Name"), msg.get("Version")
    if not name or not version:
        return []
    lic = msg.get("License-Expression") or msg.get("License")
    if lic and (len(lic) > 80 or "\n" in lic or lic.upper() == "UNKNOWN"):
        lic = None
    kind = "dist-info" if ".dist-info/" in path else "egg-info"
    c = _pypi(str(name), str(version).strip(), path=path, evidence=EV_INSTALLED, parser=f"python-{kind}",
              venv_root=_venv_root(path), license=lic, layout=kind)
    return [c] if c else []


# --------------------------------------------------------------------------- conda

def parse_conda_meta(path: str, data: bytes) -> list[Component]:
    """`conda-meta/<name>-<ver>-<build>.json` -> `pkg:conda/<name>@<version>` (ecosystem None).

    Python distributions installed by conda also ship a dist-info under site-packages; those are reported
    as PyPI by the dist-info parser. The conda record itself is kept as a conda component."""
    d = json.loads(data)
    if not isinstance(d, dict):
        return []
    name, ver = d.get("name"), d.get("version")
    if not isinstance(name, str) or not isinstance(ver, str):
        return []
    channel = d.get("channel") or ""
    if "/" in channel:  # URL form: https://conda.anaconda.org/conda-forge/linux-64 -> conda-forge
        segs = [s for s in channel.rstrip("/").split("/") if s]
        channel = segs[-2] if len(segs) >= 2 and "-" in segs[-1] and segs[-1].split("-")[0] in (
            "linux", "osx", "win", "noarch") else segs[-1]
    prefix = path.rsplit("/conda-meta/", 1)[0] if "/conda-meta/" in path else None
    c = safe_library("conda", name, ver, path=path, evidence=EV_INSTALLED, parser="conda-meta",
                     channel=channel or None, build=d.get("build_string") or d.get("build"),
                     subdir=d.get("subdir"), license=d.get("license"), conda_prefix=prefix)
    return [c] if c else []


# --------------------------------------------------------------------------- lockfiles

def parse_poetry_lock(path: str, data: bytes) -> list[Component]:
    d = tomllib.loads(data.decode("utf-8", "replace"))
    out = []
    for p in d.get("package", []):
        name, ver = p.get("name"), p.get("version")
        if not name or not ver:
            continue
        src = p.get("source") or {}
        if src.get("type") in ("directory", "file"):
            continue
        groups = p.get("groups")
        dev = (p.get("category") == "dev") if "category" in p else (
            bool(groups) and "main" not in groups) if groups is not None else None
        push(out, _pypi(name, ver, path=path, evidence=EV_LOCKFILE, parser="poetry-lock",
                         dev=True if dev else None, optional=True if p.get("optional") else None,
                         groups=groups, source_type=src.get("type")))
    return out


def parse_pipfile_lock(path: str, data: bytes) -> list[Component]:
    d = json.loads(data)
    out = []
    for section, dev in (("default", False), ("develop", True)):
        for name, e in (d.get(section) or {}).items():
            if not isinstance(e, dict) or not isinstance(e.get("version"), str):
                continue                                    # git / path / editable entries have no version
            v = e["version"].strip()
            if not v.startswith(("==", "===")):
                continue
            v = v.lstrip("=").strip()
            push(out, _pypi(name, v, path=path, evidence=EV_LOCKFILE, parser="pipfile-lock",
                             dev=True if dev else None, markers=e.get("markers")))
    return out


def parse_uv_lock(path: str, data: bytes) -> list[Component]:
    d = tomllib.loads(data.decode("utf-8", "replace"))
    pkgs = d.get("package", [])
    by_name = {pep503(p["name"]): p for p in pkgs if p.get("name")}

    def deps_of(p: dict, with_dev: bool) -> list[str]:
        names = [x.get("name") for x in p.get("dependencies", []) if isinstance(x, dict)]
        for group in (p.get("optional-dependencies") or {}).values():
            names += [x.get("name") for x in group if isinstance(x, dict)]
        if with_dev:
            for group in (p.get("dev-dependencies") or {}).values():
                names += [x.get("name") for x in group if isinstance(x, dict)]
        return [pep503(n) for n in names if n]

    def reach(starts: list[str]) -> set[str]:
        seen: set[str] = set()
        stack = list(starts)
        while stack:
            n = stack.pop()
            if n in seen or n not in by_name:
                continue
            seen.add(n)
            stack.extend(deps_of(by_name[n], False))
        return seen

    roots = [p for p in pkgs if isinstance(p.get("source"), dict)
             and ("editable" in p["source"] or "virtual" in p["source"])]
    prod = reach([n for r in roots for n in deps_of(r, False)])
    dev_only = None
    if roots:
        dev_only = reach([n for r in roots for n in deps_of(r, True)]) - prod
    out = []
    for p in pkgs:
        name, ver = p.get("name"), p.get("version")
        src = p.get("source") or {}
        if not name or not ver or "editable" in src or "virtual" in src or "directory" in src:
            continue
        push(out, _pypi(name, ver, path=path, evidence=EV_LOCKFILE, parser="uv-lock",
                         dev=True if dev_only is not None and pep503(name) in dev_only else None,
                         source_type=next(iter(src), None)))
    return out


def parse_pdm_lock(path: str, data: bytes) -> list[Component]:
    d = tomllib.loads(data.decode("utf-8", "replace"))
    out, seen = [], set()
    for p in d.get("package", []):
        name, ver = p.get("name"), p.get("version")
        if not name or not ver or p.get("editable"):
            continue
        if (name, ver) in seen:                              # same pkg repeated once per extras combination
            continue
        seen.add((name, ver))
        groups = p.get("groups")
        dev = bool(groups) and "default" not in groups
        push(out, _pypi(name, ver, path=path, evidence=EV_LOCKFILE, parser="pdm-lock",
                         dev=True if dev else None, groups=groups))
    return out


# --------------------------------------------------------------------------- requirements

_REQ_RE = re.compile(r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[(?P<extras>[^\]]*)\])?\s*"
                     r"(?P<op>===|==)\s*(?P<ver>[^\s;,#\\]+)\s*(?P<rest>.*)$")


def _logical_lines(text: str):
    buf = ""
    for raw in text.lstrip("﻿").splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        yield buf + line
        buf = ""
    if buf:
        yield buf


def parse_requirements(path: str, data: bytes) -> list[Component]:
    out = []
    for line in _logical_lines(data.decode("utf-8", "replace")):
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not line or line.startswith("-"):                 # -r / -c / -e / --index-url / --hash-only lines
            continue
        m = _REQ_RE.match(line)
        if not m:
            continue
        ver, rest = m["ver"], m["rest"].strip()
        if "*" in ver or rest.startswith((",", "!=", ">", "<", "~=")):
            continue                                         # wildcard or additional specifiers: not a pin
        marker = None
        if rest.startswith(";"):
            marker = re.split(r"\s--", rest[1:], maxsplit=1)[0].strip() or None
        push(out, _pypi(m["name"], ver, path=path, evidence=EV_MANIFEST, parser="requirements-txt",
                         extras=[e.strip() for e in m["extras"].split(",") if e.strip()] if m["extras"] else None,
                         marker=marker))
    return out


def _match_requirements(p: str) -> bool:
    b = basename(p)
    if _REQ_NAME_RE.match(b):
        return True
    parts = p.split("/")
    return b.endswith(".txt") and len(parts) >= 2 and parts[-2] == "requirements"


# --------------------------------------------------------------------------- registration

register(LangParser("python-dist-info", "PyPI", EV_INSTALLED, _match_dist_info, parse_core_metadata,
                    max_bytes=4 * 1024 * 1024))
register(LangParser("python-egg-info", "PyPI", EV_INSTALLED, _match_egg_dir, parse_core_metadata,
                    max_bytes=4 * 1024 * 1024))
register(LangParser("python-egg-info-file", "PyPI", EV_INSTALLED, _match_egg_file, parse_core_metadata,
                    max_bytes=4 * 1024 * 1024))
register(LangParser("conda-meta", "conda", EV_INSTALLED,
                    lambda p: p.split("/")[-2:-1] == ["conda-meta"] and p.endswith(".json"), parse_conda_meta,
                    max_bytes=4 * 1024 * 1024))
register(LangParser("poetry-lock", "PyPI", EV_LOCKFILE, lambda p: basename(p) == "poetry.lock", parse_poetry_lock))
register(LangParser("pipfile-lock", "PyPI", EV_LOCKFILE, lambda p: basename(p) == "Pipfile.lock",
                    parse_pipfile_lock))
register(LangParser("uv-lock", "PyPI", EV_LOCKFILE, lambda p: basename(p) == "uv.lock", parse_uv_lock))
register(LangParser("pdm-lock", "PyPI", EV_LOCKFILE, lambda p: basename(p) == "pdm.lock", parse_pdm_lock))
register(LangParser("requirements-txt", "PyPI", EV_MANIFEST, _match_requirements, parse_requirements))
