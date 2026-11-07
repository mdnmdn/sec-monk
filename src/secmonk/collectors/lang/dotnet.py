""".NET (NuGet) parsers: *.deps.json, packages.lock.json, project.assets.json, packages.config,
*.csproj / *.fsproj / *.vbproj (+ Directory.Build.props/targets) and Directory.Packages.props.

PURL / OSV mapping: `pkg:nuget/<Name>@<version>` -> OSV ecosystem "NuGet", package name = <Name>
(OSV and the engine compare case-insensitively: engine.purl.normalize_name lowercases, and the OSV
importer lowercases `affected.package` the same way; the purl itself keeps the original casing).

.NET runtime: OSV records the runtime as the NuGet *runtime packs*
`Microsoft.NETCore.App.Runtime.<rid>` / `Microsoft.AspNetCore.App.Runtime.<rid>` /
`Microsoft.WindowsDesktop.App.Runtime.<rid>` (RIDs: linux-x64, linux-musl-x64, linux-arm64, win-x64 …).
The *shared framework* directory of an installed runtime
(`/usr/share/dotnet/shared/Microsoft.NETCore.App/<ver>/Microsoft.NETCore.App.deps.json`) lists exactly
that package as its only library, and self-contained apps list `runtimepack.<same name>` -- so the
generic deps.json parser yields correct runtime components with the right RID and no extra rules.
They are emitted as library components (not CAT_RUNTIME: engine/match.py only does package matching for
library/os-package categories) with meta runtime=True.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

from ...models import Component
from .base import EV_INSTALLED, EV_LOCKFILE, EV_MANIFEST, LangParser, basename, dedupe, library, register

_RUNTIME_PACK = re.compile(
    r"^Microsoft\.(NETCore|AspNetCore|WindowsDesktop)\.App\.Runtime\.[\w.\-]+$", re.IGNORECASE)


def _nuget(name: str, version: str, path: str, evidence: str, parser: str, **meta) -> Component:
    if _RUNTIME_PACK.match(name):
        meta["runtime"] = True
    return library("nuget", name, version, path=path, evidence=evidence, parser=parser, **meta)


def _split_lib(key: str) -> tuple[str, str] | None:
    name, sep, ver = key.rpartition("/")
    return (name, ver) if sep and name and ver else None


def _strip_ns(root: ET.Element) -> ET.Element:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def _xml(data: bytes) -> ET.Element:
    return _strip_ns(ET.fromstring(data))


# ---------------------------------------------------------------------------- *.deps.json
def parse_deps_json(path: str, data: bytes) -> list[Component]:
    d = json.loads(data)
    libs = d.get("libraries") or {}
    targets = d.get("targets") or {}
    rt = (d.get("runtimeTarget") or {}).get("name")
    target = targets.get(rt) if rt else None
    if not target:   # fall back to the largest target (the RID-specific one)
        target = max(targets.values(), key=len, default={}) if targets else {}
    keys = list(target) if target else list(libs)
    tfm = rt.split("/")[0] if rt else None
    out = []
    for key in dict.fromkeys(keys + ([] if target else list(libs))):
        split = _split_lib(key)
        if not split:
            continue
        name, ver = split
        typ = (libs.get(key) or target.get(key) or {}).get("type")
        if typ == "runtimepack" or name.startswith("runtimepack."):
            name = name.removeprefix("runtimepack.")
            typ = "package"
        if typ != "package":          # project / reference / referenceassembly -> not a NuGet package
            continue
        out.append(_nuget(name, ver, path, EV_INSTALLED, "dotnet-deps-json", runtime_target=rt, tfm=tfm))
    return dedupe(out)


register(LangParser(name="dotnet-deps-json", ecosystem="NuGet", evidence=EV_INSTALLED,
                    match=lambda p: p.endswith(".deps.json"), parse=parse_deps_json))


# ---------------------------------------------------------------------------- packages.lock.json
def parse_packages_lock(path: str, data: bytes) -> list[Component]:
    d = json.loads(data)
    merged: dict[tuple[str, str], Component] = {}
    for tfm, pkgs in (d.get("dependencies") or {}).items():
        for name, info in (pkgs or {}).items():
            typ = info.get("type")
            ver = info.get("resolved")
            if typ == "Project" or not ver:
                continue
            c = _nuget(name, ver, path, EV_LOCKFILE, "dotnet-packages-lock", direct=(typ == "Direct"), tfms=[tfm])
            prev = merged.get((name.lower(), ver))
            if prev:
                prev.meta["tfms"].append(tfm)
                prev.meta["direct"] = prev.meta.get("direct", False) or typ == "Direct"
            else:
                merged[(name.lower(), ver)] = c
    return list(merged.values())


register(LangParser(name="dotnet-packages-lock", ecosystem="NuGet", evidence=EV_LOCKFILE,
                    match=lambda p: basename(p) == "packages.lock.json", parse=parse_packages_lock))


# ---------------------------------------------------------------------------- obj/project.assets.json
def parse_project_assets(path: str, data: bytes) -> list[Component]:
    d = json.loads(data)
    direct: set[str] = set()
    for deps in (d.get("projectFileDependencyGroups") or {}).values():
        for spec in deps:
            direct.add(spec.split(" ", 1)[0].lower())
    out = []
    for key, info in (d.get("libraries") or {}).items():
        split = _split_lib(key)
        if not split or info.get("type") != "package":
            continue
        out.append(_nuget(split[0], split[1], path, EV_LOCKFILE, "dotnet-project-assets",
                          direct=split[0].lower() in direct))
    return dedupe(out)


register(LangParser(name="dotnet-project-assets", ecosystem="NuGet", evidence=EV_LOCKFILE,
                    match=lambda p: basename(p) == "project.assets.json", parse=parse_project_assets))


# ---------------------------------------------------------------------------- packages.config
def parse_packages_config(path: str, data: bytes) -> list[Component]:
    root = _xml(data)
    out = []
    for p in root.iter("package"):
        pid, ver = p.get("id"), p.get("version")
        if pid and ver:
            out.append(_nuget(pid, ver, path, EV_LOCKFILE, "dotnet-packages-config",
                              tfm=p.get("targetFramework"),
                              development=True if p.get("developmentDependency", "").lower() == "true" else None))
    return dedupe(out)


register(LangParser(name="dotnet-packages-config", ecosystem="NuGet", evidence=EV_LOCKFILE,
                    match=lambda p: basename(p) == "packages.config", parse=parse_packages_config))


# ---------------------------------------------------------------------------- project files
_PROP = re.compile(r"\$\(([^)]+)\)")


def _msbuild_props(root: ET.Element) -> dict[str, str]:
    props: dict[str, str] = {}
    for pg in root.iter("PropertyGroup"):
        for p in pg:
            if isinstance(p.tag, str) and p.text and p.text.strip():
                props.setdefault(p.tag, p.text.strip())
    return props


def _exact_version(v: str | None, props: dict[str, str]) -> str | None:
    """Literal or $(Property) version; None for floating (`1.*`), ranges (`[1.0,2.0)`) or unresolved."""
    if not v:
        return None
    v = v.strip()
    for _ in range(5):
        new = _PROP.sub(lambda m: props.get(m[1], m[0]), v)
        if new == v:
            break
        v = new
    if "$(" in v or "*" in v:
        return None
    if v.startswith("[") and v.endswith("]") and "," not in v:   # [1.2.3] == exactly 1.2.3
        v = v[1:-1].strip()
    if not v or re.search(r"[\[\](),\s]", v):
        return None
    return v


def _package_items(root: ET.Element, tags: tuple[str, ...], path: str, parser: str, **extra) -> list[Component]:
    props = _msbuild_props(root)
    out = []
    for el in root.iter():
        if el.tag not in tags:
            continue
        name = el.get("Include") or el.get("Update")
        if not name or "$(" in name or "*" in name:
            continue
        ver = el.get("Version") or el.get("VersionOverride")
        if ver is None:
            for child in el:
                if child.tag in ("Version", "VersionOverride") and child.text:
                    ver = child.text
                    break
        ver = _exact_version(ver, props)
        if not ver:
            continue
        private = el.get("PrivateAssets") or next((c.text for c in el if c.tag == "PrivateAssets" and c.text), "")
        out.append(_nuget(name.strip(), ver, path, EV_MANIFEST, parser,
                          development=True if private.strip().lower() == "all" else None, **extra))
    return dedupe(out)


def parse_project_file(path: str, data: bytes) -> list[Component]:
    return _package_items(_xml(data), ("PackageReference",), path, "dotnet-project-file")


def parse_central_packages(path: str, data: bytes) -> list[Component]:
    """Directory.Packages.props (central package management). Lists *available* versions; a project may
    not reference all of them -> meta declared_only."""
    return _package_items(_xml(data), ("PackageVersion", "GlobalPackageReference"), path,
                          "dotnet-central-packages", central=True, declared_only=True)


register(LangParser(
    name="dotnet-project-file", ecosystem="NuGet", evidence=EV_MANIFEST,
    match=lambda p: p.lower().endswith((".csproj", ".fsproj", ".vbproj")) or basename(p) in (
        "Directory.Build.props", "Directory.Build.targets"),
    parse=parse_project_file))

register(LangParser(name="dotnet-central-packages", ecosystem="NuGet", evidence=EV_MANIFEST,
                    match=lambda p: basename(p).lower() == "directory.packages.props",
                    parse=parse_central_packages))
