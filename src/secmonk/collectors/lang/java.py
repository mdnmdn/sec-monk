"""Java parsers: jar/war/ear archives (incl. Spring Boot fat jars and shaded jars), pom.xml,
Gradle lockfiles and Gradle dependency-verification metadata.

PURL / OSV mapping: `pkg:maven/<group>/<artifact>@<version>` -> OSV ecosystem "Maven", package
name "group:artifact" (the Component name is "group:artifact", which is what engine/match.py looks up).

Archive identification, strongest first (see _docs/references/package-formats/java.md):
  1. META-INF/maven/<g>/<a>/pom.properties   -> exact g:a:v, evidence `binary`, confidence 1.0.
     Shaded/uber jars contain one per embedded artifact; all are emitted.
  2. META-INF/MANIFEST.MF                    -> version from Implementation-Version / Bundle-Version,
     artifactId from the filename (when its version corroborates) or Bundle-SymbolicName; group from
     Implementation-Vendor-Id / Bundle-SymbolicName. identified_by=manifest, confidence 0.7 (group
     known) or 0.4 with needs_identification=True (group unknown -> purl without namespace).
  3. Filename `artifact-1.2.3.jar`           -> identified_by=filename, confidence 0.4, group unknown
     -> needs_identification=True.
Nested jars (BOOT-INF/lib, WEB-INF/lib, lib/ …) are opened recursively (depth <= 3).
"""

from __future__ import annotations

import io
import logging
import re
import xml.etree.ElementTree as ET
import zipfile

from ...models import Component
from .base import EV_BINARY, EV_LOCKFILE, EV_MANIFEST, LangParser, basename, dedupe, library, register

log = logging.getLogger(__name__)

ARCHIVE_EXTS = (".jar", ".war", ".ear", ".hpi", ".jpi", ".par")
NESTED_EXTS = ARCHIVE_EXTS
MAX_DEPTH = 3                          # nesting levels below the outer archive
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024  # declared uncompressed total per archive (and read budget per tree)
MAX_ENTRY_BYTES = 128 * 1024 * 1024    # nested archives / metadata entries larger than this are skipped
MAX_ENTRIES = 200_000
_POM_PROPS = re.compile(r"^META-INF/maven/([^/]+)/([^/]+)/pom\.properties$")
_FILENAME = re.compile(r"^(?P<a>[A-Za-z0-9_.+\-]*?[A-Za-z0-9_])-(?P<v>\d[\w.+\-]*)$")
_SKIP_SUFFIX = re.compile(r"-(sources|javadoc|tests?|test-sources)$", re.IGNORECASE)


# ---------------------------------------------------------------------------- helpers
def _parse_props(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        k, sep, v = line.partition("=")
        if sep:
            out[k.strip()] = v.strip()
    return out


def _parse_manifest(text: str) -> dict[str, str]:
    """MANIFEST.MF main section: 'Key: value', continuation lines start with one space."""
    out: dict[str, str] = {}
    key = None
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line == "":
            if out:
                break          # end of main section
            continue
        if line.startswith(" ") and key:
            out[key] += line[1:]
            continue
        k, sep, v = line.partition(":")
        if sep:
            key = k.strip()
            out.setdefault(key, v.strip())
    return out


def _filename_ga(path_in_archive: str) -> tuple[str, str] | None:
    stem = basename(path_in_archive.split("!/")[-1])
    for ext in ARCHIVE_EXTS:
        if stem.lower().endswith(ext):
            stem = stem[: -len(ext)]
            break
    if _SKIP_SUFFIX.search(stem):
        return None
    m = _FILENAME.match(stem)
    return (m["a"], m["v"]) if m else None


def _group_from_manifest(mf: dict[str, str], artifact: str | None) -> str | None:
    """Group is only taken from evidence that really is a group: Implementation-Vendor-Id (a reverse-DNS
    id such as `org.apache.logging.log4j`), or a Bundle-SymbolicName / Automatic-Module-Name whose last
    segment *is* the artifactId (`com.acme.widgets` for artifact `widgets` -> `com.acme`). Anything else
    (e.g. `org.apache.commons.lang3` for `commons-lang3`) is a guess that would be wrong as often as
    right, so the group stays unknown."""
    vendor_id = mf.get("Implementation-Vendor-Id")
    if vendor_id and "." in vendor_id and " " not in vendor_id:
        return vendor_id
    for key in ("Bundle-SymbolicName", "Automatic-Module-Name"):
        sym = (mf.get(key) or "").split(";")[0].strip()
        head, _, last = sym.rpartition(".")
        if artifact and head.count(".") >= 1 and last.lower() == artifact.lower():
            return head
    return None


def _manifest_identity(mf: dict[str, str], archive_path: str) -> tuple[str | None, str | None, str | None]:
    """-> (group, artifact, version) best guess from the manifest + filename."""
    version = mf.get("Implementation-Version") or mf.get("Bundle-Version")
    fn = _filename_ga(archive_path)
    artifact = None
    if fn and (version is None or fn[1] == version or version.startswith(fn[1]) or fn[1].startswith(version)):
        artifact = fn[0]
        version = version or fn[1]
    if artifact is None:
        title = mf.get("Implementation-Title") or mf.get("Bundle-Name") or ""
        if re.fullmatch(r"[A-Za-z0-9_\-]+", title):
            artifact = title
        else:
            sym = (mf.get("Bundle-SymbolicName") or mf.get("Automatic-Module-Name") or "").split(";")[0].strip()
            artifact = sym.rsplit(".", 1)[-1] if sym else None
    return _group_from_manifest(mf, artifact), artifact, version


class _Budget:
    def __init__(self) -> None:
        self.left = MAX_ARCHIVE_BYTES


def _check_zip(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        raise ValueError(f"archive has {len(infos)} entries (> {MAX_ENTRIES})")
    total = sum(i.file_size for i in infos)
    if total > MAX_ARCHIVE_BYTES:
        raise ValueError(f"archive declares {total} uncompressed bytes (> {MAX_ARCHIVE_BYTES}); skipped")
    return infos


def _read(zf: zipfile.ZipFile, info: zipfile.ZipInfo, budget: _Budget) -> bytes | None:
    """Bounded read (zipfile never yields more than the declared size)."""
    if info.file_size > MAX_ENTRY_BYTES or info.file_size > budget.left:
        return None
    budget.left -= info.file_size
    return zf.read(info)


# ---------------------------------------------------------------------------- archives
def _scan_archive(display: str, data: bytes, depth: int, budget: _Budget, parent: str | None,
                  out: list[Component]) -> None:
    zf = zipfile.ZipFile(io.BytesIO(data))
    infos = _check_zip(zf)
    by_name = {i.filename: i for i in infos if not i.is_dir()}

    base_meta = {"parent": parent} if parent else {}
    poms = [(m, by_name[n]) for n in by_name if (m := _POM_PROPS.match(n))]
    found = False
    stem = basename(display.split("!/")[-1]).lower()
    for m, info in poms:
        raw = _read(zf, info, budget)
        if raw is None:
            continue
        props = _parse_props(raw.decode("utf-8", "replace"))
        group, artifact, version = (props.get("groupId") or m[1], props.get("artifactId") or m[2],
                                    props.get("version"))
        if not version or "${" in version:
            continue
        meta = dict(base_meta, identified_by="pom.properties", confidence=1.0)
        if len(poms) > 1 and artifact.lower() not in stem:   # not the jar's own artifact -> bundled/shaded
            meta["shaded"] = True
        out.append(library("maven", artifact, version, namespace=group, path=display, evidence=EV_BINARY,
                           parser="java-archive", **meta))
        found = True

    if not found:
        fn = _filename_ga(display)
        mf_info = by_name.get("META-INF/MANIFEST.MF")
        mf = {}
        if mf_info is not None:
            raw = _read(zf, mf_info, budget)
            mf = _parse_manifest(raw.decode("utf-8", "replace")) if raw else {}
        ident = None
        if mf:
            group, artifact, version = _manifest_identity(mf, display)
            if artifact and version:
                ident = (group, artifact, version, "manifest")
        if ident is None and fn:
            ident = (None, fn[0], fn[1], "filename")
        if ident:
            group, artifact, version, how = ident
            confidence = 0.7 if (how == "manifest" and group) else 0.4
            meta = dict(base_meta, identified_by=how, confidence=confidence)
            if not group:
                meta["needs_identification"] = True
            out.append(library("maven", artifact, version, namespace=group, path=display, evidence=EV_BINARY,
                               parser="java-archive", **meta))

    # nested archives
    if depth >= MAX_DEPTH:
        return
    for name, info in by_name.items():
        if not name.lower().endswith(NESTED_EXTS):
            continue
        if info.file_size > MAX_ENTRY_BYTES:
            log.warning("%s!/%s skipped: %d bytes > per-entry cap", display, name, info.file_size)
            continue
        raw = _read(zf, info, budget)
        if raw is None or raw[:4] != b"PK\x03\x04":
            continue
        try:
            _scan_archive(f"{display}!/{name}", raw, depth + 1, budget, display, out)
        except (zipfile.BadZipFile, ValueError, OSError) as e:
            log.warning("%s!/%s skipped: %s", display, name, e)


def parse_archive(path: str, data: bytes) -> list[Component]:
    out: list[Component] = []
    _scan_archive(path, data, 0, _Budget(), None, out)
    return dedupe(out)


register(LangParser(
    name="java-archive", ecosystem="Maven", evidence=EV_BINARY,
    match=lambda p: p.lower().endswith(ARCHIVE_EXTS),
    sniff=lambda head: head[:4] == b"PK\x03\x04",
    parse=parse_archive, max_bytes=MAX_ARCHIVE_BYTES, binary=True))


# ---------------------------------------------------------------------------- pom.xml
def _strip_ns(root: ET.Element) -> ET.Element:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def _text(el: ET.Element | None, tag: str) -> str | None:
    if el is None:
        return None
    c = el.find(tag)
    return c.text.strip() if c is not None and c.text and c.text.strip() else None


_PROP = re.compile(r"\$\{([^}]+)\}")


def _resolve(value: str | None, props: dict[str, str]) -> str | None:
    if value is None:
        return None
    for _ in range(8):
        new = _PROP.sub(lambda m: props.get(m[1], m[0]), value)
        if new == value:
            break
        value = new
    return None if "${" in value else value


def parse_pom(path: str, data: bytes) -> list[Component]:
    root = _strip_ns(ET.fromstring(data))
    props: dict[str, str] = {}
    pr = root.find("properties")
    if pr is not None:
        for p in pr:
            if isinstance(p.tag, str) and p.text:
                props[p.tag] = p.text.strip()
    parent = root.find("parent")
    version = _text(root, "version") or _text(parent, "version")
    group = _text(root, "groupId") or _text(parent, "groupId")
    for k, v in (("project.version", version), ("pom.version", version), ("version", version),
                 ("project.groupId", group), ("pom.groupId", group), ("groupId", group),
                 ("project.artifactId", _text(root, "artifactId")),
                 ("project.parent.version", _text(parent, "version")),
                 ("parent.version", _text(parent, "version")),
                 ("project.parent.groupId", _text(parent, "groupId"))):
        if v:
            props.setdefault(k, v)
    out: list[Component] = []
    deps = root.find("dependencies")           # NOT dependencyManagement, plugins or profiles
    for d in (deps if deps is not None else []):
        if d.tag != "dependency":
            continue
        g = _resolve(_text(d, "groupId"), props)
        a = _resolve(_text(d, "artifactId"), props)
        v = _resolve(_text(d, "version"), props)
        if not (g and a and v) or re.search(r"[\[\](),]", v) or v in ("LATEST", "RELEASE"):
            continue
        scope = _text(d, "scope")
        typ = _text(d, "type")
        quals = {"type": typ if typ and typ != "jar" else None, "classifier": _text(d, "classifier")}
        out.append(library("maven", a, v, namespace=g, path=path, evidence=EV_MANIFEST, parser="maven-pom",
                           qualifiers=quals, scope=scope, optional=True if _text(d, "optional") == "true" else None))
    return out


register(LangParser(name="maven-pom", ecosystem="Maven", evidence=EV_MANIFEST,
                    match=lambda p: basename(p) == "pom.xml", parse=parse_pom))


# ---------------------------------------------------------------------------- gradle
def parse_gradle_lockfile(path: str, data: bytes) -> list[Component]:
    """`group:artifact:version=conf1,conf2` (gradle.lockfile) or bare `group:artifact:version`
    (legacy gradle/dependency-locks/<conf>.lockfile)."""
    out: list[Component] = []
    legacy_conf = basename(path)[: -len(".lockfile")] if "dependency-locks/" in path else None
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "empty=")):
            continue
        coord, _, confs = line.partition("=")
        parts = coord.split(":")
        if len(parts) < 3:
            continue
        g, a, v = parts[0], parts[1], parts[2]
        configs = [c for c in confs.split(",") if c] or ([legacy_conf] if legacy_conf else [])
        scope = "test" if configs and all("test" in c.lower() for c in configs) else None
        out.append(library("maven", a, v, namespace=g, path=path, evidence=EV_LOCKFILE, parser="gradle-lockfile",
                           configurations=configs or None, scope=scope))
    return dedupe(out)


register(LangParser(
    name="gradle-lockfile", ecosystem="Maven", evidence=EV_LOCKFILE,
    match=lambda p: basename(p) in ("gradle.lockfile", "buildscript-gradle.lockfile")
    or ("gradle/dependency-locks/" in p and p.endswith(".lockfile")),
    parse=parse_gradle_lockfile))


def parse_gradle_verification(path: str, data: bytes) -> list[Component]:
    root = _strip_ns(ET.fromstring(data))
    out: list[Component] = []
    for c in root.iter("component"):
        g, a, v = c.get("group"), c.get("name"), c.get("version")
        if g and a and v:
            out.append(library("maven", a, v, namespace=g, path=path, evidence=EV_LOCKFILE,
                               parser="gradle-verification-metadata"))
    return dedupe(out)


register(LangParser(
    name="gradle-verification-metadata", ecosystem="Maven", evidence=EV_LOCKFILE,
    match=lambda p: p.endswith("gradle/verification-metadata.xml") or p == "verification-metadata.xml",
    parse=parse_gradle_verification))
