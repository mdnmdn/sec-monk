"""Language-dependency parsers: registry and helpers.

A *parser* turns one file (a lockfile, a manifest, installed-package metadata, or a binary with
embedded dependency info) into library `Component`s. Parsers are pure functions of
`(path, data)` so they work identically on:
  * a project folder / repository      (collectors/fs.py, DirView)
  * an image or container filesystem   (collectors/rootfs.py, docker_image.py, docker_engine.py)

Walkers ask the registry two questions:
  * `wants(path)`        — cheap path test: should this file be read at all?
  * `parsers_for(path, head)` — which parsers apply, given the path and the first bytes
                              (binaries are recognized by magic bytes, not by name).

See _docs/tech/collectors/dependencies.md and _docs/references/package-formats/.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ...engine import purl as purls
from ...models import CAT_LIBRARY, Component

# evidence kinds, strongest first (used for de-duplication: keep the strongest)
EV_INSTALLED = "installed"    # package metadata of what is actually on disk (dist-info, node_modules, vendor/)
EV_BINARY = "binary"          # embedded build info (Go buildinfo, cargo-auditable, jar pom.properties)
EV_LOCKFILE = "lockfile"      # resolved versions (package-lock, poetry.lock, Cargo.lock, go.sum…)
EV_MANIFEST = "manifest"      # declared dependencies with a pinned version (requirements ==, csproj, pom)
EVIDENCE_RANK = {EV_INSTALLED: 0, EV_BINARY: 1, EV_LOCKFILE: 2, EV_MANIFEST: 3}

MAX_PARSE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class LangParser:
    name: str                                   # e.g. 'npm-package-lock'
    ecosystem: str                              # OSV ecosystem: npm, PyPI, Go, crates.io, NuGet, Maven, Packagist
    evidence: str                               # EV_* constant
    match: Callable[[str], bool]                # relative posix path -> candidate?
    parse: Callable[[str, bytes], list[Component]]
    sniff: Callable[[bytes], bool] | None = None   # optional test on the first 512 bytes (binaries)
    max_bytes: int = MAX_PARSE_BYTES
    binary: bool = False                        # needs executable/archive content (walkers may cap these)


REGISTRY: list[LangParser] = []


def register(p: LangParser) -> LangParser:
    REGISTRY.append(p)
    return p


def basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def wants(path: str) -> bool:
    """Path-only pre-filter (no content). Binary parsers must match on path too (e.g. exec dirs)."""
    return any(p.match(path) for p in REGISTRY)


def parsers_for(path: str, head: bytes = b"") -> list[LangParser]:
    out = []
    for p in REGISTRY:
        if p.match(path) and (p.sniff is None or p.sniff(head[:512])):
            out.append(p)
    return out


def library(ecosystem_purl_type: str, name: str, version: str | None, *, path: str, evidence: str,
            parser: str, namespace: str | None = None, qualifiers: dict | None = None,
            **meta) -> Component:
    """Build a library Component with a PURL; ecosystem is derived from the purl type by classify()."""
    purl = purls.build(ecosystem_purl_type, name, version or None, namespace=namespace, qualifiers=qualifiers)
    m = {"evidence": evidence, "parser": parser}
    m.update({k: v for k, v in meta.items() if v is not None})
    display = f"{namespace}/{name}" if namespace and ecosystem_purl_type in ("npm", "composer", "golang") \
        else (f"{namespace}:{name}" if namespace and ecosystem_purl_type == "maven" else name)
    return Component(name=display, version=version or None, category=CAT_LIBRARY, purl=purl,
                     ecosystem=purls.PURL_TO_OSV.get(ecosystem_purl_type), source_path=path, meta=m)


def dedupe(components: list[Component]) -> list[Component]:
    """Merge components with the same purl (+version); keep strongest evidence, remember all paths."""
    best: dict[str, Component] = {}
    for c in components:
        key = c.purl or c.key
        prev = best.get(key)
        if prev is None:
            c.meta.setdefault("paths", [c.source_path] if c.source_path else [])
            best[key] = c
            continue
        paths = prev.meta.setdefault("paths", [])
        if c.source_path and c.source_path not in paths:
            paths.append(c.source_path)
        if EVIDENCE_RANK.get(c.meta.get("evidence"), 9) < EVIDENCE_RANK.get(prev.meta.get("evidence"), 9):
            c.meta["paths"] = paths
            best[key] = c
    return list(best.values())


def parse_file(path: str, data: bytes) -> tuple[list[Component], list[str]]:
    """Run every applicable parser on one file. Returns (components, warnings)."""
    comps: list[Component] = []
    warnings: list[str] = []
    for p in parsers_for(path, data[:512]):
        if len(data) > p.max_bytes:
            warnings.append(f"{path}: skipped by {p.name} (>{p.max_bytes} bytes)")
            continue
        try:
            comps.extend(p.parse(path, data))
        except Exception as e:  # noqa: BLE001 - one bad file must not break a scan
            warnings.append(f"{path}: {p.name} failed: {type(e).__name__}: {e}")
    return comps, warnings
