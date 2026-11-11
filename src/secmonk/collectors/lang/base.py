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

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ...engine import purl as purls
from ...models import CAT_LIBRARY, Component

# evidence kinds, strongest first (used for de-duplication: keep the strongest)
EV_INSTALLED = "installed"    # package metadata of what is actually on disk (dist-info, node_modules, vendor/)
EV_BINARY = "binary"          # embedded build info (Go buildinfo, cargo-auditable, jar pom.properties)
EV_LOCKFILE = "lockfile"      # resolved versions (package-lock, poetry.lock, Cargo.lock, go.sum…)
EV_MANIFEST = "manifest"      # declared dependencies with a pinned version (requirements ==, csproj, pom)
EVIDENCE_RANK = {EV_INSTALLED: 0, EV_BINARY: 1, EV_LOCKFILE: 2, EV_MANIFEST: 3}

MAX_PARSE_BYTES = 64 * 1024 * 1024

# A parser returns either the components, or (components, warnings) when it has something to tell
# the user without failing (e.g. "looks like a Go binary but no build info found").
# Directories that hold *someone else's* code: lockfiles / manifests found inside are not evidence
# about the scanned project (installed-package metadata and binaries still are).
VENDORED_DIRS = frozenset({"node_modules", "site-packages", "dist-packages", "vendor", ".pub-cache"})
# SwiftPM checkouts: `.build/checkouts/<repo>` (swift build), `SourcePackages/checkouts/<repo>` (Xcode)
_VENDORED_PAIRS = ((".cargo", "registry"), (".cargo", "git"), (".build", "checkouts"),
                   ("SourcePackages", "checkouts"))


def is_vendored(path: str) -> bool:
    """True when `path` lies inside a dependency directory (node_modules, site-packages, dist-packages,
    vendor/, .pub-cache, .cargo/registry, SwiftPM checkouts). Composer's own `vendor/composer/installed.json` is installed-metadata
    (EV_INSTALLED) and therefore never filtered by this."""
    parts = path.split("/")[:-1]
    if any(p in VENDORED_DIRS for p in parts):
        return True
    return any(parts[i:i + 2] == list(pair) for pair in _VENDORED_PAIRS for i in range(len(parts) - 1))


@dataclass(frozen=True)
class LangParser:
    name: str                                   # e.g. 'npm-package-lock'
    ecosystem: str                              # OSV ecosystem: npm, PyPI, Go, crates.io, NuGet, Maven, Packagist, ...
    evidence: str                               # EV_* constant
    match: Callable[[str], bool]                # relative posix path -> candidate?
    parse: Callable[[str, bytes], Any]          # -> list[Component] | (list[Component], list[str])
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
    vendored = is_vendored(path)
    return any(p.match(path) for p in REGISTRY
               if not (vendored and p.evidence in (EV_LOCKFILE, EV_MANIFEST)))


def parsers_for(path: str, head: bytes = b"") -> list[LangParser]:
    vendored = is_vendored(path)
    out = []
    for p in REGISTRY:
        if vendored and p.evidence in (EV_LOCKFILE, EV_MANIFEST):
            continue                    # vendored lockfiles / manifests are not project evidence
        if p.match(path) and (p.sniff is None or p.sniff(head[:512])):
            out.append(p)
    return out


def library(ecosystem_purl_type: str, name: str, version: str | None, *, path: str, evidence: str,
            parser: str, namespace: str | None = None, qualifiers: dict | None = None,
            **meta) -> Component:
    """Build a library Component with a PURL; ecosystem is derived from the purl type by classify()."""
    # NuGet ids are case-insensitive; the purl spec lowercases them and OSV stores them lowercase
    purl_name = name.lower() if ecosystem_purl_type == "nuget" else name
    purl = purls.build(ecosystem_purl_type, purl_name, version or None, namespace=namespace,
                       qualifiers=qualifiers)
    m = {"evidence": evidence, "parser": parser}
    m.update({k: v for k, v in meta.items() if v is not None})
    display = f"{namespace}/{name}" if namespace and ecosystem_purl_type in ("npm", "composer", "golang", "swift") \
        else (f"{namespace}:{name}" if namespace and ecosystem_purl_type == "maven" else name)
    return Component(name=display, version=version or None, category=CAT_LIBRARY, purl=purl,
                     ecosystem=purls.PURL_TO_OSV.get(ecosystem_purl_type), source_path=path, meta=m)


def safe_library(*args, **kwargs) -> Component | None:
    """`library()` that returns None instead of raising on a malformed entry (bad purl / empty name),
    so one broken entry cannot discard the rest of a file's components."""
    try:
        return library(*args, **kwargs)
    except ValueError:
        return None


def push(out: list[Component], comp: Component | None) -> None:
    """Append `comp` unless it is None (a `safe_library` that rejected a malformed entry)."""
    if comp is not None:
        out.append(comp)


def _go_at_least(v: str | None, want: tuple[int, int]) -> bool:
    m = re.match(r"(\d+)\.(\d+)", v or "")
    return bool(m) and (int(m[1]), int(m[2])) >= want


def _dirname(path: str | None) -> str:
    return (path or "").rsplit("/", 1)[0] if "/" in (path or "") else ""


def drop_shadowed(components: list[Component]) -> list[Component]:
    """Cross-file rules that a single-file parser cannot apply:
    go.sum lists every module version ever resolved, so when a go.mod sits in the same directory
    its go.sum entries are dropped (go.mod is the build list) -- but only for `go` >= 1.17: older
    go.mod files do not list indirect dependencies, so there go.sum is the more complete list."""
    gomod_dirs = {_dirname(c.source_path) for c in components
                  if c.meta.get("parser") == "go-mod" and _go_at_least(c.meta.get("go"), (1, 17))}
    if not gomod_dirs:
        return components
    return [c for c in components
            if not (c.meta.get("gosum") and _dirname(c.source_path) in gomod_dirs)]


_ALL_FLAGS = ("dev", "optional", "dev_optional", "peer")


def dedupe(components: list[Component]) -> list[Component]:
    """Merge components with the same purl (+version); keep strongest evidence, remember all paths.
    The scope flags dev / optional / dev_optional / peer survive only if *every* merged instance has
    them (a package that is also a production dependency somewhere is not dev-only)."""
    components = drop_shadowed(components)
    best: dict[str, Component] = {}
    seen: dict[str, list[Component]] = {}
    for c in components:
        key = c.purl or c.key
        seen.setdefault(key, []).append(c)
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
    for key, winner in best.items():
        group = seen[key]
        if len(group) < 2:
            continue
        for flag in _ALL_FLAGS:
            if all(g.meta.get(flag) for g in group):
                winner.meta[flag] = True
            else:
                winner.meta.pop(flag, None)
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
            res = p.parse(path, data)
            if isinstance(res, tuple):
                res, warns = res
                warnings.extend(f"{path}: {w}" for w in warns)
            comps.extend(res)
        except Exception as e:  # noqa: BLE001 - one bad file must not break a scan
            warnings.append(f"{path}: {p.name} failed: {type(e).__name__}: {e}")
    return comps, warnings
