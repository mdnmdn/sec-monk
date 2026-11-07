"""Version comparison per ecosystem, delegated to `univers` (ADR-0001).

`compare(a, b, scheme)` returns -1/0/1. Unparseable versions fall back to a tolerant
generic comparator (numeric segments compared as ints) so that a weird vendor version never
crashes a scan; the caller lowers confidence in that case (see engine/match.py).
"""

from __future__ import annotations

import re
from functools import lru_cache

from univers import versions as uv

# OSV ecosystem (prefix before ':') -> univers class
_ECOSYSTEM_SCHEME: dict[str, type[uv.Version]] = {
    "PyPI": uv.PypiVersion,
    "npm": uv.SemverVersion,
    "Maven": uv.MavenVersion,
    "Go": uv.GolangVersion,
    "crates.io": uv.SemverVersion,
    "RubyGems": uv.RubygemsVersion,
    "NuGet": uv.NugetVersion,
    "Packagist": uv.ComposerVersion,
    "Pub": uv.SemverVersion,
    "Hex": uv.SemverVersion,
    "Debian": uv.DebianVersion,
    "Ubuntu": uv.DebianVersion,
    "Alpine": uv.AlpineLinuxVersion,
    "Wolfi": uv.AlpineLinuxVersion,
    "Chainguard": uv.AlpineLinuxVersion,
    "Alpaquita": uv.AlpineLinuxVersion,
    "Red Hat": uv.RpmVersion,
    "Rocky Linux": uv.RpmVersion,
    "AlmaLinux": uv.RpmVersion,
    "openSUSE": uv.RpmVersion,
    "SUSE": uv.RpmVersion,
    "Mageia": uv.RpmVersion,
    "Azure Linux": uv.RpmVersion,
    "Photon OS": uv.RpmVersion,
    "openEuler": uv.RpmVersion,
}

_SCHEME_BY_NAME: dict[str, type[uv.Version]] = {
    "semver": uv.SemverVersion,
    "pypi": uv.PypiVersion,
    "maven": uv.MavenVersion,
    "deb": uv.DebianVersion,
    "rpm": uv.RpmVersion,
    "apk": uv.AlpineLinuxVersion,
}


def scheme_for_ecosystem(ecosystem: str | None) -> str:
    """Return a scheme name usable with `compare` for an OSV ecosystem string."""
    if not ecosystem:
        return "generic"
    base = ecosystem.split(":", 1)[0]
    return f"eco:{base}" if base in _ECOSYSTEM_SCHEME else "generic"


def _cls(scheme: str) -> type[uv.Version] | None:
    if scheme.startswith("eco:"):
        return _ECOSYSTEM_SCHEME.get(scheme[4:])
    return _SCHEME_BY_NAME.get(scheme)


_TOKEN = re.compile(r"\d+|[a-zA-Z]+")


def _generic_key(v: str) -> tuple:
    # 'v1.2.3-beta1' -> ((1,1),(1,2),(1,3),(0,'beta'),(1,1)); numbers sort above words
    # so that '1.2.3' > '1.2.3-beta' is NOT guaranteed — acceptable for a fallback.
    v = v.strip().lstrip("vV")
    out = []
    for tok in _TOKEN.findall(v):
        out.append((1, int(tok)) if tok.isdigit() else (0, tok.lower()))
    return tuple(out)


def _generic_cmp(a: str, b: str) -> int:
    ka, kb = _generic_key(a), _generic_key(b)
    # pad with zeros so 1.2 == 1.2.0
    n = max(len(ka), len(kb))
    ka += ((1, 0),) * (n - len(ka))
    kb += ((1, 0),) * (n - len(kb))
    return (ka > kb) - (ka < kb)


@lru_cache(maxsize=200_000)
def _parse(cls: type[uv.Version], v: str) -> uv.Version | None:
    try:
        if cls is uv.SemverVersion:
            v = v.lstrip("v")
        return cls(v)
    except Exception:
        return None


def compare(a: str, b: str, scheme: str = "generic") -> int:
    """Compare two version strings. Returns -1, 0 or 1."""
    if a == b:
        return 0
    cls = _cls(scheme)
    if cls is not None:
        pa, pb = _parse(cls, a), _parse(cls, b)
        if pa is not None and pb is not None:
            try:
                return (pa > pb) - (pa < pb)
            except Exception:
                pass
    return _generic_cmp(a, b)


def is_parseable(v: str, scheme: str) -> bool:
    cls = _cls(scheme)
    return cls is None or _parse(cls, v) is not None


def in_osv_range(version: str, events: list[dict], scheme: str) -> bool:
    """Evaluate an OSV ECOSYSTEM/SEMVER range (list of events) for `version`.

    OSV semantics: events sorted by version; 'introduced' opens an affected interval,
    'fixed' closes it (exclusive), 'last_affected' closes it (inclusive), 'limit' caps it.
    introduced "0" means "since the beginning".
    """
    if not events:
        return False
    intervals: list[tuple[str | None, str | None, bool]] = []  # (start, end, end_inclusive)
    start: str | None = None
    opened = False
    limit: str | None = None
    for ev in events:
        if "introduced" in ev:
            start = None if ev["introduced"] in ("0", "") else ev["introduced"]
            opened = True
        elif "fixed" in ev and opened:
            intervals.append((start, ev["fixed"], False))
            opened = False
        elif "last_affected" in ev and opened:
            intervals.append((start, ev["last_affected"], True))
            opened = False
        elif "limit" in ev:
            limit = ev["limit"]
    if opened:
        intervals.append((start, None, False))
    if limit and limit != "*" and compare(version, limit, scheme) >= 0:
        return False
    for lo, hi, inclusive in intervals:
        if lo is not None and compare(version, lo, scheme) < 0:
            continue
        if hi is None:
            return True
        c = compare(version, hi, scheme)
        if c < 0 or (inclusive and c == 0):
            return True
    return False


def first_fixed_after(version: str, events: list[dict], scheme: str) -> str | None:
    """Smallest 'fixed' version greater than `version` (the upgrade target), if any."""
    fixes = [e["fixed"] for e in events if "fixed" in e and compare(e["fixed"], version, scheme) > 0]
    if not fixes:
        return None
    best = fixes[0]
    for f in fixes[1:]:
        if compare(f, best, scheme) < 0:
            best = f
    return best
