"""Version comparison per ecosystem, delegated to `univers` (ADR-0001).

`compare(a, b, scheme)` returns -1/0/1. Unparseable versions fall back to a tolerant
generic comparator (numeric segments compared as ints) so that a weird vendor version never
crashes a scan; the caller lowers confidence in that case (see engine/match.py).
"""

from __future__ import annotations

import re
from functools import cmp_to_key, lru_cache

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

# Generic comparator token ranks (higher sorts later):
#   number > post-release word > padding/final > pre-release word
_R_PRE, _R_FINAL, _R_POST, _R_NUM = 1, 2, 3, 4
_PRE_WORDS = {"dev": 0, "snapshot": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "m": 3, "milestone": 3,
              "preview": 4, "pre": 4, "rc": 5, "cr": 5}
_FINAL_WORDS = frozenset({"final", "ga", "release", "rel", "stable"})
_POST_ALIASES = {"pl": "p", "patch": "p", "post": "p", "patchlevel": "p"}
_PAD = (_R_FINAL, 0, "")


@lru_cache(maxsize=200_000)
def _generic_key(v: str) -> tuple:
    """Sort key of the tolerant comparator used for vendor/product versions.

    '1.0-rc1' < '1.0' == '1.0.0' == '1.0.Final' < '1.0p1' < '1.0a' < '1.0.1';
    '1.1.1w' > '1.1.1t'; 'a'/'b' are pre-release only after '-', '.' or '~' ('1.0-b2'),
    a letter glued to a number is a post-release letter (OpenSSL '1.1.1w')."""
    v = v.strip()
    if v[:1] in ("v", "V") and v[1:2].isdigit():
        v = v[1:]
    out: list[tuple] = []
    for m in _TOKEN.finditer(v):
        tok = m.group().lower()
        if tok.isdigit():
            out.append((_R_NUM, int(tok), ""))
            continue
        prev = v[m.start() - 1] if m.start() else ""
        if tok in _FINAL_WORDS:
            out.append(_PAD)
        elif tok in _PRE_WORDS and (len(tok) > 1 or prev in "-.~"):
            out.append((_R_PRE, _PRE_WORDS[tok], ""))
        else:
            out.append((_R_POST, 0, _POST_ALIASES.get(tok, tok)))
    # drop zero numbers / final markers that end a numeric group ('1.0.0-rc1' == '1.0-rc1', '1.2.Final' == '1.2')
    i = len(out) - 1
    while i >= 0:
        if (out[i] == (_R_NUM, 0, "") or out[i] == _PAD) and (i == len(out) - 1 or out[i + 1][0] != _R_NUM):
            del out[i]
        i -= 1
    return tuple(out)


def _generic_cmp(a: str, b: str) -> int:
    ka, kb = _generic_key(a), _generic_key(b)
    n = max(len(ka), len(kb))
    ka += (_PAD,) * (n - len(ka))
    kb += (_PAD,) * (n - len(kb))
    return (ka > kb) - (ka < kb)


@lru_cache(maxsize=200_000)
def _parse(cls: type[uv.Version], v: str) -> uv.Version | None:
    try:
        if cls is uv.SemverVersion:
            v = v.lstrip("v")
        return cls(v)
    except Exception:  # noqa: BLE001 - unparseable -> fallback comparator
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
            except Exception:  # noqa: BLE001, S110 - incomparable -> fallback
                pass
    return _generic_cmp(a, b)


_GENERIC_PARSEABLE = re.compile(r"^\s*[vV]?\d")


def is_parseable(v: str, scheme: str) -> bool:
    """True when `v` is a version of `scheme`. Generic versions must start with a digit
    (optionally 'v'): 'Version ??? (beta)' or 'build 2024' are not versions."""
    cls = _cls(scheme)
    if cls is None:
        return bool(_GENERIC_PARSEABLE.match(v or ""))
    return _parse(cls, v) is not None


_EVENT_ORDER = {"introduced": 0, "last_affected": 1, "fixed": 2, "limit": 3}


def _event(ev: dict) -> tuple[str, str] | None:
    for kind in _EVENT_ORDER:
        if kind in ev:
            return kind, str(ev[kind] if ev[kind] is not None else "")
    return None


def in_osv_range(version: str, events: list[dict], scheme: str) -> bool:
    """Evaluate an OSV ECOSYSTEM/SEMVER range (list of events) for `version`.

    Follows the OSV evaluation algorithm: events are sorted by version (introduced "0" first;
    on equal versions introduced < last_affected < fixed), then walked in order —
    `introduced` <= v sets affected (a second `introduced` while affected is a no-op),
    `fixed` <= v clears it, `last_affected` < v clears it. `limit` caps the whole range.
    The order of the events in the record does not matter.
    """
    evs = [e for e in (_event(ev) for ev in events or []) if e is not None]
    if not evs:
        return False

    def zero(kind: str, ver: str) -> bool:
        return kind == "introduced" and ver in ("0", "")

    def cmp(x: tuple[str, str], y: tuple[str, str]) -> int:
        zx, zy = zero(*x), zero(*y)
        if zx or zy:
            return (zy - zx) if zx != zy else 0
        c = compare(x[1], y[1], scheme)
        return c or (_EVENT_ORDER[x[0]] - _EVENT_ORDER[y[0]])

    limits = [v for k, v in evs if k == "limit" and v not in ("", "*")]
    if limits and all(compare(version, lim, scheme) >= 0 for lim in limits):
        return False
    affected = False
    for kind, ver in sorted(evs, key=cmp_to_key(cmp)):
        if kind == "introduced":
            affected = affected or zero(kind, ver) or compare(version, ver, scheme) >= 0
        elif kind == "fixed":
            affected = affected and compare(version, ver, scheme) < 0
        elif kind == "last_affected":
            affected = affected and compare(version, ver, scheme) <= 0
    return affected


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
