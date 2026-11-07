"""Prioritization — draft rules from vision §8. Thresholds are deliberately simple; tune them
once real data is in (see _docs/tech/engine/matching.md#prioritization)."""

from __future__ import annotations

EPSS_HIGH = 0.1


def priority(*, cvss: float | None, epss: float | None, kev: bool, asset_meta: dict | None = None) -> str:
    meta = asset_meta or {}
    exposed = bool(meta.get("internet_facing") or meta.get("exposed"))
    production = meta.get("env") in ("prod", "production")
    epss = epss or 0.0
    cvss = cvss or 0.0
    if kev:
        level = 1
    elif epss >= EPSS_HIGH and exposed:
        level = 1
    elif cvss >= 9 and exposed:
        level = 2
    elif epss >= EPSS_HIGH:
        level = 2
    elif cvss >= 7:
        level = 3
    else:
        level = 4
    # modifiers raise priority by one step each (never above P1)
    level -= int(production) + int(exposed and level > 2)
    return f"P{max(1, level)}"
