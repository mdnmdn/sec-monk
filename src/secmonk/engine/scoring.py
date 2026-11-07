"""Prioritization — draft rules from vision §8. Thresholds are deliberately simple; tune them
once real data is in (see _docs/tech/engine/matching.md, section "Prioritization")."""

from __future__ import annotations

EPSS_HIGH = 0.1


MINOR_TRIAGE = frozenset({"unimportant", "ignored", "end-of-life"})
DEFERRED_TRIAGE = frozenset({"no-dsa", "postponed"})

# Score assumed for a finding that only has a severity label (e.g. OSV records with a CVSS v4 vector
# only, whose numeric score is not computed): the lower bound of the CVSS band.
SEVERITY_SCORE = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 5.0, "MODERATE": 5.0, "LOW": 3.0}


def priority(*, cvss: float | None, epss: float | None, kev: bool, asset_meta: dict | None = None,
             triage: str | None = None, severity: str | None = None) -> str:
    """Priority P1..P4. Distro triage (Debian tracker / OSV urgency) caps it unless the CVE is in
    KEV: minor (unimportant, ignored, end-of-life) → P4; deferred (no-dsa, postponed) → at most P3.
    Without a CVSS score the severity label stands in (CRITICAL 9.0, HIGH 7.0, MEDIUM 5.0, LOW 3.0)."""
    if cvss is None and severity:
        cvss = SEVERITY_SCORE.get(severity.strip().upper())
    p = _base_priority(cvss=cvss, epss=epss, kev=kev, asset_meta=asset_meta)
    if kev or not triage:
        return p
    level = int(p[1])
    if triage in MINOR_TRIAGE:
        level = 4
    elif triage in DEFERRED_TRIAGE or triage == "low":
        level = max(level, 3)
    return f"P{level}"


def _base_priority(*, cvss: float | None, epss: float | None, kev: bool, asset_meta: dict | None = None) -> str:
    meta = asset_meta or {}
    exposed = bool(meta.get("internet_facing") or meta.get("exposed"))
    production = meta.get("env") in ("prod", "production")
    epss = epss or 0.0
    cvss = cvss or 0.0
    if kev or epss >= EPSS_HIGH and exposed:
        level = 1
    elif cvss >= 9 and exposed or epss >= EPSS_HIGH:
        level = 2
    elif cvss >= 7:
        level = 3
    else:
        level = 4
    # modifiers raise priority by one step each (never above P1)
    level -= int(production) + int(exposed and level > 2)
    return f"P{max(1, level)}"
