"""PURL helpers and PURL <-> OSV ecosystem mapping.

See _docs/tech/engine/classification.md and _docs/references/vuln-sources/osv.md.
"""

from __future__ import annotations

from packageurl import PackageURL

# purl type -> OSV ecosystem (language ecosystems; distro ones are computed from qualifiers)
PURL_TO_OSV = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
}

# distro id (os-release ID) -> OSV ecosystem base name
DISTRO_TO_OSV = {
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "alpine": "Alpine",
    "wolfi": "Wolfi",
    "chainguard": "Chainguard",
    "rhel": "Red Hat",
    "redhat": "Red Hat",
    "rocky": "Rocky Linux",
    "rocky-linux": "Rocky Linux",
    "almalinux": "AlmaLinux",
    "opensuse-leap": "openSUSE",
    "sles": "SUSE",
}


def normalize_ecosystem(ecosystem: str | None) -> str | None:
    """Collapse OSV ecosystem variants to the matching key stored in `affected.ecosystem`
    and `component.ecosystem`:

      'Ubuntu:22.04:LTS' / 'Ubuntu:Pro:18.04:LTS' -> 'Ubuntu:22.04' / 'Ubuntu:18.04'
      'Red Hat:enterprise_linux:9::appstream' / 'Red Hat:enterprise_linux:10.2' -> 'Red Hat:9' / 'Red Hat:10'
      'Rocky Linux:8', 'AlmaLinux:9', 'Debian:12', 'Alpine:v3.20', 'PyPI' -> unchanged
    """
    if not ecosystem:
        return ecosystem
    parts = ecosystem.split(":")
    base = parts[0]
    if base == "Ubuntu":
        rel = next((p for p in parts[1:] if p and p[0].isdigit()), None)
        return f"Ubuntu:{rel}" if rel else "Ubuntu"
    if base == "Red Hat":
        rel = next((p for p in parts[1:] if p and p[0].isdigit()), None)
        return f"Red Hat:{rel.split('.')[0]}" if rel else "Red Hat"
    if base in ("Rocky Linux", "AlmaLinux") and len(parts) > 1:
        return f"{base}:{parts[1].split('.')[0]}"
    return ecosystem


def osv_distro_ecosystem(distro_id: str, version_id: str | None) -> str | None:
    """Normalized OSV ecosystem for an installed distro (os-release ID / VERSION_ID), e.g.
    ('debian','12') -> 'Debian:12', ('alpine','3.20.3') -> 'Alpine:v3.20',
    ('ubuntu','22.04') -> 'Ubuntu:22.04', ('rhel','9.4') -> 'Red Hat:9'."""
    base = DISTRO_TO_OSV.get((distro_id or "").lower())
    if not base:
        return None
    if base in ("Wolfi", "Chainguard") or not version_id:
        return base
    if base == "Alpine":
        parts = version_id.split(".")
        return f"Alpine:v{parts[0]}.{parts[1]}" if len(parts) >= 2 else f"Alpine:v{version_id}"
    if base == "Ubuntu":
        return f"Ubuntu:{version_id}"
    if base in ("Debian", "Rocky Linux", "AlmaLinux", "Red Hat"):
        return f"{base}:{version_id.split('.')[0]}"
    return f"{base}:{version_id}"


def osv_package_name(purl: PackageURL) -> str:
    """Package name as OSV spells it for a purl."""
    if purl.type == "maven" and purl.namespace:
        return f"{purl.namespace}:{purl.name}"
    if purl.type in ("npm", "composer", "golang") and purl.namespace:
        return f"{purl.namespace}/{purl.name}"
    return purl.name


def normalize_name(ecosystem: str | None, name: str) -> str:
    """Normalized lookup key for a package name in a given ecosystem."""
    base = (ecosystem or "").split(":", 1)[0]
    n = name.strip()
    if base == "PyPI":
        import re

        return re.sub(r"[-_.]+", "-", n).lower()
    if base in ("Go", "Maven"):
        return n  # case-sensitive-ish; keep as-is
    return n.lower()


def parse(purl: str) -> PackageURL | None:
    try:
        return PackageURL.from_string(purl)
    except Exception:
        return None


def build(type_: str, name: str, version: str | None = None, namespace: str | None = None,
          qualifiers: dict | None = None) -> str:
    q = {k: v for k, v in (qualifiers or {}).items() if v}
    return PackageURL(type=type_, namespace=namespace, name=name, version=version,
                      qualifiers=q or None).to_string()


def without_version(purl: str) -> str:
    p = parse(purl)
    if not p:
        return purl
    return PackageURL(type=p.type, namespace=p.namespace, name=p.name).to_string()
