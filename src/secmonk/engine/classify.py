"""Recognize and categorize components: fill ecosystem, vendor and the product key used for
name-based matching. See _docs/tech/engine/classification.md.

Collectors already set the obvious fields (category, purl). `classify()` is idempotent and
adds what can be derived centrally:
  * ecosystem from purl (language packages, distro packages)
  * meta.product / vendor from the curated alias table (data/product_aliases.yaml)
  * a CPE 2.3 string when vendor+product are known
"""

from __future__ import annotations

import csv
import re
from functools import lru_cache
from importlib import resources

import yaml

from ..models import CAT_LIBRARY, CAT_OS_PACKAGE, Component
from ..sources.base import norm_vendor_product
from . import purl as purls

_NOISE = re.compile(
    r"\b(x64|x86|64-bit|32-bit|arm64|aarch64|universal|intel|apple silicon|\(x64\)|\(x86\)|"
    r"desktop|app|for mac|for macos|beta|nightly|insiders?|community edition|ce)\b",
    re.IGNORECASE,
)


@lru_cache(maxsize=1)
def product_aliases() -> dict:
    """Load the curated alias table: names/bundle ids/brew names -> (vendor, product)."""
    text = resources.files("secmonk.data").joinpath("product_aliases.yaml").read_text()
    raw = yaml.safe_load(text) or {}
    index: dict[str, dict] = {}
    for entry in raw.get("products", []):
        target = {"vendor": entry["vendor"], "product": entry["product"]}
        if entry.get("cpe_product"):
            target["cpe_product"] = entry["cpe_product"]
        for key in entry.get("names", []) + entry.get("bundle_ids", []) + entry.get("brew", []):
            index[key.lower()] = target
    return index


def normalize_product_name(name: str) -> str:
    """'Google Chrome (x64) 2024' -> 'google chrome'."""
    n = name.lower()
    n = re.sub(r"\.app$", "", n)
    n = re.sub(r"@[\d.]+$", "", n)          # brew versioned formula: openssl@3 -> openssl
    n = _NOISE.sub(" ", n)
    n = re.sub(r"\b(19|20)\d\d\b", " ", n)  # years
    n = re.sub(r"[^a-z0-9+.# ]+", " ", n)
    return " ".join(n.split())


def classify(c: Component) -> Component:
    # 1) purl-derived ecosystem
    if c.purl and not c.ecosystem:
        p = purls.parse(c.purl)
        if p is not None:
            if p.type in purls.PURL_TO_OSV:
                c.ecosystem = purls.PURL_TO_OSV[p.type]
                c.category = c.category or CAT_LIBRARY
            elif p.type in ("deb", "rpm", "apk"):
                distro = (p.qualifiers or {}).get("distro", "")
                did, _, ver = distro.partition("-")
                c.ecosystem = purls.osv_distro_ecosystem(did or (p.namespace or ""), ver or None)
                c.category = c.category or CAT_OS_PACKAGE

    # 2) product identity for name-based matching (applications, brew, runtimes, os)
    if c.category not in (CAT_LIBRARY, CAT_OS_PACKAGE) or not c.ecosystem:
        if c.meta.get("brew_kind") == "formula" and _classify_brew_formula(c):
            return c
        aliases = product_aliases()
        hit = None
        # product_hint: collector-cleaned name (e.g. Windows DisplayName without version/arch tags)
        for key in (c.meta.get("bundle_id"), c.meta.get("brew_name"), c.meta.get("product_hint"), c.name):
            if key and key.lower() in aliases:
                hit = aliases[key.lower()]
                break
        if hit is None:
            norm = normalize_product_name(c.name)
            hit = aliases.get(norm) or aliases.get(normalize_product_name(c.meta.get("product_hint") or ""))
        if hit:
            c.vendor = c.vendor or hit["vendor"]
            c.meta["product"] = hit["product"]
            c.meta["product_source"] = "alias-table"
            if c.version and not c.cpe:
                part = "o" if c.category == "os" else "a"
                cpe_product = hit.get("cpe_product", hit["product"]).replace(" ", "_")
                c.cpe = f"cpe:2.3:{part}:{hit['vendor'].replace(' ', '_')}:{cpe_product}:{c.version}:*:*:*:*:*:*:*"
        else:
            c.meta.setdefault("product", c.meta.get("product_hint") or normalize_product_name(c.name))
            c.meta.setdefault("product_source", "normalized-name")
    return c


# --------------------------------------------------------------------------- Homebrew formulae
# Identity precedence for brew formulae (see _docs/tech/engine/classification.md):
#   brew-seed > alias-table > brew-name-vendor > normalized-name.
# alias-table and normalized-name are produced by the generic code in classify(); this block handles
# the two brew-specific sources and returns False when the generic code should decide.

_SEED_EVIDENCE_RANK = {"cve-affected": 0, "repo-url": 1, "manual": 2}
_GENERIC_HOST_LABELS = frozenset({"github", "gitlab", "sourceforge", "pypi", "npmjs", "readthedocs",
                                  "wordpress", "bitbucket", "codeberg", "sf"})


@lru_cache(maxsize=1)
def brew_seed() -> dict[str, list[dict]]:
    """formula -> candidate rows [{vendor, product, evidence}], best evidence first."""
    text = resources.files("secmonk.data").joinpath("brew_cpe_seed.csv").read_text()
    out: dict[str, list[dict]] = {}
    for row in csv.DictReader(text.splitlines()):
        f = (row.get("formula") or "").strip().lower()
        if f and row.get("vendor") and row.get("product"):
            vendor, product = norm_vendor_product(row["vendor"]), norm_vendor_product(row["product"])
            if not vendor or not product:
                continue
            # same normalization as affected.vendor/product ('kerberos_5' -> 'kerberos 5')
            out.setdefault(f, []).append({"vendor": vendor, "product": product,
                                          "evidence": (row.get("evidence") or "").strip()})
    for rows in out.values():
        rows.sort(key=lambda r: _SEED_EVIDENCE_RANK.get(r["evidence"], 9))
    return out


def brew_vendor_guess(meta: dict) -> str | None:
    """Vendor token from the upstream forge org (preferred) or the homepage domain."""
    repo = meta.get("upstream_repo")
    if repo:
        host, _, path = repo.partition("/")
        if host == "sourceforge.net":
            return path.rsplit("/", 1)[-1] or None
        org = path.split("/")[0]
        if org:
            return org.lower()
    homepage = meta.get("homepage") or ""
    m = re.match(r"^[a-z]+://([^/:?#]+)", homepage.lower())
    if not m:
        return None
    labels = m.group(1).removeprefix("www.").split(".")
    if len(labels) >= 3 and labels[-2:] == ["github", "io"]:
        return labels[0]
    if len(labels) < 2:
        return None
    label = labels[-3] if len(labels) >= 3 and labels[-2] in ("co", "com", "org", "net", "ac", "gov") \
        else labels[-2]
    return None if label in _GENERIC_HOST_LABELS else label


def _classify_brew_formula(c: Component) -> bool:
    name = str(c.meta.get("brew_name") or c.name).lower()
    rows = brew_seed().get(name)
    if rows:
        first = rows[0]
        c.vendor = norm_vendor_product(c.vendor) or first["vendor"]
        c.meta["product"] = first["product"]
        c.meta["product_source"] = "brew-seed"
        c.meta["brew_seed_evidence"] = first["evidence"]
        alts_v = sorted({r["vendor"] for r in rows} - {c.vendor})
        alts_p = sorted({r["product"] for r in rows} - {first["product"]})
        if alts_v:
            c.meta["vendor_alts"] = alts_v
        if alts_p:
            c.meta["product_alts"] = alts_p
        if c.version and not c.cpe:
            c.cpe = (f"cpe:2.3:a:{c.vendor.replace(' ', '_')}:{first['product'].replace(' ', '_')}:"
                     f"{c.version}:*:*:*:*:*:*:*")
        return True
    aliases = product_aliases()
    if any(k and k.lower() in aliases for k in (c.meta.get("brew_name"), c.name)) \
            or normalize_product_name(c.name) in aliases:
        return False                                   # alias-table (generic code)
    hint = brew_vendor_guess(c.meta)
    if hint:
        c.meta["product"] = re.sub(r"@[\d.]+$", "", name)   # formula name minus @N, hyphens kept
        c.meta["product_source"] = "brew-name-vendor"
        c.meta["vendor_hint"] = hint                   # matcher: row vendor must agree, else lower
        return True
    return False                                       # normalized-name (generic code)
