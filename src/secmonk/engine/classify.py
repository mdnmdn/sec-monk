"""Recognize and categorize components: fill ecosystem, vendor and the product key used for
name-based matching. See _docs/tech/engine/classification.md.

Collectors already set the obvious fields (category, purl). `classify()` is idempotent and
adds what can be derived centrally:
  * ecosystem from purl (language packages, distro packages)
  * meta.product / vendor from the curated alias table (data/product_aliases.yaml)
  * a CPE 2.3 string when vendor+product are known
"""

from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources

import yaml

from ..models import CAT_LIBRARY, CAT_OS_PACKAGE, Component
from . import purl as purls

_NOISE = re.compile(
    r"\b(x64|x86|64-bit|32-bit|arm64|aarch64|universal|intel|apple silicon|\(x64\)|\(x86\)|"
    r"desktop|app|for mac|for macos|beta|nightly|insiders?|community edition|ce)\b",
    re.I,
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
        aliases = product_aliases()
        hit = None
        for key in (c.meta.get("bundle_id"), c.meta.get("brew_name"), c.name):
            if key and key.lower() in aliases:
                hit = aliases[key.lower()]
                break
        if hit is None:
            norm = normalize_product_name(c.name)
            hit = aliases.get(norm)
        if hit:
            c.vendor = c.vendor or hit["vendor"]
            c.meta["product"] = hit["product"]
            c.meta["product_source"] = "alias-table"
            if c.version and not c.cpe:
                part = "o" if c.category == "os" else "a"
                cpe_product = hit.get("cpe_product", hit["product"]).replace(" ", "_")
                c.cpe = f"cpe:2.3:{part}:{hit['vendor'].replace(' ', '_')}:{cpe_product}:{c.version}:*:*:*:*:*:*:*"
        else:
            c.meta.setdefault("product", normalize_product_name(c.name))
            c.meta.setdefault("product_source", "normalized-name")
    return c
