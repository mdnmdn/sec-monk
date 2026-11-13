"""Golden of the lookup keys: what the Python matcher (src/secmonk/engine/match.py) queries for each component.

    cd rust/python && uv run python scripts/lookup_keys_golden.py           # rewrite the expected file
    cd rust/python && uv run python scripts/lookup_keys_golden.py --check   # compare (exit 1 on a difference)

Input: rust/golden/node/lookup-keys.components.json (components as collectors give them, synthetic). Each one goes
through `classify()` (what a state node stores and sends to a match service), then the keys are derived the way
`match_asset` dispatches and reads `affected` (and `distro_triage`):

- package route (an ecosystem and category library / os-package / runtime): `_match_package` queries
  `affected WHERE ecosystem = ? AND package IN (names)` with names = `normalize_name(eco, name)` plus
  `normalize_name(eco, meta.source_package)`; `_triage` reads `distro_triage` with the same pairs;
- product route (everything else): `_match_product` queries `affected WHERE product IN (_product_candidates(...))`.

Keys are normalized like `secmonk_model::node::pkg_key` / `prod_key` (lowercase). The output records, per
component, the classified identity (the fields a state node sends; meta limited to the identity keys) and the keys;
the Rust test `secmonk-engine` `node::keys` asserts `component_lookup_keys` returns a superset of them. Nothing of
`src/` is modified: the script calls the matcher's own helpers.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secmonk.engine import purl as purls
from secmonk.engine.classify import classify
from secmonk.engine.match import _product_candidates
from secmonk.models import CAT_LIBRARY, CAT_OS_PACKAGE, CAT_RUNTIME, Component

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "golden" / "node"
SRC = DIR / "lookup-keys.components.json"
OUT = DIR / "lookup-keys.expected.json"

# secmonk_model::node::IDENTITY_META_KEYS: what a component's identity carries to a match service
IDENTITY_META_KEYS = ["source_package", "source_version", "product", "product_source", "product_alts",
                      "vendor_alts", "vendor_hint", "brew_kind", "brew_name", "patched_cves", "confidence"]


def pkg_key(ecosystem: str, package: str) -> str:
    return f"pkg:{ecosystem.lower()}/{package.lower()}"


def prod_key(product: str) -> str:
    return "prod:" + " ".join(product.lower().replace("_", " ").split())


def matcher_keys(c: Component) -> list[str]:
    """The keys match_asset reads for `c` (its dispatch, `_match_package` / `_match_product`)."""
    keys: set[str] = set()
    if c.ecosystem and c.category in (CAT_LIBRARY, CAT_OS_PACKAGE, CAT_RUNTIME):
        names = {purls.normalize_name(c.ecosystem, c.name)}
        if c.meta.get("source_package"):
            names.add(purls.normalize_name(c.ecosystem, c.meta["source_package"]))
        keys.update(pkg_key(c.ecosystem, n) for n in names)
    else:
        keys.update(prod_key(p) for p in _product_candidates(c.meta, c.name))
    return sorted(keys)


def identity(c: Component) -> dict:
    out = {"name": c.name, "version": c.version, "category": c.category, "purl": c.purl, "cpe": c.cpe,
           "vendor": c.vendor, "ecosystem": c.ecosystem,
           "meta": {k: c.meta[k] for k in IDENTITY_META_KEYS if k in c.meta}}
    return {k: v for k, v in out.items() if v not in (None, {})}


def build() -> list[dict]:
    rows = []
    for raw in json.loads(SRC.read_text()):
        c = Component(**{"meta": {}, **raw})
        c = classify(c)
        rows.append({"component": identity(c), "keys": matcher_keys(c)})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="compare with the stored file instead of writing it")
    args = ap.parse_args()
    text = json.dumps(build(), indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    if args.check:
        if not OUT.exists() or OUT.read_text() != text:
            print(f"{OUT} differs: run without --check to rewrite it", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
