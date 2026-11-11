"""Golden rows of engine/inventory.save_inventory (run from the repo root):

    uv run python -I rust/crates/secmonk-store/tests/golden/gen_save_inventory.py \
        > rust/crates/secmonk-store/tests/golden/save_inventory.json

Saves inventory A (the contract example fs-npm-v3 plus synthetic components), then B (a partial re-scan with a
removed, a changed and a duplicate-key component) into an in-memory v2 database, and records each inventory as
stored (save_inventory classifies in place: the Rust store receives classified inventories) and the resulting rows
with timestamps replaced by "TS".
"""
import copy
import json
import sys
from pathlib import Path

from secmonk import db
from secmonk.engine.inventory import save_inventory
from secmonk.models import Asset, Component, Inventory

EX = Path("rust/contracts/examples/inventory/fs-npm-v3.json")


def load(d):
    return Inventory(asset=Asset(**d["asset"]), collector=d["collector"],
                     components=[Component(**c) for c in d["components"]], warnings=list(d["warnings"]),
                     partial=d["partial"], partial_reason=d["partial_reason"])


def dump(inv):
    return {"schema": "secmonk-inventory/1", "classified": True,
            "asset": inv.asset.__dict__, "collector": inv.collector,
            "components": [c.__dict__ for c in inv.components], "warnings": inv.warnings,
            "partial": inv.partial, "partial_reason": inv.partial_reason}


base = json.loads(EX.read_text())
a = copy.deepcopy(base)
a["components"] += [
    {"name": "Google Chrome", "version": "131.0.6778.86", "category": "application", "purl": None, "cpe": None,
     "vendor": None, "ecosystem": None, "source_path": "/Applications/Google Chrome.app",
     "meta": {"bundle_id": "com.google.Chrome", "users": ["alice"]}},
    {"name": "openssl", "version": "3.4.0", "category": "package", "purl": "pkg:brew/openssl@3.4.0", "cpe": None,
     "vendor": None, "ecosystem": None, "source_path": None, "meta": {"formula": "openssl@3"}},
    {"name": "Tool", "version": None, "category": "executable", "purl": None, "cpe": None, "vendor": "Ünïcode Ltd",
     "ecosystem": None, "source_path": "/opt/tool", "meta": {"paths": ["/opt/tool", "/usr/local/bin/tool", ""]}},
    {"name": "tool", "version": None, "category": "executable", "purl": None, "cpe": None, "vendor": "ünïcode ltd",
     "ecosystem": None, "source_path": "/opt/tool2", "meta": {"paths": ["/usr/local/bin/tool", "/opt/tool3"]}},
]
a["warnings"] = ["one warning", "ünïcode \"quoted\""]
b = copy.deepcopy(a)
b["components"] = b["components"][2:]          # two removed
b["components"][0]["version"] = "9.9.9"         # a new key (purl unchanged? no: purl carries the version)
b["components"].append(dict(b["components"][1], source_path="dup/package-lock.json"))
b["components"][-3]["cpe"] = None               # openssl: COALESCE keeps the previous cpe
b["partial"] = True
b["partial_reason"] = "layer skipped"

conn = db.connect(":memory:")
inv_a, inv_b = load(a), load(b)
scan_a = save_inventory(conn, inv_a)
scan_b = save_inventory(conn, inv_b)


def rows(sql):
    out = []
    for r in conn.execute(sql):
        d = dict(r)
        for k in ("first_seen", "last_seen", "started_at", "finished_at"):
            if k in d and d[k] is not None:
                d[k] = "TS"
        out.append(d)
    return out


json.dump({
    "inventories": [dump(inv_a), dump(inv_b)],
    "scan_ids": [scan_a, scan_b],
    "asset": rows("SELECT * FROM asset ORDER BY id"),
    "scan": rows("SELECT * FROM scan ORDER BY id"),
    "component": rows("SELECT * FROM component ORDER BY id"),
    "asset_component": rows("SELECT * FROM asset_component ORDER BY asset_id, component_id"),
}, sys.stdout, ensure_ascii=False, indent=1)
