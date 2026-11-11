"""Contract schemas of rust/contracts as a jsonschema registry: validate any value against `path#/$defs/x`."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"
SCHEMAS = CONTRACTS / "schemas"
BASE = "https://contracts.secmonk.invalid/"


@lru_cache(maxsize=1)
def registry() -> Registry:
    reg = Registry()
    for f in sorted(SCHEMAS.rglob("*.schema.json")):
        doc = json.loads(f.read_text())
        reg = reg.with_resource(doc["$id"], Resource.from_contents(doc))
    return reg


def validator(ref: str) -> Draft202012Validator:
    """`ref` = `engine/match.schema.json#/$defs/result` (as written in catalog/module-methods.json)."""
    return Draft202012Validator({"$ref": BASE + ref}, registry=registry())


def errors(ref: str, value: Any) -> list[str]:
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}" for e in validator(ref).iter_errors(value)]


def check(ref: str, value: Any) -> None:
    errs = errors(ref, value)
    assert not errs, f"does not satisfy {ref}:\n  " + "\n  ".join(errs[:10])


@lru_cache(maxsize=1)
def catalog() -> dict[str, dict]:
    doc = json.loads((CONTRACTS / "catalog" / "module-methods.json").read_text())
    return {m["name"]: m for m in doc["methods"]}
