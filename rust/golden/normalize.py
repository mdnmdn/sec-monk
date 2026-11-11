"""Golden normalizer (rules in normalize.json). Pure functions over JSON values: the Python and the Rust test runners
apply the same rules (README.md). Usage: `normalize(value, roots={"data_dir": ..., "fixtures": ..., "repo": ...})`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

RULES = json.loads((Path(__file__).with_name("normalize.json")).read_text())


def _sub(s: str, roots: dict[str, str]) -> str:
    for name in RULES["placeholders"]["order"]:
        root = roots.get(name)
        if root:
            for variant in {root, root.replace("\\", "/"), str(Path(root).resolve())}:
                s = s.replace(variant, RULES["placeholders"]["tokens"][name])
    return s


def _sort_key(item: Any, keys: list[str]) -> tuple:
    if not isinstance(item, dict):
        return (json.dumps(item, sort_keys=True),)
    if not keys:
        return (json.dumps(item, sort_keys=True),)
    return tuple("" if item.get(k) is None else str(item.get(k)) for k in keys) + (json.dumps(item, sort_keys=True),)


def normalize(value: Any, roots: dict[str, str] | None = None, _name: str | None = None) -> Any:
    roots = roots or {}
    if isinstance(value, str):
        return _sub(value, roots)
    if isinstance(value, list):
        out = [normalize(v, roots, _name) for v in value]
        if _name in RULES["sort"]:
            out.sort(key=lambda i: _sort_key(i, RULES["sort"][_name]))
        return out
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            nk = _sub(k, roots)
            if k in RULES["volatile_keys"] and not k.startswith("_") and v is not None and not isinstance(v, (dict, list)):
                out[nk] = RULES["volatile_keys"][k]
            else:
                out[nk] = normalize(v, roots, k)
        return out
    return value


def dumps(value: Any) -> str:
    return json.dumps(value, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
