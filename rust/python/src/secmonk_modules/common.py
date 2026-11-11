"""Conversions shared by the modules: JSON <-> `secmonk.models`, option lists, exception -> wire error."""

from __future__ import annotations

import dataclasses
from typing import Any

from .errors import WireError
from .wire import scrub

COMPONENT_KEYS = {"name", "version", "category", "purl", "cpe", "vendor", "ecosystem", "source_path", "meta"}
ASSET_KEYS = {"id", "type", "name", "os_name", "os_version", "platform", "meta"}


def _opt_str(d: dict, key: str, where: str) -> str | None:
    v = d.get(key)
    if v is not None and not isinstance(v, str):
        raise WireError("invalid-params", f"{where}.{key}: expected string or null")
    return v


def component_from_dict(d: Any, where: str = "component"):
    from secmonk.models import CATEGORIES, Component

    if not isinstance(d, dict):
        raise WireError("invalid-params", f"{where}: expected an object")
    unknown = sorted(set(d) - COMPONENT_KEYS)
    if unknown:
        raise WireError("invalid-params", f"{where}: unknown field(s) {', '.join(unknown)}")
    name = d.get("name")
    if not isinstance(name, str) or not name:
        raise WireError("invalid-params", f"{where}.name: expected a non-empty string")
    if d.get("category") not in CATEGORIES:
        raise WireError("invalid-params", f"{where}.category: expected one of {', '.join(CATEGORIES)}")
    meta = d.get("meta", {})
    if not isinstance(meta, dict):
        raise WireError("invalid-params", f"{where}.meta: expected an object")
    return Component(name=name, version=_opt_str(d, "version", where), category=d["category"],
                     purl=_opt_str(d, "purl", where), cpe=_opt_str(d, "cpe", where),
                     vendor=_opt_str(d, "vendor", where), ecosystem=_opt_str(d, "ecosystem", where),
                     source_path=_opt_str(d, "source_path", where), meta=dict(meta))


def asset_from_dict(d: Any, where: str = "asset"):
    from secmonk.models import Asset

    if not isinstance(d, dict):
        raise WireError("invalid-params", f"{where}: expected an object")
    unknown = sorted(set(d) - ASSET_KEYS)
    if unknown:
        raise WireError("invalid-params", f"{where}: unknown field(s) {', '.join(unknown)}")
    for k in ("id", "type", "name"):
        if not isinstance(d.get(k), str):
            raise WireError("invalid-params", f"{where}.{k}: expected a string")
    meta = d.get("meta", {})
    if not isinstance(meta, dict):
        raise WireError("invalid-params", f"{where}.meta: expected an object")
    return Asset(id=d["id"], type=d["type"], name=d["name"], os_name=_opt_str(d, "os_name", where),
                 os_version=_opt_str(d, "os_version", where), platform=_opt_str(d, "platform", where), meta=dict(meta))


def inventory_from_dict(d: Any):
    from secmonk.models import Inventory

    if not isinstance(d, dict):
        raise WireError("invalid-params", "inventory: expected an object")
    comps = d.get("components")
    warns = d.get("warnings")
    if not isinstance(comps, list) or not isinstance(warns, list) or not all(isinstance(w, str) for w in warns):
        raise WireError("invalid-params", "inventory: components and warnings must be arrays")
    collector = d.get("collector")
    if not isinstance(collector, str):
        raise WireError("invalid-params", "inventory.collector: expected a string")
    inv = Inventory(asset=asset_from_dict(d.get("asset")), collector=collector,
                    components=[component_from_dict(c, f"components[{i}]") for i, c in enumerate(comps)],
                    warnings=list(warns), partial=bool(d.get("partial")), partial_reason=d.get("partial_reason"))
    return inv


def component_to_dict(c) -> dict[str, Any]:
    return dataclasses.asdict(c)


def inventory_to_dict(inv, *, classified: bool) -> dict[str, Any]:
    d = dataclasses.asdict(inv)
    return {"schema": "secmonk-inventory/1", "classified": classified, **d}


def parse_options(items: list[str]) -> dict[str, Any]:
    """`key=value` strings -> collector kwargs with the one parser of the CLI and the web jobs (`ops.parse_opts`)."""
    from secmonk import ops

    try:
        return ops.parse_opts(items)
    except ValueError as e:
        raise WireError("invalid-params", f"options: {e}") from None


def err_text(e: BaseException) -> str:
    """`<Type>: <message>`, URL credentials removed, never a traceback."""
    return scrub(f"{type(e).__name__}: {e}")
