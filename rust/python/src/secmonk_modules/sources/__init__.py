"""py-sources: the unchanged sources on a staging database, streamed as `secmonk-mirror-rows/1` (rust ADR-0010)."""

from __future__ import annotations

from typing import Any

from ..wire import MethodTable, ModuleDef

TABLE = MethodTable()

from . import sync  # noqa: F401  (registers source.sync / ack / export)


def _provides() -> dict[str, Any]:
    from secmonk import ops

    reg = ops.sources_registry()
    rows = [{"name": n, "description": getattr(c, "description", "") or n, "in_all": bool(getattr(c, "in_all", True))}
            for n, c in sorted(reg.items())]
    return {"sources": rows, "sync_all_order": list(ops.SYNC_ALL_ORDER)}


def module() -> ModuleDef:
    return ModuleDef(name="py-sources", kind="source", capabilities=["network", "writes-staging"], max_inflight=1,
                     provides_extra=_provides, methods=TABLE,
                     description="The 8 vulnerability feeds, run on a staging database")
