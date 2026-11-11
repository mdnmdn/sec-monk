"""py-engine: classify, match, versions, scoring and the report payloads (contracts.md (e), api-contract.md).

Reads the host's databases read-only (rust ADR-0006); the only thing it returns for the host to write is the finding
set of a persisted match. Domain code is the unchanged `secmonk` package.
"""

from __future__ import annotations

from ..wire import MethodTable, ModuleDef

TABLE = MethodTable()

from . import classify, match, reports, versions  # noqa: F401  (register their methods on TABLE)


def module() -> ModuleDef:
    return ModuleDef(name="py-engine", kind="engine", capabilities=["db-read"], max_inflight=4,
                     description="classify, match, versions, scoring and report payloads", methods=TABLE)
