"""py-probe: the existing collectors, discovery and the docker / kubernetes listings (contracts.md (c)).

Collectors only collect: the inventory leaves **unclassified** (classification is `engine.classify`, rust ADR-0002) and
no database is touched. Redaction is the collectors' own (`redact_command`, `strip_url_secrets`, `redact_labels`);
free text that leaves this module (warnings, errors) additionally goes through `scrub_text`.
"""

from __future__ import annotations

from typing import Any

from ..wire import MethodTable, ModuleDef

TABLE = MethodTable()

from . import collect, discover  # noqa: F401  (register their methods on TABLE)


def _provides() -> dict[str, Any]:
    from secmonk import ops

    return {"collectors": [{"name": n, "description": getattr(c, "description", "") or n}
                           for n, c in sorted(ops.collectors_registry().items())]}


def module() -> ModuleDef:
    return ModuleDef(name="py-probe", kind="probe", capabilities=["read-target", "run-commands", "network"],
                     max_inflight=4, provides_extra=_provides, methods=TABLE,
                     description="Today's collectors, discovery, docker and kubernetes listings (secmonk package)")
