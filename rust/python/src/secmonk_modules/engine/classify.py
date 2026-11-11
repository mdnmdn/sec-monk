"""engine.classify: `engine/classify.classify` per component (aliases, ecosystem from purl, CPE)."""

from __future__ import annotations

from ..common import component_from_dict, component_to_dict
from ..errors import WireError
from ..wire import Request
from . import TABLE

MAX_COMPONENTS = 5000


@TABLE.unary("engine.classify", {"components": list})
def classify(ctx: Request, p: dict) -> dict:
    from secmonk.engine.classify import classify as classify_one

    items = p["components"]
    if len(items) > MAX_COMPONENTS:
        raise WireError("invalid-params", f"components: at most {MAX_COMPONENTS} per call, got {len(items)}")
    out = []
    for i, d in enumerate(items):
        ctx.check()
        out.append(component_to_dict(classify_one(component_from_dict(d, f"components[{i}]"))))
    return {"components": out}
