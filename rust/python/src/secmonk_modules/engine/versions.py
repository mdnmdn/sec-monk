"""versions.* and scoring.priority: the unchanged `engine/versions` (univers-backed) and `engine/scoring`."""

from __future__ import annotations

from ..errors import WireError
from ..wire import Request
from . import TABLE


def _events(events: list) -> list[dict]:
    if not all(isinstance(e, dict) for e in events):
        raise WireError("invalid-params", "events: expected an array of objects")
    return events


@TABLE.unary("versions.compare", {"a": str, "b": str, "scheme": str})
def compare(ctx: Request, p: dict) -> dict:
    from secmonk.engine import versions

    r = versions.compare(p["a"], p["b"], p["scheme"])
    return {"result": (r > 0) - (r < 0)}


@TABLE.unary("versions.in_range", {"version": str, "events": list, "scheme": str})
def in_range(ctx: Request, p: dict) -> dict:
    from secmonk.engine import versions

    return {"affected": bool(versions.in_osv_range(p["version"], _events(p["events"]), p["scheme"]))}


@TABLE.unary("versions.first_fixed", {"version": str, "events": list, "scheme": str})
def first_fixed(ctx: Request, p: dict) -> dict:
    from secmonk.engine import versions

    return {"fixed": versions.first_fixed_after(p["version"], _events(p["events"]), p["scheme"])}


@TABLE.unary("versions.scheme", {"ecosystem": (str, type(None))})
def scheme(ctx: Request, p: dict) -> dict:
    from secmonk.engine import versions

    return {"scheme": versions.scheme_for_ecosystem(p["ecosystem"])}


@TABLE.unary("scoring.priority", {"cvss": (float, type(None)), "epss": (float, type(None)), "kev": bool,
                                  "asset_meta?": (dict, type(None)), "triage?": (str, type(None)),
                                  "severity?": (str, type(None))})
def priority(ctx: Request, p: dict) -> dict:
    from secmonk.engine import scoring

    return {"priority": scoring.priority(cvss=p["cvss"], epss=p["epss"], kev=p["kev"], asset_meta=p.get("asset_meta"),
                                         triage=p.get("triage"), severity=p.get("severity"))}
