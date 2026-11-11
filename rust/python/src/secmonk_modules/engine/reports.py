"""reports.*: the payload builders of `secmonk.reports` / `sbom` the API needs, on a read-only snapshot."""

from __future__ import annotations

from typing import Any

from ..db import read_session
from ..errors import WireError
from ..wire import Request
from . import TABLE

MAX_LIMIT = 5000
PRIORITIES = ("P1", "P2", "P3", "P4")


def _unknown_asset(aid: str) -> WireError:
    return WireError("unknown-asset", f"unknown asset {aid!r}")


@TABLE.unary("reports.overview", {})
def overview(ctx: Request, p: dict) -> dict[str, Any]:
    from secmonk import reports

    with read_session(ctx.session) as (conn, path):
        return reports.overview(conn, path)


@TABLE.unary("reports.assets", {})
def assets(ctx: Request, p: dict) -> list[dict]:
    from secmonk import reports

    with read_session(ctx.session) as (conn, _):
        return reports.asset_rows(conn)


@TABLE.unary("reports.asset_detail", {"id": str, "limit?": int})
def asset_detail(ctx: Request, p: dict) -> dict[str, Any]:
    from secmonk import reports

    limit = p.get("limit", MAX_LIMIT)
    if not 1 <= limit <= MAX_LIMIT:
        raise WireError("invalid-params", f"limit: expected 1..{MAX_LIMIT}")
    with read_session(ctx.session) as (conn, _):
        d = reports.asset_detail(conn, p["id"], limit=limit)
    if d is None:
        raise _unknown_asset(p["id"])
    return d


@TABLE.unary("reports.unmatched", {})
def unmatched(ctx: Request, p: dict) -> list[dict]:
    from secmonk import reports

    with read_session(ctx.session) as (conn, _):
        return reports.unmatched_rows(conn)


@TABLE.unary("reports.findings", {"asset?": (str, type(None)), "priority?": (str, type(None)),
                                  "include_closed?": bool, "fixable?": bool, "hide_minor?": bool,
                                  "hide_deferred?": bool, "limit": int})
def findings(ctx: Request, p: dict) -> list[dict]:
    from secmonk import reports
    from secmonk.engine import queries

    if not 1 <= p["limit"] <= MAX_LIMIT:
        raise WireError("invalid-params", f"limit: expected 1..{MAX_LIMIT}")
    prio = p.get("priority")
    if prio is not None and prio not in PRIORITIES:
        raise WireError("invalid-params", f"priority: expected one of {', '.join(PRIORITIES)}")
    asset = p.get("asset")
    with read_session(ctx.session) as (conn, _):
        if asset and not queries.asset_exists(conn, asset):
            raise _unknown_asset(asset)
        return reports.findings(conn, asset=asset, priority=prio, include_closed=p.get("include_closed", False),
                                fixable=p.get("fixable", False), hide_minor=p.get("hide_minor", False),
                                hide_deferred=p.get("hide_deferred", False), limit=p["limit"])


@TABLE.unary("reports.vuln_detail", {"id": str, "raw?": bool})
def vuln_detail(ctx: Request, p: dict) -> dict[str, Any]:
    from secmonk import reports

    with read_session(ctx.session) as (conn, _):
        d = reports.vuln_detail(conn, p["id"], raw=p.get("raw", False))
    if d is None:
        raise WireError("unknown-vuln", f"unknown vulnerability id {p['id']!r}",
                        "Not in the local mirror: sync the source that publishes it (osv, cvelist, nvd, euvd…).")
    return d


@TABLE.unary("reports.vuln_search", {"package?": (str, type(None)), "ecosystem?": (str, type(None)),
                                     "product?": (str, type(None)), "version?": (str, type(None)), "limit": int})
def vuln_search(ctx: Request, p: dict) -> list[dict]:
    from secmonk import reports

    if not 1 <= p["limit"] <= 1000:
        raise WireError("invalid-params", "limit: expected 1..1000")
    with read_session(ctx.session) as (conn, _):
        try:
            return reports.vuln_search(conn, package=p.get("package"), ecosystem=p.get("ecosystem"),
                                       product=p.get("product"), version=p.get("version"), limit=p["limit"])
        except ValueError as e:
            raise WireError("invalid-params", str(e)) from None


@TABLE.unary("reports.status", {})
def status(ctx: Request, p: dict) -> dict[str, Any]:
    from secmonk import reports

    with read_session(ctx.session) as (conn, path):
        return reports.status_payload(conn, path)


@TABLE.unary("reports.sbom", {"asset_id": str, "with_vulns?": bool})
def sbom(ctx: Request, p: dict) -> dict[str, Any]:
    from secmonk import sbom as sbom_mod

    with read_session(ctx.session) as (conn, _):
        doc = sbom_mod.export_asset(conn, p["asset_id"], with_vulns=p.get("with_vulns", False))
    if doc is None:
        raise _unknown_asset(p["asset_id"])
    return doc
