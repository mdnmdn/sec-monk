"""collector.collect / collector.expand_targets / process.snapshot / docker.image_check."""

from __future__ import annotations

import dataclasses
from typing import Any

from ..common import parse_options
from ..errors import Cancelled, WireError
from ..wire import Request
from . import TABLE
from .errors import collect_error

# options a module never honours: they make a collector write a file chosen by the caller (a module writes only in
# its own directory). Policy on options that choose what runs (ssh_bin, kubectl…) is the host's (api-contract.md).
FORBIDDEN_OPTS = frozenset({"snapshot_out"})
COLLECT_PARAMS = {"collector": str, "target": (str, type(None)), "options": list}
MAX_WARNING = 2000


def _registry_entry(name: str):
    from secmonk import ops

    reg = ops.collectors_registry()
    if name not in reg:
        raise WireError("unknown-collector", f"unknown collector {name!r} (known: {', '.join(sorted(reg))})")
    return reg[name]


def parse_collect_params(p: dict) -> tuple[str, str | None, dict[str, Any]]:
    options = p["options"]
    if not all(isinstance(x, str) for x in options):
        raise WireError("invalid-params", "options: expected an array of key=value strings")
    opts = parse_options(options)
    bad = sorted(set(opts) & FORBIDDEN_OPTS)
    if bad:
        raise WireError("invalid-params", f"option not accepted by a module: {', '.join(bad)}")
    return p["collector"], (p["target"] or None), opts


@TABLE.unary("collector.expand_targets", COLLECT_PARAMS)
def expand_targets(ctx: Request, p: dict) -> dict:
    from secmonk import ops

    name, target, opts = parse_collect_params(p)
    _registry_entry(name)
    try:
        return {"targets": ops.expand_targets(name, target, opts)}
    except Cancelled:
        raise
    except Exception as e:  # noqa: BLE001
        raise collect_error(e, name, target) from None


@TABLE.stream("collector.collect", COLLECT_PARAMS)
def collect(ctx: Request, p: dict):
    """asset, components (≤ chunk_items each), warnings; end {partial, partial_reason, components, warnings}.
    `ops.collect` minus `engine.classify`: the host classifies on ingest."""
    from secmonk import ops
    from secmonk.collectors.base import scrub_text

    name, target, opts = parse_collect_params(p)
    cls = _registry_entry(name)
    shown = ops.redact_target(target)
    ctx.progress(f"collecting with {name}{' on ' + shown if shown else ''}…")
    try:
        inv = cls().collect(target, **opts)
    except Cancelled:
        raise
    except Exception as e:  # noqa: BLE001
        raise collect_error(e, name, target) from None
    ctx.check()
    yield {"kind": "asset", "schema": "secmonk-inventory/1", "collector": inv.collector, "classified": False,
           "asset": dataclasses.asdict(inv.asset)}
    comps = [dataclasses.asdict(c) for c in inv.components]
    step = max(1, ctx.chunk_items)
    for i in range(0, len(comps), step):
        yield {"kind": "components", "components": comps[i:i + step]}
    warnings = [(scrub_text(str(w)) or "")[:MAX_WARNING] for w in inv.warnings]
    for w in warnings:
        yield {"kind": "warning", "message": w}
    return {"partial": bool(inv.partial), "partial_reason": inv.partial_reason, "components": len(comps),
            "warnings": len(warnings)}


@TABLE.unary("process.snapshot", COLLECT_PARAMS)
def process_snapshot(ctx: Request, p: dict) -> dict:
    """`ProcessCollector.snapshot` as a `secmonk-process-snapshot/1` document (the future probe/engine split point)."""
    from secmonk.collectors.process import snapshot as snapfile
    from secmonk.collectors.process.collector import ProcessCollector

    name, target, opts = parse_collect_params(p)
    if name != "process":
        raise WireError("invalid-params", "process.snapshot serves the process collector")
    try:
        return snapfile.to_dict(ProcessCollector.snapshot(target, **opts))
    except Cancelled:
        raise
    except Exception as e:  # noqa: BLE001
        raise collect_error(e, name, target) from None


@TABLE.unary("docker.image_check", {"target": str, "options": list})
def image_check(ctx: Request, p: dict) -> dict:
    """The probe half of `ops._reuse_image`: the asset id of an expanded image target and what the engine says about
    it now. The host applies the trust rule (stored scan, inventory_version, id_verified, same engine/platform)."""
    from secmonk.collectors import docker_engine
    from secmonk.collectors.base import strip_url_secrets

    if not all(isinstance(x, str) for x in p["options"]):
        raise WireError("invalid-params", "options: expected an array of key=value strings")
    opts = {k: v for k, v in parse_options(p["options"]).items() if k != "rescan"}
    version = getattr(docker_engine, "IMAGE_INVENTORY_VERSION", None)
    out: dict[str, Any] = {"asset_id": docker_engine.image_identity(p["target"]),
                           "inventory_version": None if version is None else str(version),
                           "engine": None, "meta": None, "error": None}
    if out["asset_id"] is None:
        return out
    try:
        out["engine"] = strip_url_secrets(str(docker_engine.find_endpoint(opts)))
        out["meta"] = docker_engine.image_meta(p["target"], **opts)
    except Cancelled:
        raise
    except Exception as e:  # noqa: BLE001  # unreachable / deleted: the host collects and reports it properly
        out["engine"], out["meta"] = None, None
        out["error"] = f"{type(e).__name__}"
    return out
