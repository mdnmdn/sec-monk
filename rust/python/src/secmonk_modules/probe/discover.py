"""discover.host, docker.contexts, docker.containers, k8s.kubeconfigs (the `ops` functions behind the API)."""

from __future__ import annotations

from typing import Any

from ..common import err_text, parse_options
from ..errors import Cancelled, WireError
from ..wire import Request
from . import TABLE
from .errors import k8s_error

ENGINE_HINT = ("Is the Docker/Podman engine running and reachable? For ssh:// hosts the key must be usable without "
               "a prompt.")
HOST_HINT = "Is the host reachable over ssh with a key (no password prompt)? `secmonk discover <target>` shows more."


def _options(items: list) -> dict[str, Any]:
    if not all(isinstance(x, str) for x in items):
        raise WireError("invalid-params", "options: expected an array of key=value strings")
    return parse_options(items)


def _engine_error(e: BaseException) -> WireError:
    """`web/jobs._engine_error`: bad input keeps our message, anything from the engine is generic (its reply body is
    never echoed)."""
    if isinstance(e, ValueError):
        return WireError("invalid-params", err_text(e), "Check the host (unix:// tcp:// ssh://user@host), the "
                         "context name and the selector (names, globs, re:<regex>, comma separated).")
    return WireError("engine-unreachable", f"cannot reach the Docker engine ({type(e).__name__})", ENGINE_HINT)


@TABLE.unary("discover.host", {"target?": (str, type(None)), "options": list})
def discover_host(ctx: Request, p: dict) -> dict:
    from secmonk import ops

    opts = _options(p["options"])
    target = p.get("target") or None
    try:
        return ops.discover_host(target, opts)
    except Cancelled:
        raise
    except ValueError as e:
        raise WireError("invalid-params", err_text(e), "Expected nothing (this machine) or [ssh://]user@host[:port].") \
            from None
    except Exception as e:  # noqa: BLE001
        if type(e).__name__ == "KubectlError" or (target or "").startswith("k8s://"):
            raise k8s_error(e) from None
        raise WireError("host-unreachable", f"cannot explore the host ({type(e).__name__})", HOST_HINT) from None


@TABLE.unary("docker.contexts", {})
def docker_contexts(ctx: Request, p: dict) -> list[dict]:
    from secmonk import ops

    try:
        return ops.docker_contexts()
    except Cancelled:
        raise
    except Exception as e:  # noqa: BLE001
        raise _engine_error(e) from None


@TABLE.unary("docker.containers", {"host?": (str, type(None)), "context?": (str, type(None)), "all?": bool,
                                   "match?": (str, type(None)), "options?": list})
def docker_containers(ctx: Request, p: dict) -> dict:
    from secmonk import ops

    opts = _options(p.get("options", []))
    try:
        return ops.docker_containers(host=p.get("host"), context=p.get("context"), all=p.get("all", False),
                                     match=p.get("match"), opts=opts)
    except Cancelled:
        raise
    except Exception as e:  # noqa: BLE001
        raise _engine_error(e) from None


@TABLE.unary("k8s.kubeconfigs", {})
def kubeconfigs(ctx: Request, p: dict) -> list[dict]:
    from secmonk import ops

    try:
        return ops.k8s_kubeconfigs()
    except Cancelled:
        raise
    except Exception as e:  # noqa: BLE001
        raise WireError("collect-error", f"cannot list kubeconfigs ({type(e).__name__})") from None
