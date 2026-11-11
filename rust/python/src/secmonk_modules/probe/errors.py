"""Collector / engine exceptions -> wire errors (the `COLLECT_ERRORS` of `secmonk.errors` and its siblings)."""

from __future__ import annotations

from ..common import err_text
from ..errors import WireError


def collect_error(e: BaseException, collector: str | None = None, target: str | None = None) -> WireError:
    """A collector failure. `unsupported-platform` (process on an OS without a backend), `host-unreachable` (ssh,
    kubectl against a cluster), `engine-unreachable` (a Docker engine), else `collect-error`. The text is
    `<Type>: <message>` with URL credentials removed; k8s failures carry `data.reason` for the API's finer codes."""
    from secmonk.collectors.process.backend import UnsupportedPlatformError

    text = err_text(e)
    if isinstance(e, UnsupportedPlatformError):
        return WireError("unsupported-platform", text)
    name = type(e).__name__
    if name == "SSHError":
        return WireError("host-unreachable", text)
    if name == "KubectlError":
        return k8s_error(e)
    if collector == "docker-engine" and isinstance(e, RuntimeError):
        return WireError("engine-unreachable", text)
    if collector == "ssh" and isinstance(e, (RuntimeError, OSError)):
        return WireError("host-unreachable", text)
    return WireError("collect-error", text)


def k8s_error(e: BaseException) -> WireError:
    """`web/jobs._discover_error` without the HTTP part: kubectl missing -> collect-error, refused (RBAC) or
    unreachable cluster -> host-unreachable, the finer reason in `data.reason`."""
    text = err_text(e)
    if "not found" in str(e) and "kubectl" in str(e):
        return WireError("collect-error", text, "Install kubectl (on PATH), or use the CLI with -o kubectl=/path.",
                         {"reason": "kubectl-missing"})
    if getattr(e, "denied", False):
        return WireError("host-unreachable", text, "The kubeconfig user lacks read access (RBAC) or its "
                         "credentials expired.", {"reason": "k8s-denied"})
    return WireError("host-unreachable", text, "Check the kubeconfig and context (and the VPN).",
                     {"reason": "k8s-unreachable"})
