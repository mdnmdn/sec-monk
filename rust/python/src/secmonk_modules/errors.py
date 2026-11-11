"""Wire errors (`err` frames) and cooperative cancellation."""

from __future__ import annotations

from typing import Any

# codes of contracts.md (a); anything else is a bug in a module
CODES = frozenset({
    "protocol-error", "unknown-method", "invalid-params",
    "unknown-asset", "unknown-vuln", "unknown-collector", "unknown-source", "no-db",
    "unsupported-platform", "collect-error", "engine-unreachable", "host-unreachable",
    "cancelled", "timeout", "module-crashed", "module-unavailable", "busy",
    "stale", "internal",
})


class WireError(Exception):
    """An error the host receives as `err {code, error, hint?, data?}`."""

    def __init__(self, code: str, message: str, hint: str | None = None, data: dict[str, Any] | None = None):
        super().__init__(message)
        assert code in CODES, code
        self.code, self.message, self.hint, self.data = code, message, hint, data

    def frame(self, req_id: int | None) -> dict[str, Any]:
        out: dict[str, Any] = {"type": "err", "id": req_id, "code": self.code, "error": self.message}
        if self.hint:
            out["hint"] = self.hint
        if self.data:
            out["data"] = self.data
        return out


class ProtocolError(WireError):
    """The peer broke the protocol: the server answers `err id=null` and closes."""

    def __init__(self, message: str):
        super().__init__("protocol-error", message)


class Cancelled(BaseException):
    """The request was cancelled by the host (raised by `Request.check()` and the progress hooks)."""
