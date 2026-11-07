"""Collector interface.

A collector turns a target (a directory, an image reference, a socket...) into an `Inventory`.
It must not touch the database or match vulnerabilities — `engine.inventory.save_inventory()`
persists, `engine.match` matches. This keeps collectors testable against fixture trees.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar
from urllib.parse import urlsplit, urlunsplit

from ..models import Inventory


class Collector:
    name: ClassVar[str]
    description: ClassVar[str] = ""

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:  # pragma: no cover
        raise NotImplementedError


REGISTRY: dict[str, type[Collector]] = {}


def register(cls: type[Collector]) -> type[Collector]:
    REGISTRY[cls.name] = cls
    return cls


# --------------------------------------------------------------------------- secret hygiene
# Inventories are stored and exported, so values that commonly carry credentials never go into
# them verbatim (container Cmd/Entrypoint/Labels, URLs in git remotes or update feeds).

REDACTED = "<redacted>"
_SECRET_KEY = re.compile(r"token|secret|passw(or)?d|passwd|api[-_]?key|apikey|auth(?!ors?(?![a-z]))|credential|private[-_]?key",
                         re.IGNORECASE)


def looks_secret(key: str) -> bool:
    return bool(_SECRET_KEY.search(key))


def strip_url_secrets(url: str | None) -> str | None:
    """Drop userinfo, query and fragment from a URL (scp-like `git@host:path` is left alone)."""
    if not url or "://" not in url:
        return url
    try:
        u = urlsplit(url)
        host = u.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        netloc = host + (f":{u.port}" if u.port else "")
        return urlunsplit((u.scheme, netloc, u.path, "", ""))
    except ValueError:
        return url.split("://", 1)[0] + "://<invalid-url>"


def redact_command(args: list[str] | str | None) -> list[str] | str | None:
    """Redact secret-looking arguments of a Cmd/Entrypoint: `--password x`, `--token=x`, `KEY=x`,
    and URLs with userinfo."""
    if args is None:
        return None
    if isinstance(args, str):
        out = redact_command(args.split(" "))
        return " ".join(out)  # type: ignore[arg-type]
    res: list[str] = []
    hide_next = False
    for a in args:
        if not isinstance(a, str):
            res.append(a)
            continue
        if hide_next:
            res.append(REDACTED)
            hide_next = False
            continue
        m = re.match(r"^(-{0,2}[\w.-]+)=(.*)$", a, re.DOTALL)
        if m and looks_secret(m.group(1)):
            res.append(f"{m.group(1)}={REDACTED}")
        elif a.startswith("-") and looks_secret(a):
            res.append(a)
            hide_next = True
        elif "://" in a:
            res.append(strip_url_secrets(a) or a)
        else:
            res.append(a)
    return res


def redact_labels(labels: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (labels or {}).items():
        if looks_secret(str(k)):
            out[k] = REDACTED
        elif isinstance(v, str) and "://" in v:
            out[k] = strip_url_secrets(v)
        else:
            out[k] = v
    return out


# --------------------------------------------------------------------------- scanning mounted trees
# A scanned directory (an extracted image, a mounted disk) is untrusted: a symlink inside it may
# point at /etc/shadow or at a device. Reads of such trees go through these helpers.

def resolve_within(path: Any, boundary: Any) -> Any:
    """`path` resolved (symlinks followed) and checked to be `boundary` itself or below it.
    Raises ValueError when it escapes (or the symlink chain is a loop)."""
    from pathlib import Path

    b = Path(boundary).resolve()
    try:
        r = Path(path).resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"cannot resolve {path}: {e}") from e
    if r != b and b not in r.parents:
        raise ValueError(f"{path} resolves outside {b}")
    return r


def read_within(path: Any, boundary: Any, cap: int) -> bytes:
    """Read a regular file below `boundary` (following only symlinks that stay inside), at most `cap` bytes."""
    import os
    import stat

    r = resolve_within(path, boundary)
    fd = os.open(r, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{path} is not a regular file")
        if st.st_size > cap:
            raise ValueError(f"{path} is larger than {cap} bytes")
        return f.read(cap + 1)[:cap]
