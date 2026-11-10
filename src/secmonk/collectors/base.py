"""Collector interface.

A collector turns a target (a directory, an image reference, a socket...) into an `Inventory`.
It must not touch the database or match vulnerabilities — `engine.inventory.save_inventory()`
persists, `engine.match` matches. This keeps collectors testable against fixture trees.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from ..models import Inventory


class Collector:
    name: ClassVar[str]
    description: ClassVar[str] = ""

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:  # pragma: no cover
        raise NotImplementedError

    def expand_targets(self, target: str | None, **opts: Any) -> list[str | None]:
        """One target spec -> the targets to scan, each passed to `collect` (e.g. docker-engine: a comma list,
        globs, `re:` regexes over container names). Default: the target itself. Raises ValueError when nothing
        matches."""
        return [target]


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


def strip_url_secrets(url: str | None, *, keep_user: bool = False) -> str | None:
    """Drop the password (and, unless `keep_user`, the user name), query and fragment of a URL; scp-like
    `git@host:path` is left alone. Lenient: never fails on an odd port or trailing punctuation, keeps
    `unix:///path` as is."""
    if not url or "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    m = re.match(r"([^/?#]*)([^?#]*)", rest)
    authority, path = (m.group(1), m.group(2)) if m else ("", "")
    if "@" in authority:
        userinfo, _, hostport = authority.rpartition("@")
        user = userinfo.split(":", 1)[0]
        authority = (f"{user}@" if keep_user and user else "") + hostport
    return f"{scheme}://{authority}{path}"


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


# Collector options as stored in the run history. Keys naming a file (exactly these, or `*_file` / `*_path`) keep
# their value: a path says how a scan ran and is not the secret itself. Any other key that looks secret (`password`,
# `pass`, `passphrase`, `token`, `*_secret`, `*key`, `tls_key_passphrase`…) is masked.
_PATH_OPTS = frozenset({"identity", "tls_ca", "tls_cert", "tls_key", "known_hosts", "ssh_config"})
_PATH_SUFFIX = re.compile(r"_(file|path)$", re.IGNORECASE)
_SECRET_OPT = re.compile(r"pass|token|secret|key$", re.IGNORECASE)
_HOST_OPT = re.compile(r"host|url|endpoint|socket", re.IGNORECASE)
_SSHPASS = re.compile(r"(\bsshpass\b(?:\s+-\w+)*?\s+-p)\s*\S+")
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s'\"<>]+", re.IGNORECASE)


def redact_option(key: str, value: Any) -> Any:
    """A collector option as stored in the run history: secrets -> '***', URL credentials stripped, `ssh_option`
    commands (ProxyCommand=…) through redact_command."""
    if isinstance(value, list):
        return [redact_option(key, v) for v in value]
    if key.lower() in _PATH_OPTS or _PATH_SUFFIX.search(key):
        return scrub_text(value) if isinstance(value, str) else value
    if _SECRET_OPT.search(key) or looks_secret(key):
        return "***"
    if not isinstance(value, str):
        return value
    if key == "ssh_option":
        return _SSHPASS.sub(r"\1 ***", redact_command(value) or value)  # type: ignore[arg-type]
    if "://" in value and _HOST_OPT.search(key):
        return strip_url_secrets(value, keep_user=True)
    return scrub_text(value)


def scrub_text(text: str | None) -> str | None:
    """Free text (an error message, a log line) with every URL's password, query and fragment removed (user names
    kept): a backstop for whatever reaches the stored run history."""
    if not text or "://" not in text:
        return text
    return _URL.sub(lambda m: strip_url_secrets(m.group(0), keep_user=True) or m.group(0), text)


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
