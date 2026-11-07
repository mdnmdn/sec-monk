"""Per-user locations for the database and caches.

Never relative to the current working directory: a scanned checkout must not be able to plant
a cache (e.g. a `.git` config with `core.fsmonitor`) or a database that sec-monk then trusts.

    data  (database)   $SECMONK_HOME/ or $XDG_DATA_HOME/secmonk  or ~/.local/share/secmonk
                       (Windows: %LOCALAPPDATA%\\secmonk)
    cache (downloads)  $SECMONK_CACHE or $XDG_CACHE_HOME/secmonk or ~/.cache/secmonk
                       (Windows: %LOCALAPPDATA%\\secmonk\\cache)

Directories are created with mode 0700 and must be owned by the current user.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def _base(env_override: str, xdg_var: str, xdg_default: str, win_sub: str | None) -> Path:
    if os.environ.get(env_override):
        return Path(os.environ[env_override]).expanduser()
    if sys.platform == "win32":
        root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "secmonk"
        return root / win_sub if win_sub else root
    xdg = os.environ.get(xdg_var)
    return (Path(xdg) if xdg else Path.home() / xdg_default) / "secmonk"


def ensure_private_dir(path: Path) -> Path:
    """Create `path` (0700) if missing; refuse a directory owned by someone else or a symlink."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"{path} is a symlink; refusing to use it")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise PermissionError(f"{path} is not owned by the current user; refusing to use it")
    if hasattr(os, "getuid") and stat.S_IMODE(st.st_mode) & 0o077:
        os.chmod(path, 0o700)
    return path


def data_dir() -> Path:
    return _base("SECMONK_HOME", "XDG_DATA_HOME", ".local/share", None)


def cache_dir() -> Path:
    return _base("SECMONK_CACHE", "XDG_CACHE_HOME", ".cache", "cache")


def default_db_path() -> Path:
    """$SECMONK_DB if set, else <data_dir>/secmonk.db."""
    if os.environ.get("SECMONK_DB"):
        return Path(os.environ["SECMONK_DB"]).expanduser()
    return data_dir() / "secmonk.db"


def cache_subdir(*parts: str) -> Path:
    """A private cache sub-directory (created 0700, ownership-checked)."""
    ensure_private_dir(cache_dir())
    return ensure_private_dir(cache_dir().joinpath(*parts))
