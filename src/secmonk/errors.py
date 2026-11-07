"""Exception groups shared by the CLI and the web API (kept import-light: no collector is loaded)."""

from __future__ import annotations

import configparser
import sqlite3
import tarfile
import zipfile

import httpx

# Errors a collector run may raise for a bad target / connection / permission / format: reported without a traceback
# by the CLI (exit 1), as a 503 by the web API. Anything else is a bug and keeps its traceback.
COLLECT_ERRORS: tuple[type[BaseException], ...] = (
    OSError, RuntimeError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile, httpx.HTTPError,
    configparser.Error, sqlite3.Error)
