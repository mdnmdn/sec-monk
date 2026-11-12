"""Test-only hook of py-sources for the osv differential test (rust/crates/secmonk-engine/tests/native_osv.rs).

When `$SECMONK_TEST_OSV_HOOK` names a JSON file `{"bucket": "<url>"}`, the unchanged osv source (`secmonk.sources.osv`)
is pointed at that URL (a local server) for the next osv sync; without it the original bucket is restored. The file is
read again at every osv sync, so a test can change the URL between syncs.

Two ways to reach `apply()`:
- `python -I -m secmonk_modules.sources.test_hooks_osv serve --stdio --module py-sources`: wraps `OsvSource.sync` and
  then runs the normal module entry point (what the differential test starts; nothing else changes);
- one line in `sync.py` next to the nvd hook (`if name == "osv": test_hooks_osv.apply()`), not added here.

The host never passes `SECMONK_TEST_*` variables to a module (`MODULE_PASSTHROUGH` in secmonk-runtime), and never starts
this entry point, so production modules never see it; `src/` is unchanged.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

TEST_OSV_HOOK = "SECMONK_TEST_OSV_HOOK"
_ORIGINALS: dict[str, Any] = {}


def apply() -> None:
    """Point `secmonk.sources.osv.BUCKET` at the hook file's `bucket`, or restore the original without a hook file."""
    from secmonk.sources import osv

    if not _ORIGINALS:
        _ORIGINALS["BUCKET"] = osv.BUCKET
    path = os.environ.get(TEST_OSV_HOOK)
    if not path or not os.path.isfile(path):
        osv.BUCKET = _ORIGINALS["BUCKET"]
        return
    with open(path, encoding="utf-8") as f:
        hook = json.load(f)
    osv.BUCKET = str(hook["bucket"]).rstrip("/")


def install() -> None:
    """Run `apply()` before every osv sync (wraps the unchanged `OsvSource.sync`)."""
    from secmonk.sources import osv

    original = osv.OsvSource.sync
    if getattr(original, "_secmonk_test_hook", False):
        return

    def sync(self, conn, opts):  # the signature of Source.sync
        apply()
        return original(self, conn, opts)

    sync._secmonk_test_hook = True  # type: ignore[attr-defined]
    osv.OsvSource.sync = sync  # type: ignore[method-assign]


if __name__ == "__main__":
    install()
    from secmonk_modules.__main__ import main

    sys.exit(main())
