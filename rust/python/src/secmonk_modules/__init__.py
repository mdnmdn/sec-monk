"""sec-monk protocol modules: `secmonk-wire/1` over stdio, wrapping the unchanged `secmonk` package.

Entry point: `python -I -m secmonk_modules serve <module> --stdio` (see `rust/_docs/tech/contracts.md`).
"""

from __future__ import annotations

__version__ = "0.1.0"
PROTOCOL = "secmonk-wire/1.0"
