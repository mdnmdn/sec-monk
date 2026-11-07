"""Language dependency parsers. Importing this package registers all parsers.

Each ecosystem module appends its parsers to `base.REGISTRY` at import time.
"""

from .base import REGISTRY, dedupe, parse_file, parsers_for, wants  # noqa: F401


def _ensure_loaded() -> None:
    """Parsers register on package import (the ecosystem imports below); nothing else to do."""


# ecosystem modules — one import per line
from . import golang as golang
from . import rust as rust
from . import java as java
from . import dotnet as dotnet
