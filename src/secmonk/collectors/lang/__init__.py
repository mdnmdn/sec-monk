"""Language dependency parsers. Importing this package registers all parsers.

Each ecosystem module appends its parsers to `base.REGISTRY` at import time.
"""

from .base import REGISTRY, dedupe, parse_file, parsers_for, wants  # noqa: F401


def _ensure_loaded() -> None:
    """Parsers register on package import (the ecosystem imports below); nothing else to do."""


# ecosystem modules — one import per line
from . import dart as dart
from . import dotnet as dotnet
from . import golang as golang
from . import java as java
from . import javascript as javascript
from . import php as php
from . import python as python
from . import rust as rust
from . import swift as swift
