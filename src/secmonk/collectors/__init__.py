"""Inventory collectors. Importing this package registers all collectors."""
from . import (
    docker_engine,  # noqa: F401
    docker_image,  # noqa: F401
    macos,  # noqa: F401
    rootfs,  # noqa: F401
)
