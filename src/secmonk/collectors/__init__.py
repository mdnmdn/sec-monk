"""Inventory collectors. Importing this package registers all collectors."""
from . import (
    docker_engine,  # noqa: F401
    docker_image,  # noqa: F401
    fs,  # noqa: F401
    homebrew,  # noqa: F401
    k8s,  # noqa: F401
    macos,  # noqa: F401
    process,  # noqa: F401
    rootfs,  # noqa: F401
    sbom,  # noqa: F401
    ssh,  # noqa: F401
    windows,  # noqa: F401
)
