"""Plain data structures exchanged between sources, collectors and the engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Component categories (see _docs/tech/engine/classification.md)
CAT_OS = "os"                      # the operating system itself (macOS 15.1, Debian 12)
CAT_OS_PACKAGE = "os-package"      # distro package (deb/rpm/apk)
CAT_LIBRARY = "library"            # language package (pypi, npm, maven, ...)
CAT_APPLICATION = "application"    # end-user app (.app bundle, MSI product, cask)
CAT_SYSTEM_APP = "system-app"      # app shipped with the OS (Safari, Mail)
CAT_PACKAGE = "package"            # package-manager tool/formula (brew formula, pkgutil receipt)
CAT_RUNTIME = "runtime"            # embedded runtime/framework (Electron, Chromium, JRE, Python)
CATEGORIES = (CAT_OS, CAT_OS_PACKAGE, CAT_LIBRARY, CAT_APPLICATION, CAT_SYSTEM_APP, CAT_PACKAGE, CAT_RUNTIME)


@dataclass
class Component:
    """A piece of software found on an asset."""

    name: str
    version: str | None
    category: str
    purl: str | None = None
    cpe: str | None = None
    vendor: str | None = None
    ecosystem: str | None = None       # OSV ecosystem for matching ('PyPI', 'Debian:12', 'Alpine:v3.20')
    source_path: str | None = None     # where it was found on the target
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        if self.purl:
            return self.purl
        vendor = (self.vendor or "").lower()
        return f"name:{self.category}/{vendor}/{self.name.lower()}@{self.version or ''}"


@dataclass
class Asset:
    id: str
    type: str                          # desktop | server | container-image | container | repo
    name: str
    os_name: str | None = None
    os_version: str | None = None
    platform: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Inventory:
    """Output of a collector run."""

    asset: Asset
    collector: str
    components: list[Component] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
