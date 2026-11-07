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
CAT_EXECUTABLE = "executable"      # running binary with no package identity (process collector; never matched)
CATEGORIES = (CAT_OS, CAT_OS_PACKAGE, CAT_LIBRARY, CAT_APPLICATION, CAT_SYSTEM_APP, CAT_PACKAGE, CAT_RUNTIME,
              CAT_EXECUTABLE)


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
    source_path: str | None = None     # where it was found on the target (extra locations: meta['paths'])
    # Identity facts used for matching (vendor/product hints, source package, ...) are shared by every
    # asset with the same key; per-asset facts (users, install_location, scope) are stored per asset in
    # asset_component.meta by engine/inventory.py (see _docs/tech/data-model.md).
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        if self.purl:
            return self.purl
        vendor = (self.vendor or "").lower()
        return f"name:{self.category}/{vendor}/{self.name.lower()}@{self.version or ''}"


@dataclass
class Asset:
    # id examples: macos:<host>, ssh:<host>[:<port>], image:<repo>@<digest>, container:<name>, repo:<path>
    id: str
    type: str                          # desktop | server | container-image | container | repo | directory
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
    # True when the collection is known to be incomplete (aborted stream, skipped/unreadable layer,
    # truncation). A partial inventory never counts as the authoritative "latest scan": components
    # it did not see are NOT treated as removed (see engine/inventory.py).
    partial: bool = False
    partial_reason: str | None = None

    def mark_partial(self, reason: str) -> None:
        self.partial = True
        self.partial_reason = f"{self.partial_reason}; {reason}" if self.partial_reason else reason
