"""Collector interface.

A collector turns a target (a directory, an image reference, a socket...) into an `Inventory`.
It must not touch the database or match vulnerabilities — `engine.inventory.save_inventory()`
persists, `engine.match` matches. This keeps collectors testable against fixture trees.
"""

from __future__ import annotations

from typing import Any, ClassVar

from ..models import Inventory


class Collector:
    name: ClassVar[str]
    description: ClassVar[str] = ""

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:  # pragma: no cover
        raise NotImplementedError


REGISTRY: dict[str, type[Collector]] = {}


def register(cls: type[Collector]) -> type[Collector]:
    REGISTRY[cls.name] = cls
    return cls
