"""The four prototype modules, loaded lazily (a module's imports are heavy and only that module needs them)."""

from __future__ import annotations

import importlib

from .wire import ModuleDef

MODULES = {"py-probe": "secmonk_modules.probe", "py-sources": "secmonk_modules.sources",
           "py-engine": "secmonk_modules.engine", "py-procmon": "secmonk_modules.procmon"}
MODULE_NAMES = tuple(MODULES)


def load_module(name: str) -> ModuleDef:
    if name not in MODULES:
        raise KeyError(name)
    return importlib.import_module(MODULES[name]).module()
