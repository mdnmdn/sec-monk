"""macOS inventory collector: .app bundles, Homebrew, pkgutil receipts and the OS version.

Works against a filesystem root (default "/"), so it can be tested on Linux with a fixture tree.
See _docs/tech/collectors/macos.md.
"""

from __future__ import annotations

import json
import platform
import plistlib
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

from ..engine import purl as purls
from ..models import (
    CAT_APPLICATION,
    CAT_OS,
    CAT_PACKAGE,
    CAT_RUNTIME,
    CAT_SYSTEM_APP,
    Asset,
    Component,
    Inventory,
)
from .base import Collector, read_within, register, resolve_within, strip_url_secrets
from .homebrew import (  # noqa: F401  (re-exported for backwards compatibility)
    _cask_apps,
    _cask_component,
    _formula_component,
    collect_prefixes,
    flag,
    parse_brew_info_json,
)

MAX_APP_DEPTH = 3
MAX_PLIST_BYTES = 8 * 1024 * 1024
# pkgutil receipts: third-party packages, and (macOS 10.15+) Apple's own on the system data volume
RECEIPT_DIRS = ("var/db/receipts", "Library/Apple/System/Library/Receipts")
DENIED_HINT = ("permission denied (macOS privacy protection: grant Full Disk Access to the app running "
               "secmonk, or run it where this path is readable)")

# bundled frameworks reported as runtimes: dir name -> (component name, bundle id, purl type)
_FRAMEWORKS = {
    "Electron Framework.framework": ("Electron", "com.github.Electron"),
    "Chromium Embedded Framework.framework": ("Chromium Embedded Framework", None),
    "Sparkle.framework": ("Sparkle", "org.sparkle-project.Sparkle"),
}


_PLIST_PROLOG = re.compile(rb"^(?:\xef\xbb\xbf)?\s*(?:<\?xml[^>]*\?>)?\s*(?:<!DOCTYPE[^>]*>)?\s*<plist\b[^>]*>")
_CANONICAL_PROLOG = (b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                     b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">')


def loads_plist(data: bytes) -> Any:
    """`plistlib.loads`, tolerating an XML prolog with unquoted attributes (`<?xml version=1.0 ...?>`,
    `<!DOCTYPE plist PUBLIC -//Apple//...>`, `<plist version=1.0>`): Apple ships such files (macOS 26.5:
    /System/Library/LaunchAgents/com.apple.familycircled.plist) and `plutil` accepts them, expat does not.
    Also a UTF-8 file (BOM optional) whose prolog declares another encoding (`encoding="utf-16"`: Royal TSX 6
    Info.plist, 2026-11-08): the prolog is replaced only when the bytes really are 8-bit (start with `<`)."""
    try:
        return plistlib.loads(data)
    except Exception:
        fixed = _PLIST_PROLOG.sub(_CANONICAL_PROLOG, data, count=1)
        if fixed == data or not data.removeprefix(b"\xef\xbb\xbf").lstrip().startswith(b"<"):
            raise
        return plistlib.loads(fixed)


def _load_plist(path: Path, boundary: Path | None = None) -> dict | None:
    """Parse a plist (<= 8 MB). With `boundary`, the file must resolve below it (no symlink escapes)."""
    if boundary is None:
        with path.open("rb") as fh:
            data = loads_plist(fh.read(MAX_PLIST_BYTES + 1)[:MAX_PLIST_BYTES])
    else:
        data = loads_plist(read_within(path, boundary, MAX_PLIST_BYTES))
    return data if isinstance(data, dict) else None


def _why(e: OSError) -> str:
    return DENIED_HINT if isinstance(e, PermissionError) else f"{type(e).__name__}: {e}"


def _list_dir(d: Path, label: str, warnings: list[str] | None) -> list[Path]:
    """Sorted entries of `d`. A missing directory is empty; an unreadable one is empty *with a warning*
    (`Path.is_dir()` / `glob()` would hide a denied directory as if it did not exist)."""
    try:
        return sorted(d.iterdir())
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError as e:
        if warnings is not None:
            warnings.append(f"cannot list {label}: {_why(e)}")
        return []


def _as_list(v: Any) -> list:
    if v is None or v == "":
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


def _norm(s: str) -> str:
    s = re.sub(r"\.app$", "", s.lower())
    return re.sub(r"[^a-z0-9]+", "", s)


def _vendor_hint(bundle_id: str | None) -> str | None:
    if not bundle_id:
        return None
    parts = bundle_id.split(".")
    return parts[1].lower() if len(parts) >= 3 else None


def _rel(path: Path, root: Path) -> str:
    try:
        return "/" + path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def parse_system_profiler_json(data: dict) -> list[Component]:
    """Components from `system_profiler SPApplicationsDataType -json`."""
    comps: list[Component] = []
    for a in data.get("SPApplicationsDataType", []) or []:
        name = a.get("_name")
        if not name:
            continue
        path = a.get("path") or ""
        system = path.startswith("/System/")
        signed = a.get("signed_by") or []
        meta = {"obtained_from": a.get("obtained_from"), "signed_by": signed,
                "arch_kind": a.get("arch_kind"), "last_modified": a.get("lastModified"),
                "source": "system_profiler"}
        comps.append(Component(
            name=name, version=a.get("version"),
            category=CAT_SYSTEM_APP if system or a.get("obtained_from") == "apple" else CAT_APPLICATION,
            source_path=path or None, meta={k: v for k, v in meta.items() if v}))
    return comps


def _brew_key(c: Component) -> tuple:
    return (c.meta.get("brew_kind"), c.meta.get("brew_name"), c.meta.get("brew_version"))


# `brew info` keys that describe the formula / cask, not one keg: safe to copy onto a walked keg of another version
_BREW_FORMULA_KEYS = ("homepage", "license", "keg_only", "pinned", "auto_updates", "brew_oldnames")


def merge_brew(walk: list[Component], cli: list[Component]) -> list[Component]:
    """Union of the filesystem walk and `brew info --json=v2` components. Nothing found by the walk is ever
    dropped and the walk's values win; the CLI only adds the meta keys the walk lacks (`brew_cli=True`).

    A CLI component is matched by purl, else by (kind, name, raw version), where the name may also be one of its
    `brew_oldnames` (a renamed formula keeps its old Cellar rack: the walk reports `mprocs`, the CLI `dekit`). When
    the walk has the formula/cask under any of those names but another version (the two pick the active keg
    differently: opt link vs linked_keg), the CLI enriches the walk's active keg with formula-level keys only and
    records its own choice in `brew_cli_version`: it never adds a second keg. Only formulae/casks the walk does not
    have at all are appended, with `meta.source=brew-cli`."""
    by_purl = {c.purl: c for c in walk if c.purl}
    by_key = {_brew_key(c): c for c in walk if c.meta.get("brew_kind")}
    by_name: dict[tuple, list[Component]] = {}
    for c in walk:
        if c.meta.get("brew_kind"):
            by_name.setdefault((c.meta["brew_kind"], c.meta.get("brew_name")), []).append(c)
    out = list(walk)
    for c in cli:
        kind, ver = c.meta.get("brew_kind"), c.meta.get("brew_version")
        names = [c.meta.get("brew_name"), *(c.meta.get("brew_oldnames") or [])]
        hit = by_purl.get(c.purl) if c.purl else None
        for n in names:
            hit = hit or by_key.get((kind, n, ver))
        if hit is not None:
            keys = [k for k, v in c.meta.items() if v is not None]
        else:
            same = [w for n in names for w in by_name.get((kind, n), [])]
            if not same:
                c.meta["source"] = "brew-cli"
                out.append(c)
                continue
            hit = next((w for w in same if w.meta.get("active")), same[0])
            keys = [k for k in _BREW_FORMULA_KEYS if c.meta.get(k) is not None]
            if c.meta.get("active") and ver != hit.meta.get("brew_version"):
                hit.meta["brew_cli_version"] = ver
        for k in keys:
            if hit.meta.get(k) is None:
                hit.meta[k] = c.meta[k]
        if c.meta.get("brew_name") != hit.meta.get("brew_name"):
            hit.meta["brew_current_name"] = c.meta.get("brew_name")     # renamed: the tap's current name
        hit.meta["brew_cli"] = True
    return out


@register
class MacOSCollector(Collector):
    name = "macos"
    description = "macOS apps (.app bundles), Homebrew formulae/casks, pkgutil receipts and OS version"

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        root = Path(target or "/")
        boundary = root.resolve()
        live = boundary == Path("/").resolve()        # the running system (also `/.`, `//`)
        include_system = opts.get("include_system", True)
        warnings: list[str] = []
        components: list[Component] = []

        # --- OS / asset
        os_comp = None
        sv = root / "System/Library/CoreServices/SystemVersion.plist"
        try:
            d = _load_plist(sv, boundary) or {}
            ver = d.get("ProductVersion")
            os_comp = Component(name="macOS", version=ver, category=CAT_OS, vendor="apple",
                                source_path=_rel(sv, root),
                                meta={"build": d.get("ProductBuildVersion")})
            components.append(os_comp)
        except FileNotFoundError:
            warnings.append(f"SystemVersion.plist not found under {root}")
        except PermissionError as e:
            warnings.append(f"cannot read {sv}: {_why(e)}")
        except Exception as e:  # noqa: BLE001
            warnings.append(f"cannot read {sv}: {e}")
        hostname = opts.get("hostname") or (socket.gethostname() if live else (root.resolve().name or "macos"))
        asset = Asset(
            id=f"macos:{hostname}", type="desktop", name=hostname, os_name="macOS",
            os_version=os_comp.version if os_comp else None,
            platform=f"darwin/{platform.machine() if live else 'unknown'}",
        )

        # --- apps
        apps: list[Component] = []
        explicit_homes = bool(_as_list(opts.get("home")))
        app_dirs = [(root / "Applications", CAT_APPLICATION, boundary)]
        for h in self._home_dirs(root, live, opts.get("home"), warnings):
            # homes given explicitly may live outside `root`; their apps must stay inside the home
            app_dirs.append((h / "Applications", CAT_APPLICATION,
                             h.resolve() if explicit_homes else boundary))
        if include_system:
            app_dirs.append((root / "System/Applications", CAT_SYSTEM_APP, boundary))
        seen_bundles: set[Path] = set()
        for base, cat, bound in app_dirs:
            for bundle in self._find_bundles(base, MAX_APP_DEPTH, warnings, root):
                try:
                    real = resolve_within(bundle, bound)
                except ValueError as e:
                    warnings.append(f"skipped bundle {_rel(bundle, root)}: {e}")
                    continue
                if real in seen_bundles:
                    continue
                seen_bundles.add(real)
                try:
                    apps.extend(self._read_bundle(bundle, root, cat, bound))
                except PermissionError as e:
                    warnings.append(f"cannot read bundle {_rel(bundle, root)}: {_why(e)}")
                except Exception as e:  # noqa: BLE001
                    warnings.append(f"cannot read bundle {_rel(bundle, root)}: {e}")

        # --- homebrew
        brew = self._brew(root, live, opts, warnings)

        # dedupe casks against app bundles
        app_comps = [a for a in apps if a.category in (CAT_APPLICATION, CAT_SYSTEM_APP)
                     and "embedded_in" not in a.meta]
        kept_brew: list[Component] = []
        for b in brew:
            if b.meta.get("brew_kind") == "cask":
                match = self._match_app(b, app_comps)
                if match is not None:
                    match.meta["also_cask"] = b.meta["brew_name"]
                    if b.meta.get("auto_updates"):
                        match.meta["cask_auto_updates"] = True    # bundle version is the truth
                    continue
            kept_brew.append(b)

        components.extend(apps)
        components.extend(kept_brew)

        # --- system_profiler export
        sp = opts.get("system_profiler")
        if sp:
            try:
                sp_data = json.loads(Path(sp).read_text())
                sp_comps = parse_system_profiler_json(sp_data)
                if not sp_comps:
                    warnings.append(f"system_profiler JSON {sp} lists no applications: system_profiler may "
                                    "have run without access to the app folders (Full Disk Access)")
                have = {(_norm(c.name), c.version) for c in components}
                components.extend(c for c in sp_comps if (_norm(c.name), c.version) not in have)
            except Exception as e:  # noqa: BLE001
                warnings.append(f"cannot read system_profiler JSON {sp}: {e}")

        # --- pkgutil receipts
        components.extend(self._receipts(root, include_system, warnings, boundary))
        return Inventory(asset=asset, collector=self.name, components=components, warnings=warnings)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _brew(root: Path, live: bool, opts: dict[str, Any], warnings: list[str]) -> list[Component]:
        """The filesystem walk always runs; `brew info` only enriches it (the CLI skips formulae of untapped
        taps, renamed/removed formulae, and cannot see a second prefix such as /usr/local). The CLI describes
        the host, so it is asked only when the scanned root is the live system."""
        brew, brew_warnings = collect_prefixes(root, opts)
        warnings.extend(brew_warnings)
        if not opts.get("use_brew_cli"):
            return brew
        if not live:
            warnings.append(f"use_brew_cli ignored: root is not the live system ({root})")
            return brew
        if not shutil.which("brew"):
            warnings.append("use_brew_cli ignored: brew not found on PATH")
            return brew
        try:
            out = subprocess.run(["brew", "info", "--json=v2", "--installed"], capture_output=True,
                                 text=True, check=True, timeout=120).stdout
            return merge_brew(brew, parse_brew_info_json(json.loads(out), all_kegs=flag(opts.get("all_kegs"))))
        except Exception as e:  # noqa: BLE001
            err = (getattr(e, "stderr", None) or "").strip().splitlines()
            warnings.append(f"brew CLI failed, filesystem walk only: {e}" + (f" ({err[0][:200]})" if err else ""))
            return brew

    @staticmethod
    def _home_dirs(root: Path, live: bool, homes: Any, warnings: list[str] | None = None) -> list[Path]:
        homes = _as_list(homes)       # `-o home=/Users/bob` arrives as a plain string
        if homes:
            return [Path(h) for h in homes]
        out: list[Path] = []
        users = _list_dir(root / "Users", _rel(root / "Users", root), warnings)
        out.extend(p for p in users if p.is_dir() and p.name not in ("Shared",))
        if live:
            home = Path.home()
            if home not in out:
                out.append(home)
        return out

    @staticmethod
    def _find_bundles(base: Path, max_depth: int, warnings: list[str] | None = None,
                      root: Path | None = None):
        """`.app` bundles below `base`; unreadable directories are reported in `warnings`, not skipped silently."""
        def walk(d: Path, depth: int):
            for p in _list_dir(d, _rel(d, root) if root is not None else str(d), warnings):
                if p.suffix == ".app" and p.is_dir():
                    yield p
                elif p.is_dir() and not p.is_symlink() and depth < max_depth:
                    yield from walk(p, depth + 1)

        yield from walk(base, 1)

    def _read_bundle(self, bundle: Path, root: Path, cat: str, boundary: Path | None = None) -> list[Component]:
        boundary = boundary or root.resolve()
        info_path = bundle / "Contents/Info.plist"
        ios_wrapper = False
        try:
            info_path.stat()                  # raises PermissionError: a denied plist is not a missing one
            has_info = True
        except (FileNotFoundError, NotADirectoryError):
            has_info = False
        if not has_info:
            # iOS/iPadOS apps on Apple silicon: <App>.app/Wrapper/<App>.app/Info.plist
            wrapped = sorted(bundle.glob("Wrapper/*.app/Info.plist"))
            if not wrapped:
                raise FileNotFoundError("Contents/Info.plist missing")
            info_path, ios_wrapper = wrapped[0], True
        info = _load_plist(info_path, boundary)
        if info is None:
            raise ValueError("Info.plist is not a dictionary")
        bundle_id = info.get("CFBundleIdentifier")
        name = info.get("CFBundleDisplayName") or info.get("CFBundleName") or bundle.stem
        version = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
        frameworks = bundle / "Contents/Frameworks"
        electron = (frameworks / "Electron Framework.framework").is_dir() or "ElectronAsarIntegrity" in info
        hint = _vendor_hint(bundle_id)
        meta = {
            "bundle_id": bundle_id,
            "bundle_version": info.get("CFBundleVersion"),
            "copyright": info.get("NSHumanReadableCopyright"),
            "min_os": info.get("LSMinimumSystemVersion"),
            "mas": (bundle / "Contents/_MASReceipt").exists(),
            "sparkle_feed": strip_url_secrets(info.get("SUFeedURL")) if isinstance(info.get("SUFeedURL"), str)
            else None,
            "ios_app_on_mac": ios_wrapper or None,
            "electron": electron,
            "vendor_hint": hint,
        }
        qualifiers = {"bundle_id": bundle_id}
        purl = purls.build("generic", str(name), str(version) if version else None,
                           namespace=hint, qualifiers=qualifiers)
        comp = Component(name=str(name), version=str(version) if version else None, category=cat,
                         purl=purl, source_path=_rel(bundle, root), meta=meta)
        out = [comp]
        if frameworks.is_dir():
            for fw_name, (rt_name, rt_bundle_id) in _FRAMEWORKS.items():
                fw = frameworks / fw_name
                if fw.is_dir():
                    rt = self._read_framework(fw, rt_name, rt_bundle_id, str(name), root, boundary)
                    if rt:
                        out.append(rt)
        return out

    @staticmethod
    def _read_framework(fw: Path, rt_name: str, rt_bundle_id: str | None, app_name: str,
                        root: Path, boundary: Path | None = None) -> Component | None:
        candidates = sorted(fw.glob("Versions/*/Resources/Info.plist")) + [fw / "Resources/Info.plist"]
        for p in candidates:
            if not p.is_file():
                continue
            try:
                d = _load_plist(p, boundary) or {}
            except Exception:  # noqa: BLE001, S112
                continue
            if rt_name == "Electron":
                v = d.get("CFBundleVersion") or d.get("CFBundleShortVersionString")
            else:
                v = d.get("CFBundleShortVersionString") or d.get("CFBundleVersion")
            if not v:
                continue
            v = str(v)
            meta = {"embedded_in": app_name, "bundle_id": rt_bundle_id or d.get("CFBundleIdentifier"),
                    "vendor_hint": rt_name.split()[0].lower()}
            purl = purls.build("npm", "electron", v) if rt_name == "Electron" else \
                purls.build("generic", rt_name, v)
            return Component(name=rt_name, version=v, category=CAT_RUNTIME, purl=purl,
                             source_path=_rel(p, root), meta={k: x for k, x in meta.items() if x})
        return None

    @staticmethod
    def _match_app(cask: Component, apps: list[Component]) -> Component | None:
        keys = {_norm(a) for a in cask.meta.get("cask_apps", [])}
        keys.add(_norm(cask.meta["brew_name"]))
        keys.add(_norm(cask.name))
        bundle_ids = set(cask.meta.get("cask_bundle_ids") or [])
        for app in apps:
            if bundle_ids and app.meta.get("bundle_id") in bundle_ids:
                return app
            bundle_name = Path(app.source_path or "").stem
            if keys & {_norm(app.name), _norm(bundle_name)}:
                return app
        return None

    @staticmethod
    def _receipts(root: Path, include_system: bool, warnings: list[str],
                  boundary: Path | None = None) -> list[Component]:
        out: list[Component] = []
        seen: set[str] = set()
        plists = [p for rel in RECEIPT_DIRS for p in _list_dir(root / rel, "/" + rel, warnings)
                  if p.suffix == ".plist"]
        for p in plists:
            try:
                r = _load_plist(p, boundary or root.resolve()) or {}
                pid = str(r.get("PackageIdentifier") or "").strip()   # `pkgutil` strips; ids with a trailing space exist
                if not pid:
                    raise ValueError("no PackageIdentifier")
                if pid in seen:
                    continue
                seen.add(pid)
                apple = pid.startswith("com.apple.")
                if apple and not include_system:
                    continue
                ver = r.get("PackageVersion")
                ver = str(ver) if ver is not None else None
                meta = {"pkg_id": pid, "install_date": r.get("InstallDate"),
                        "install_prefix": r.get("InstallPrefixPath"),
                        "install_process": r.get("InstallProcessName"),
                        "vendor_hint": "apple" if apple else _vendor_hint(pid)}
                out.append(Component(
                    name=pid, version=ver, category=CAT_PACKAGE,
                    purl=purls.build("generic", pid, ver), source_path=_rel(p, root),
                    meta={k: (v.isoformat() if hasattr(v, "isoformat") else v)
                          for k, v in meta.items() if v}))
            except PermissionError as e:
                warnings.append(f"cannot read receipt {_rel(p, root)}: {_why(e)}")
            except Exception as e:  # noqa: BLE001
                warnings.append(f"cannot read receipt {p.name}: {e}")
        return out
