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
from .base import Collector, register

MAX_APP_DEPTH = 3
BREW_PREFIXES = ("opt/homebrew", "usr/local")
_REVISION = re.compile(r"_\d+$")

# bundled frameworks reported as runtimes: dir name -> (component name, bundle id, purl type)
_FRAMEWORKS = {
    "Electron Framework.framework": ("Electron", "com.github.Electron"),
    "Chromium Embedded Framework.framework": ("Chromium Embedded Framework", None),
    "Sparkle.framework": ("Sparkle", "org.sparkle-project.Sparkle"),
}


def _load_plist(path: Path) -> dict | None:
    with path.open("rb") as fh:
        data = plistlib.load(fh)
    return data if isinstance(data, dict) else None


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


def _brew_purl(kind: str, name: str, version: str | None, tap: str | None) -> str:
    if kind == "cask":
        return purls.build("brew", name, version, namespace="homebrew/cask")
    if tap and tap.lower() != "homebrew/core":
        return purls.build("brew", name, version, namespace=tap.lower())
    return purls.build("brew", name, version)


def _formula_component(name: str, raw_version: str, tap: str | None, **meta: Any) -> Component:
    version = _REVISION.sub("", raw_version)
    m = {"brew_name": name, "brew_kind": "formula", "brew_version": raw_version, "tap": tap}
    m.update({k: v for k, v in meta.items() if v is not None})
    return Component(name=name, version=version, category=CAT_PACKAGE,
                     purl=_brew_purl("formula", name, version, tap), meta=m)


def _cask_component(token: str, version: str | None, names: list[str] | None = None,
                    homepage: str | None = None, apps: list[str] | None = None,
                    tap: str | None = None) -> Component:
    display = (names or [None])[0] or token
    meta = {"brew_name": token, "brew_kind": "cask", "brew_version": version,
            "homepage": homepage, "cask_apps": apps or [], "tap": tap}
    return Component(name=display, version=version, category=CAT_APPLICATION,
                     purl=_brew_purl("cask", token, version, tap), meta={k: v for k, v in meta.items() if v})


def _cask_apps(artifacts: list) -> list[str]:
    out: list[str] = []
    for a in artifacts or []:
        if isinstance(a, dict):
            for app in a.get("app", []) or []:
                if isinstance(app, str):
                    out.append(app)
    return out


def parse_brew_info_json(data: dict) -> list[Component]:
    """Components from `brew info --json=v2 --installed` output."""
    comps: list[Component] = []
    for f in data.get("formulae", []) or []:
        name = f.get("name")
        installed = f.get("installed") or []
        for inst in installed:
            ver = inst.get("version")
            if not name or not ver:
                continue
            comp = _formula_component(
                name, ver, f.get("tap"),
                installed_on_request=inst.get("installed_on_request"),
                runtime_dependencies=len(inst.get("runtime_dependencies") or []),
                homepage=f.get("homepage"), license=f.get("license"),
                source_url=((f.get("urls") or {}).get("stable") or {}).get("url"),
            )
            comps.append(comp)
    for c in data.get("casks", []) or []:
        token = c.get("token")
        if not token or not c.get("installed"):
            continue
        comps.append(_cask_component(token, c.get("installed") or c.get("version"), c.get("name"),
                                     c.get("homepage"), _cask_apps(c.get("artifacts")), c.get("tap")))
    return comps


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


@register
class MacOSCollector(Collector):
    name = "macos"
    description = "macOS apps (.app bundles), Homebrew formulae/casks, pkgutil receipts and OS version"

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        root = Path(target or "/")
        live = str(root) == "/"
        include_system = opts.get("include_system", True)
        warnings: list[str] = []
        components: list[Component] = []

        # --- OS / asset
        os_comp = None
        sv = root / "System/Library/CoreServices/SystemVersion.plist"
        if sv.is_file():
            try:
                d = _load_plist(sv) or {}
                ver = d.get("ProductVersion")
                os_comp = Component(name="macOS", version=ver, category=CAT_OS, vendor="apple",
                                    source_path=_rel(sv, root),
                                    meta={"build": d.get("ProductBuildVersion")})
                components.append(os_comp)
            except Exception as e:  # noqa: BLE001
                warnings.append(f"cannot read {sv}: {e}")
        else:
            warnings.append(f"SystemVersion.plist not found under {root}")
        hostname = opts.get("hostname") or (socket.gethostname() if live else (root.resolve().name or "macos"))
        asset = Asset(
            id=f"macos:{hostname}", type="desktop", name=hostname, os_name="macOS",
            os_version=os_comp.version if os_comp else None,
            platform=f"darwin/{platform.machine() if live else 'unknown'}",
        )

        # --- apps
        apps: list[Component] = []
        app_dirs = [(root / "Applications", CAT_APPLICATION)]
        for h in self._home_dirs(root, live, opts.get("home")):
            app_dirs.append((h / "Applications", CAT_APPLICATION))
        if include_system:
            app_dirs.append((root / "System/Applications", CAT_SYSTEM_APP))
        seen_bundles: set[Path] = set()
        for base, cat in app_dirs:
            for bundle in self._find_bundles(base, MAX_APP_DEPTH):
                real = bundle.resolve()
                if real in seen_bundles:
                    continue
                seen_bundles.add(real)
                try:
                    apps.extend(self._read_bundle(bundle, root, cat))
                except Exception as e:  # noqa: BLE001
                    warnings.append(f"cannot read bundle {_rel(bundle, root)}: {e}")

        # --- homebrew
        brew: list[Component] = []
        if opts.get("use_brew_cli") and shutil.which("brew"):
            try:
                out = subprocess.run(["brew", "info", "--json=v2", "--installed"], capture_output=True,
                                     text=True, check=True, timeout=120).stdout
                brew = parse_brew_info_json(json.loads(out))
            except Exception as e:  # noqa: BLE001
                warnings.append(f"brew CLI failed, using filesystem walk: {e}")
        if not brew:
            brew = self._walk_brew(root, warnings)

        # dedupe casks against app bundles
        app_comps = [a for a in apps if a.category in (CAT_APPLICATION, CAT_SYSTEM_APP)
                     and "embedded_in" not in a.meta]
        kept_brew: list[Component] = []
        for b in brew:
            if b.meta.get("brew_kind") == "cask":
                match = self._match_app(b, app_comps)
                if match is not None:
                    match.meta["also_cask"] = b.meta["brew_name"]
                    continue
            kept_brew.append(b)

        components.extend(apps)
        components.extend(kept_brew)

        # --- system_profiler export
        sp = opts.get("system_profiler")
        if sp:
            try:
                sp_comps = parse_system_profiler_json(json.loads(Path(sp).read_text()))
                have = {(_norm(c.name), c.version) for c in components}
                components.extend(c for c in sp_comps if (_norm(c.name), c.version) not in have)
            except Exception as e:  # noqa: BLE001
                warnings.append(f"cannot read system_profiler JSON {sp}: {e}")

        # --- pkgutil receipts
        components.extend(self._receipts(root, include_system, warnings))
        return Inventory(asset=asset, collector=self.name, components=components, warnings=warnings)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _home_dirs(root: Path, live: bool, homes: list | None) -> list[Path]:
        if homes:
            return [Path(h) for h in homes]
        out: list[Path] = []
        users = root / "Users"
        if users.is_dir():
            out.extend(p for p in sorted(users.iterdir()) if p.is_dir() and p.name not in ("Shared",))
        if live:
            home = Path.home()
            if home not in out:
                out.append(home)
        return out

    @staticmethod
    def _find_bundles(base: Path, max_depth: int):
        def walk(d: Path, depth: int):
            try:
                entries = sorted(d.iterdir())
            except OSError:
                return
            for p in entries:
                if p.suffix == ".app" and p.is_dir():
                    yield p
                elif p.is_dir() and not p.is_symlink() and depth < max_depth:
                    yield from walk(p, depth + 1)

        if base.is_dir():
            yield from walk(base, 1)

    def _read_bundle(self, bundle: Path, root: Path, cat: str) -> list[Component]:
        info_path = bundle / "Contents/Info.plist"
        if not info_path.is_file():
            raise FileNotFoundError("Contents/Info.plist missing")
        info = _load_plist(info_path)
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
            "sparkle_feed": info.get("SUFeedURL"),
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
                    rt = self._read_framework(fw, rt_name, rt_bundle_id, str(name), root)
                    if rt:
                        out.append(rt)
        return out

    @staticmethod
    def _read_framework(fw: Path, rt_name: str, rt_bundle_id: str | None, app_name: str,
                        root: Path) -> Component | None:
        candidates = sorted(fw.glob("Versions/*/Resources/Info.plist")) + [fw / "Resources/Info.plist"]
        for p in candidates:
            if not p.is_file():
                continue
            try:
                d = _load_plist(p) or {}
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

    def _walk_brew(self, root: Path, warnings: list[str]) -> list[Component]:
        out: list[Component] = []
        for pfx in BREW_PREFIXES:
            prefix = root / pfx
            cellar = prefix / "Cellar"
            if cellar.is_dir():
                for formula in sorted(cellar.iterdir()):
                    if not formula.is_dir():
                        continue
                    for vdir in sorted(formula.iterdir()):
                        receipt = vdir / "INSTALL_RECEIPT.json"
                        if not vdir.is_dir() or not receipt.is_file():
                            continue
                        try:
                            r = json.loads(receipt.read_text())
                        except Exception as e:  # noqa: BLE001
                            warnings.append(f"cannot read {_rel(receipt, root)}: {e}")
                            continue
                        c = _formula_component(
                            formula.name, vdir.name, (r.get("source") or {}).get("tap"),
                            installed_on_request=r.get("installed_on_request"),
                            runtime_dependencies=len(r.get("runtime_dependencies") or []),
                            homebrew_version=r.get("homebrew_version"))
                        c.source_path = _rel(vdir, root)
                        out.append(c)
            caskroom = prefix / "Caskroom"
            if caskroom.is_dir():
                for cask in sorted(caskroom.iterdir()):
                    if not cask.is_dir() or cask.name.startswith("."):
                        continue
                    for vdir in sorted(cask.iterdir()):
                        if not vdir.is_dir() or vdir.name.startswith("."):
                            continue
                        names = homepage = tap = None
                        apps: list[str] = []
                        for jf in sorted(cask.glob(f".metadata/{vdir.name}/*/Casks/{cask.name}.json")):
                            try:
                                j = json.loads(jf.read_text())
                                names, homepage, tap = j.get("name"), j.get("homepage"), j.get("tap")
                                apps = _cask_apps(j.get("artifacts"))
                            except Exception as e:  # noqa: BLE001
                                warnings.append(f"cannot read {_rel(jf, root)}: {e}")
                        if not apps:
                            apps = [p.name for p in vdir.glob("*.app")]
                        c = _cask_component(cask.name, vdir.name, names, homepage, apps, tap)
                        c.source_path = _rel(vdir, root)
                        out.append(c)
        return out

    @staticmethod
    def _match_app(cask: Component, apps: list[Component]) -> Component | None:
        keys = {_norm(a) for a in cask.meta.get("cask_apps", [])}
        keys.add(_norm(cask.meta["brew_name"]))
        keys.add(_norm(cask.name))
        for app in apps:
            bundle_name = Path(app.source_path or "").stem
            if keys & {_norm(app.name), _norm(bundle_name)}:
                return app
        return None

    @staticmethod
    def _receipts(root: Path, include_system: bool, warnings: list[str]) -> list[Component]:
        out: list[Component] = []
        d = root / "var/db/receipts"
        if not d.is_dir():
            return out
        for p in sorted(d.glob("*.plist")):
            try:
                r = _load_plist(p) or {}
                pid = r.get("PackageIdentifier")
                if not pid:
                    raise ValueError("no PackageIdentifier")
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
            except Exception as e:  # noqa: BLE001
                warnings.append(f"cannot read receipt {p.name}: {e}")
        return out
