"""Windows inventory collector: OS identity, installed programs, Appx/MSIX, Chocolatey, Scoop, .NET.

Three input modes (see _docs/tech/collectors/windows.md):
  * `target` = JSON produced by scripts/windows/secmonk-inventory.ps1 (primary; runs on Linux too)
  * `-o osquery=<file>` = osquery results (programs + os_version + patches [+ registry])
  * live, when running ON Windows (`sys.platform == "win32"`): stdlib `winreg` for the OS and
    Uninstall keys, PowerShell (best effort) for Appx and hotfixes, plain file reads for
    Chocolatey / Scoop / .NET

The OS component is named and versioned so it hits Microsoft CNA records in the CVE List:
product "Windows 11 Version 23H2", version "10.0.<CurrentBuild>.<UBR>".
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ..engine import purl as purls
from ..engine.versions import compare
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

SCHEMA = "secmonk-windows-inventory/1"
# shipped as package data (scripts/windows/secmonk-inventory.ps1 is a symlink to it)
INVENTORY_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "data" / "windows" / "secmonk-inventory.ps1"


def inventory_script(compact: bool = True) -> str:
    """Text of the PowerShell inventory script (for `powershell -Command -` over SSH / Intune).

    `compact` drops blank and comment-only lines: with `-Command -` PowerShell reads stdin like an
    interactive console, where blank lines are the most likely thing to confuse multi-line blocks.
    """
    try:
        text = INVENTORY_SCRIPT_PATH.read_text(encoding="utf-8")
    except OSError as e:  # broken install
        raise FileNotFoundError(f"inventory script not found at {INVENTORY_SCRIPT_PATH}: {e}") from e
    if not compact:
        return text
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    return "\r\n".join(lines) + "\r\n"


def load_json_file(path: str | Path) -> Any:
    """Read JSON tolerant of BOMs and of the UTF-16 that `powershell > file` writes."""
    raw = Path(path).read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8-sig")
    return json.loads(text)


# --------------------------------------------------------------------------- OS identity

# Windows 10 build -> marketing version as spelled in Microsoft CNA products ("Windows 10 Version 22H2")
_WIN10 = {10240: "1507", 10586: "1511", 14393: "1607", 15063: "1703", 16299: "1709", 17134: "1803",
          17763: "1809", 18362: "1903", 18363: "1909", 19041: "2004", 19042: "20H2", 19043: "21H1",
          19044: "21H2", 19045: "22H2"}
# Windows 11 build -> version. 26200/28000 (25H2/26H1) are from memory, not from a CNA record.
_WIN11 = {22000: "21H2", 22621: "22H2", 22631: "23H2", 26100: "24H2", 26200: "25H2", 28000: "26H1"}
# Windows Server build -> CNA product (Server Core variants are separate CNA products but Microsoft
# lists the non-Core product for the same CVE, so the base product is what we match on)
_SERVER = {6003: "Windows Server 2008 Service Pack 2", 7601: "Windows Server 2008 R2 Service Pack 1",
           9200: "Windows Server 2012", 9600: "Windows Server 2012 R2", 14393: "Windows Server 2016",
           17763: "Windows Server 2019", 20348: "Windows Server 2022",
           25398: "Windows Server 2022, 23H2 Edition (Server Core installation)",
           26100: "Windows Server 2025"}
# Microsoft's CNA spells the ARM64 23H2 product "Windows 11 version 22H3" (see CVE-2024-38063):
# the second spelling is added as meta.product, the first stays the component name.
_ALT_PRODUCT = {22631: "windows 11 version 22h3"}
_PLATFORM = {"amd64": "windows/amd64", "x64": "windows/amd64", "arm64": "windows/arm64",
             "x86": "windows/386"}


def _int(v: Any) -> int | None:
    try:
        return int(str(v).strip(), 0) if v is not None and str(v).strip() != "" else None
    except ValueError:
        return None


def windows_os_identity(os_info: dict) -> dict[str, Any]:
    """Map registry/os_version facts to the CNA-style product. Returns a dict with
    name, product, family (client|server), release, cpe_slug, marketing_name."""
    build = _int(os_info.get("current_build"))
    raw_name = str(os_info.get("product_name") or "")
    itype = str(os_info.get("installation_type") or "")
    display_version = str(os_info.get("display_version") or "").strip() or None
    release_id = str(os_info.get("release_id") or "").strip() or None
    is_server = itype.lower() in ("server", "server core", "nano server") or "windows server" in raw_name.lower()
    if is_server:
        name = _SERVER.get(build or -1)
        if name is None:
            m = re.search(r"Windows Server (\d{4}(?: R2)?)", raw_name)
            name = f"Windows Server {m.group(1)}" if m else "Windows Server"
        slug = re.sub(r"[^a-z0-9]+", "_", re.sub(r",.*$", "", name.lower())).strip("_")
        return {"name": name, "product": name.lower(), "family": "server", "release": None,
                "cpe_slug": slug, "marketing_name": raw_name or name}
    if build is not None and build >= 22000:
        rel = _WIN11.get(build) or display_version
        name = f"Windows 11 Version {rel}" if rel else "Windows 11"
        slug = f"windows_11_{rel.lower()}" if rel else "windows_11"
    elif build is not None and build >= 10240:
        rel = _WIN10.get(build) or display_version or release_id
        name = f"Windows 10 Version {rel}" if rel else "Windows 10"
        slug = f"windows_10_{rel.lower()}" if rel else "windows_10"
    elif build == 7601:
        rel, name, slug = None, "Windows 7 Service Pack 1", "windows_7"
    elif build == 9600:
        rel, name, slug = None, "Windows 8.1", "windows_8.1"
    else:
        rel, name, slug = None, raw_name or "Windows", "windows"
    product = _ALT_PRODUCT.get(build or -1, name.lower())
    # ProductName still says "Windows 10 Pro" on Windows 11 -> fix the human-readable name
    marketing = raw_name
    if build is not None and build >= 22000:
        marketing = raw_name.replace("Windows 10", "Windows 11")
    return {"name": name, "product": product, "family": "client", "release": rel, "cpe_slug": slug,
            "marketing_name": marketing or name}


def _os_version(os_info: dict, warnings: list[str]) -> str | None:
    """'10.0.<build>.<UBR>' (what Microsoft CNA ranges compare). None when the UBR is unknown:
    a 3-part version would sort below every fix and flag the host for every CVE."""
    build = _int(os_info.get("current_build"))
    ubr = _int(os_info.get("ubr"))
    if build is None:
        warnings.append("OS build number missing: OS vulnerability matching disabled")
        return None
    major, minor = _int(os_info.get("major")), _int(os_info.get("minor"))
    if major is None or minor is None:
        cur = str(os_info.get("current_version") or "")
        m = re.match(r"^(\d+)\.(\d+)", cur)
        major, minor = (int(m.group(1)), int(m.group(2))) if m else (10, 0)
    if ubr is None:
        warnings.append("OS UBR (update build revision) missing: OS vulnerability matching disabled")
        return None
    return f"{major}.{minor}.{build}.{ubr}"


def os_component(os_info: dict, hotfixes: list[dict], warnings: list[str], extra: dict | None = None) -> Component:
    ident = windows_os_identity(os_info)
    version = _os_version(os_info, warnings)
    arch = str(os_info.get("architecture") or "").lower()
    meta: dict[str, Any] = {
        "product": ident["product"], "product_source": "alias-table",  # curated build->CNA table above
        "family": ident["family"], "release": ident["release"],
        "marketing_name": ident["marketing_name"],
        "edition": os_info.get("edition_id"), "installation_type": os_info.get("installation_type"),
        "build": _int(os_info.get("current_build")), "ubr": _int(os_info.get("ubr")),
        "display_version": os_info.get("display_version"), "install_date": os_info.get("install_date"),
        "server_core": str(os_info.get("installation_type") or "").lower() == "server core",
        "hotfixes": sorted({h["id"] for h in hotfixes if h.get("id")}),
    }
    if extra:
        meta.update(extra)
    cpe = None
    if version:
        cpe = f"cpe:2.3:o:microsoft:{ident['cpe_slug']}:{version}:*:*:*:*:*:{arch or '*'}:*"
    purl = purls.build("generic", "windows", version, namespace="microsoft",
                       qualifiers={"release": re.sub(r"[^A-Za-z0-9]+", "-", ident["name"].replace("Windows ", "")
                                                      .replace("Version ", "")).strip("-")})
    return Component(name=ident["name"], version=version, category=CAT_OS, purl=purl, cpe=cpe,
                     vendor="microsoft", source_path="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     meta={k: v for k, v in meta.items() if v not in (None, "", [])})


# --------------------------------------------------------------------------- display-name normalization

_ARCH_TOKENS = {"x64", "x86", "amd64", "arm64", "64-bit", "32-bit", "64bit", "32bit"}
_LOCALE = re.compile(r"^[a-z]{2,3}-[a-z]{2,4}$", re.IGNORECASE)
_ARCH_WORD = re.compile(r"(?<![\w.])(x64|x86|amd64|arm64|64-bit|32-bit)(?![\w])", re.IGNORECASE)
_TRAIL_VERSION = re.compile(r"\s+-\s+v?(\d+(?:\.\d+)+)\s*$")
_EMBEDDED_VERSION = re.compile(r"(?<![\w.])v?(\d+(?:\.\d+)+)(?![\w])")
_LOCALE_TAIL = re.compile(r"\s+-\s+[a-z]{2}-[a-z]{2,4}\s*$", re.IGNORECASE)
_TRAIL_WORD = re.compile(r"\s+(release|version|ver\.?)\s*$", re.IGNORECASE)
_VERSION_FROM_NAME = {"python"}   # Python's DisplayVersion is 3.12.4150.0 for 3.12.4
_VERSION_TOKEN = re.compile(r"\d+(?:\.\d+)+")


def _tag_group(content: str) -> list[str] | None:
    toks = [t for t in re.split(r"[\s,]+", content.strip().lower()) if t]
    if toks and all(t in _ARCH_TOKENS or _LOCALE.match(t) for t in toks):
        return toks
    return None


def normalize_display_name(raw: str) -> tuple[str, str | None, str | None]:
    """'7-Zip 23.01 (x64)' -> ('7-Zip', '23.01', 'x64').

    Removes arch tags (also inside parentheses together with locales), trailing ' - 14.38.33135'
    versions, embedded dotted versions, locale tails (' - en-us') and 'release'/'version' leftovers.
    Returns (clean name, embedded version, arch)."""
    s = raw.strip()
    arch: list[str] = []

    def paren(m: re.Match) -> str:
        toks = _tag_group(m.group(1))
        if toks is None:
            return m.group(0)
        arch.extend(t for t in toks if t in _ARCH_TOKENS)
        return " "

    s = re.sub(r"\(([^()]*)\)", paren, s)
    for m in _ARCH_WORD.finditer(s):
        arch.append(m.group(1).lower())
    s = _ARCH_WORD.sub(" ", s)
    s = _LOCALE_TAIL.sub("", s)
    ver = None
    m = _TRAIL_VERSION.search(s)
    if m:
        ver, s = m.group(1), s[:m.start()]
    else:
        m = _EMBEDDED_VERSION.search(s)
        if m:
            ver, s = m.group(1), s[:m.start()] + " " + s[m.end():]
    s = " ".join(s.split())
    s = _TRAIL_WORD.sub("", s)
    s = re.sub(r"^[\s\-,:;]+|[\s\-,:;]+$", "", s)
    s = " ".join(s.split())
    a = None
    if arch:
        a = "arm64" if "arm64" in arch else "x64" if ({"x64", "amd64", "64-bit", "64bit"} & set(arch)) else "x86"
    return (s or raw.strip()), ver, a


def _clean_version(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip()
    if re.fullmatch(r"[\w.+\-]+", v):
        return v.lstrip("vV") if re.match(r"^[vV]\d", v) else v
    m = _VERSION_TOKEN.search(v)
    return m.group(0) if m else v


_PUBLISHER_SUFFIX = re.compile(
    r"[,\s]+(inc|llc|ltd|gmbh|corporation|corp|co|limited|foundation|software|s\.a\.|ag)\.?$", re.IGNORECASE)


def _vendor_hint(publisher: str | None) -> str | None:
    if not publisher:
        return None
    p = publisher.strip()
    m = re.search(r"CN=([^,]+)", p)       # Appx publisher: "CN=Microsoft Corporation, O=..., C=US"
    if m:
        p = m.group(1)
    else:
        p = p.split(",")[0]           # "Zoom Video Communications, Inc." / "The Wireshark developer community, https://..."
    for _ in range(3):
        p = _PUBLISHER_SUFFIX.sub("", p)
    slug = re.sub(r"[^a-z0-9]+", "-", p.lower()).strip("-")
    return slug or None


# --------------------------------------------------------------------------- programs (Uninstall keys)

_GUID = re.compile(r"^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$", re.IGNORECASE)
_UPDATE_RELEASE = {"update", "hotfix", "security update", "update rollup", "critical update", "service pack"}
_UPDATE_NAME = re.compile(r"^(security update|update|hotfix|servicing stack update)\b.*\bfor\b|\(KB\d{6,8}\)\s*$|^KB\d{6,8}\b",
                          re.IGNORECASE)
_PYTHON_PART = re.compile(r"^Python\s+\d+\.\d+.*\b(Core Interpreter|Documentation|Standard Library|Development Libraries|"
                          r"Executables|pip Bootstrap|Tcl/Tk Support|Test Suite|Add to Path)\b", re.IGNORECASE)
# .NET runtimes are taken from the dotnet directories; their Uninstall entries (and the SDKs, whose
# 8.0.4xx versions are not runtime versions) would only duplicate or mislead.
_DOTNET_PROGRAM = re.compile(r"^Microsoft (\.NET|ASP\.NET Core|Windows Desktop Runtime|Windows Desktop)\b", re.IGNORECASE)


def _is_update(e: dict) -> bool:
    if e.get("parent_key_name") or str(e.get("release_type") or "").lower() in _UPDATE_RELEASE:
        return True
    return bool(_UPDATE_NAME.search(str(e.get("display_name") or "")) or re.match(r"^KB\d+", str(e.get("key_name") or ""), re.IGNORECASE))


def _program_key(e: dict) -> tuple[str, str | None, Any]:
    raw = str(e.get("display_name") or "")
    name, emb, arch = normalize_display_name(raw)
    ver = _clean_version(e.get("display_version"))
    if name.lower() in _VERSION_FROM_NAME and emb or ver is None:
        ver = emb
    return name, ver, arch


def programs_from_uninstall(entries: list[dict], warnings: list[str], skip_dotnet: bool = False) -> list[Component]:
    """Uninstall-key entries -> application components (updates, system components and 32/64-bit
    duplicates removed)."""
    groups: dict[tuple[str, str | None], dict[str, Any]] = {}
    for e in entries or []:
        raw = e.get("display_name")
        if not raw or not str(raw).strip():
            continue
        if _int(e.get("system_component")) == 1 or _is_update(e):
            continue
        if _PYTHON_PART.match(str(raw)) or (skip_dotnet and _DOTNET_PROGRAM.match(normalize_display_name(str(raw))[0])):
            continue
        name, ver, arch = _program_key(e)
        if arch is None and e.get("wow6432") is True:
            arch = "x86"
        g = groups.setdefault((name.lower(), ver), {"name": name, "version": ver, "members": []})
        g["members"].append((e, arch))
    rank = {"x64": 0, "arm64": 0, None: 1, "x86": 2}
    out: list[Component] = []
    for g in groups.values():
        members = sorted(g["members"], key=lambda m: (rank.get(m[1], 1), bool(m[0].get("wow6432")),
                                                      m[0].get("scope") != "machine"))
        e, arch = members[0]
        name, ver = g["name"], g["version"]
        vendor_hint = _vendor_hint(e.get("publisher"))
        key_name = str(e.get("key_name") or "")
        meta: dict[str, Any] = {
            "product_hint": name.lower(), "display_name": e.get("display_name"),
            "publisher": e.get("publisher"), "vendor_hint": vendor_hint, "arch": arch,
            "install_location": e.get("install_location"), "install_date": e.get("install_date"),
            "registry_key": key_name,
            "scope": e.get("scope"), "source": "registry-uninstall",
            "msi_product_code": key_name.upper() if _GUID.match(key_name) and
            _int(e.get("windows_installer")) == 1 else None,
        }
        variants = sorted({a or "unknown" for _, a in members})
        if len(variants) > 1:
            meta["arch_variants"] = variants
        scopes = sorted({str(m[0].get("scope")) for m in members if m[0].get("scope")})
        users = sorted({str(m[0].get("user")) for m in members if m[0].get("user")})
        if len(scopes) > 1:
            meta["scopes"] = scopes
        if users:
            meta["users"] = users
        hive = e.get("hive") or "HKLM"
        out.append(Component(
            name=name, version=ver, category=CAT_APPLICATION,
            purl=purls.build("generic", name, ver, namespace=vendor_hint),
            source_path=f"{hive}\\...\\Uninstall\\{key_name}",
            meta={k: v for k, v in meta.items() if v not in (None, "")}))
    return out


# --------------------------------------------------------------------------- Appx / MSIX

# Appx package Name -> product hint where the package name is not the product name
_APPX_HINTS = {"msteams": "microsoft teams", "microsoft.windowsterminal": "windows terminal",
               "microsoft.powershell": "powershell"}


def appx_components(items: list[dict], include_system: bool = True) -> tuple[list[Component], int]:
    """Appx/MSIX packages -> components. Returns (components, skipped framework packages)."""
    seen: dict[tuple[str, str], Component] = {}
    skipped = 0
    for p in items or []:
        name, ver = p.get("name"), p.get("version")
        if not name or not ver:
            continue
        if p.get("is_framework"):
            skipped += 1
            continue
        system = str(p.get("signature_kind") or "").lower() == "system"
        if system and not include_system:
            continue
        arch = str(p.get("architecture") or "").lower() or None
        key = (name.lower(), ver)
        if key in seen:
            seen[key].meta.setdefault("arch_variants", [])
            if arch and arch not in seen[key].meta["arch_variants"]:
                seen[key].meta["arch_variants"].append(arch)
            continue
        vendor_hint = _vendor_hint(p.get("publisher"))
        meta = {"product_hint": _APPX_HINTS.get(name.lower(), name.lower()), "publisher": p.get("publisher"),
                "vendor_hint": vendor_hint, "package_full_name": p.get("package_full_name"), "arch": arch,
                "signature_kind": p.get("signature_kind"), "install_location": p.get("install_location"),
                "source": "appx"}
        if arch:
            meta["arch_variants"] = [arch]
        seen[key] = Component(
            name=name, version=ver, category=CAT_SYSTEM_APP if system else CAT_APPLICATION,
            purl=purls.build("generic", name, ver, namespace="appx"),
            source_path=p.get("install_location") or p.get("package_full_name"),
            meta={k: v for k, v in meta.items() if v not in (None, "")})
    return list(seen.values()), skipped


# --------------------------------------------------------------------------- Chocolatey / Scoop

def _alias_identity(hint: str) -> tuple[str, str] | None:
    from ..engine.classify import normalize_product_name, product_aliases

    aliases = product_aliases()
    hit = aliases.get(hint.lower()) or aliases.get(normalize_product_name(hint))
    return (hit["vendor"], hit["product"]) if hit else None


def _same_as_program(hint: str, version: str | None, programs: list[Component]) -> Component | None:
    ident = _alias_identity(hint)
    if ident is None:
        return None
    for p in programs:
        pid = _alias_identity(p.meta.get("product_hint") or p.name)
        if pid == ident and (not version or not p.version or compare(version, p.version) == 0):
            return p
    return None


def chocolatey_components(items: list[dict], programs: list[Component]) -> list[Component]:
    out: list[Component] = []
    for c in items or []:
        cid, ver = (c.get("id") or "").strip(), (c.get("version") or "").strip() or None
        if not cid:
            continue
        hint = re.sub(r"\.(install|portable|commandline)$", "", cid.lower())
        dup = _same_as_program(hint, ver, programs)
        if dup is not None:                      # installed by choco *and* registered in Uninstall
            dup.meta["also_chocolatey"] = cid
            continue
        meta = {"product_hint": hint, "choco_id": cid, "title": c.get("title"), "authors": c.get("authors"),
                "project_url": c.get("project_url"), "source": "chocolatey"}
        out.append(Component(name=cid, version=ver, category=CAT_PACKAGE,
                             purl=purls.build("chocolatey", cid.lower(), ver), source_path=c.get("path"),
                             meta={k: v for k, v in meta.items() if v}))
    return out


def scoop_components(items: list[dict], programs: list[Component]) -> list[Component]:
    out: list[Component] = []
    seen: set[tuple[str, str | None]] = set()
    for s in items or []:
        app, ver = (s.get("app") or "").strip(), (s.get("version") or "").strip() or None
        if not app or (app.lower(), ver) in seen:
            continue
        seen.add((app.lower(), ver))
        dup = _same_as_program(app, ver, programs)
        if dup is not None:
            dup.meta["also_scoop"] = app
            continue
        meta = {"product_hint": app.lower(), "scoop_bucket": s.get("bucket"), "arch": s.get("architecture"),
                "homepage": s.get("homepage"), "user": s.get("user"), "global": s.get("global") or None,
                "source": "scoop"}
        out.append(Component(name=app, version=ver, category=CAT_PACKAGE,
                             purl=purls.build("generic", app.lower(), ver, namespace="scoop"),
                             source_path=s.get("root"), meta={k: v for k, v in meta.items() if v}))
    return out


# --------------------------------------------------------------------------- .NET

_DOTNET_FX = {
    "microsoft.netcore.app": (".NET", ".net", "dotnet-runtime"),
    "microsoft.aspnetcore.app": ("ASP.NET Core", "asp.net core", "aspnetcore-runtime"),
    "microsoft.aspnetcore.all": ("ASP.NET Core", "asp.net core", "aspnetcore-runtime"),
    "microsoft.windowsdesktop.app": (".NET Desktop Runtime", ".net", "dotnet-desktop-runtime"),
}


def dotnet_components(items: list[dict]) -> list[Component]:
    """Shared-framework directories (dotnet/shared/<fx>/<version>) -> runtime components.

    Microsoft CNA names them ".NET 8.0" / "ASP.NET Core 8.0" and cpeApplicability uses
    microsoft:.net / microsoft:asp.net_core: the component name carries the CNA spelling (normalized
    name candidate) and meta.product the CPE spelling, so both kinds of `affected` rows are looked up."""
    out: dict[tuple[str, str, str], Component] = {}
    for r in items or []:
        fx, ver = str(r.get("name") or ""), str(r.get("version") or "")
        spec = _DOTNET_FX.get(fx.lower())
        m = re.match(r"^(\d+)\.(\d+)\.", ver + ".")
        if not spec or not m:
            continue
        label, product, slug = spec
        arch = str(r.get("arch") or "").lower() or None
        key = (fx.lower(), ver, arch or "")
        if key in out:
            continue
        out[key] = Component(
            name=f"{label} {m.group(1)}.{m.group(2)}", version=ver, category=CAT_RUNTIME, vendor="microsoft",
            purl=purls.build("generic", slug, ver, namespace="microsoft", qualifiers={"arch": arch}),
            source_path=r.get("path"),
            meta={k: v for k, v in {"product": product, "product_source": "alias-table",
                                    "framework": fx, "arch": arch, "source": "dotnet-shared"}.items() if v})
    return list(out.values())


# --------------------------------------------------------------------------- inventory JSON

def _hotfixes(items: list[dict]) -> list[dict]:
    return [h for h in items or [] if isinstance(h, dict) and h.get("id")]


def parse_inventory_json(data: dict | str | bytes, include_system: bool = True) -> Inventory:
    """`secmonk-windows-inventory/1` document (output of secmonk-inventory.ps1) -> Inventory."""
    if isinstance(data, (str, bytes)):
        data = json.loads(data.decode("utf-8-sig") if isinstance(data, bytes) else data.lstrip("\ufeff"))
    if not isinstance(data, dict):
        raise TypeError("not a Windows inventory document")
    schema = str(data.get("schema") or "")
    if not schema.startswith("secmonk-windows-inventory/"):
        raise ValueError(f"unexpected schema {schema!r} (want {SCHEMA})")
    warnings: list[str] = [f"script: {w}" for w in data.get("warnings") or []]
    os_info = data.get("os") or {}
    hotfixes = _hotfixes(data.get("hotfixes"))
    hostname = str(data.get("hostname") or "unknown")

    extra: dict[str, Any] = {}
    if data.get("dotnet_framework"):
        extra["dotnet_framework"] = data["dotnet_framework"]
    os_c = os_component(os_info, hotfixes, warnings, extra)
    if hotfixes:
        dated = [h["installed_on"] for h in hotfixes if h.get("installed_on")]
        if dated:
            os_c.meta["last_hotfix_on"] = max(dated)

    runtimes = dotnet_components(data.get("dotnet_runtimes"))
    programs = programs_from_uninstall(data.get("uninstall"), warnings, skip_dotnet=bool(runtimes))
    appx, fw = appx_components(data.get("appx"), include_system=include_system)
    comps = [os_c, *programs, *appx,
             *chocolatey_components(data.get("chocolatey"), programs),
             *scoop_components(data.get("scoop"), programs), *runtimes]

    for p in data.get("unloaded_profiles") or []:
        warnings.append(f"user hive of {p.get('user') or p.get('sid')} not loaded: per-user installs not inventoried")

    itype = str(os_info.get("installation_type") or "")
    is_server = windows_os_identity(os_info)["family"] == "server"
    arch = str(os_info.get("architecture") or "").lower()
    build, ubr = _int(os_info.get("current_build")), _int(os_info.get("ubr"))
    dv = os_info.get("display_version") or os_info.get("release_id")
    os_version = f"{dv} (build {build}.{ubr})" if dv else (f"build {build}.{ubr}" if build else None)
    meta = {k: v for k, v in {
        "collected_at": data.get("collected_at"), "domain": data.get("domain"),
        "is_admin": data.get("is_admin"), "installation_type": itype or None,
        "edition": os_info.get("edition_id"), "script_version": data.get("script_version"),
        "dotnet_sdks": [s.get("version") for s in data.get("dotnet_sdks") or [] if s.get("version")] or None,
        "winget": [{"id": w.get("id"), "version": w.get("version")} for w in data.get("winget") or []] or None,
        "appx_frameworks_skipped": fw or None,
    }.items() if v not in (None, "")}
    asset = Asset(id=f"windows:{hostname}", type="server" if is_server else "desktop", name=hostname,
                  os_name=windows_os_identity(os_info)["marketing_name"], os_version=os_version,
                  platform=_PLATFORM.get(arch), meta=meta)
    return Inventory(asset=asset, collector="windows", components=comps, warnings=warnings)


# --------------------------------------------------------------------------- osquery

_OSQ_REGISTRY_NAMES = {"UBR": "ubr", "DisplayVersion": "display_version", "EditionID": "edition_id",
                       "InstallationType": "installation_type", "ProductName": "product_name",
                       "CurrentBuild": "current_build", "ReleaseId": "release_id"}


def _rows(data: dict, table: str) -> list[dict]:
    v = data.get(table)
    if isinstance(v, dict):
        return [v]
    return [r for r in v or [] if isinstance(r, dict)]


def parse_osquery(data: dict | list | str | bytes, hostname: str | None = None,
                  include_system: bool = True) -> Inventory:
    """osquery results -> Inventory. `data` maps table name -> rows, e.g. the merge of

        SELECT * FROM programs;  SELECT * FROM os_version;  SELECT * FROM patches;
        SELECT name, data FROM registry WHERE path LIKE
          'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\%';   -- UBR, DisplayVersion...
        SELECT hostname FROM system_info;

    The UBR comes from os_version.revision (newer osquery) or from the registry rows; without it the
    OS version is unknown and OS matching is skipped (see _os_version)."""
    if isinstance(data, (str, bytes)):
        data = json.loads(data.decode("utf-8-sig") if isinstance(data, bytes) else data)
    if not isinstance(data, dict):
        raise TypeError("osquery input must be an object {table: [rows]}")
    os_rows = _rows(data, "os_version")
    osr = os_rows[0] if os_rows else {}
    reg = {str(r.get("name")): r.get("data") for r in _rows(data, "registry")}
    os_info: dict[str, Any] = {
        "product_name": re.sub(r"^Microsoft\s+", "", str(osr.get("name") or "")) or None,
        "current_build": osr.get("build"), "ubr": osr.get("revision") if osr.get("revision") not in (None, "") else None,
        "major": osr.get("major"), "minor": osr.get("minor"),
        "architecture": {"64-bit": "AMD64", "32-bit": "x86", "arm64": "ARM64"}.get(str(osr.get("arch") or "").lower(),
                                                                                  osr.get("arch")),
    }
    for reg_name, key in _OSQ_REGISTRY_NAMES.items():
        if reg_name in reg and reg[reg_name] not in (None, ""):
            os_info[key] = reg[reg_name]
    if os_info.get("installation_type") is None and "server" in str(os_info.get("product_name") or "").lower():
        os_info["installation_type"] = "Server"
    sysinfo = _rows(data, "system_info")
    host = hostname or data.get("hostname") or (sysinfo[0].get("hostname") if sysinfo else None) or "unknown"
    uninstall = [{
        "hive": "HKLM", "scope": "machine", "key_name": r.get("identifying_number") or None,
        "display_name": r.get("name"), "display_version": r.get("version"), "publisher": r.get("publisher"),
        "install_date": r.get("install_date"), "install_location": r.get("install_location"),
        "windows_installer": 1 if r.get("identifying_number") else None,
    } for r in _rows(data, "programs")]
    hotfixes = [{"id": r.get("hotfix_id"), "description": r.get("description"),
                 "installed_on": r.get("installed_on")} for r in _rows(data, "patches")]
    doc = {"schema": SCHEMA, "hostname": host, "os": os_info, "uninstall": uninstall, "hotfixes": hotfixes,
           "appx": [], "chocolatey": [], "scoop": []}
    inv = parse_inventory_json(doc, include_system=include_system)
    inv.warnings.insert(0, "osquery input: no Appx/Chocolatey/Scoop/.NET data, per-user installs depend on osquery config")
    return inv


# --------------------------------------------------------------------------- live mode (Windows only)

_VALUE_MAP = {"DisplayName": "display_name", "DisplayVersion": "display_version", "Publisher": "publisher",
              "InstallDate": "install_date", "InstallLocation": "install_location",
              "SystemComponent": "system_component", "WindowsInstaller": "windows_installer",
              "ParentKeyName": "parent_key_name", "ReleaseType": "release_type"}


def _reg_value(winreg: Any, key: Any, name: str) -> Any:
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def _reg_subkeys(winreg: Any, key: Any) -> list[str]:
    out, i = [], 0
    while True:
        try:
            out.append(winreg.EnumKey(key, i))
        except OSError:
            return out
        i += 1


def _live_uninstall(winreg: Any, hive: Any, hive_name: str, prefix: str, view: int, wow: bool,
                    scope: str, sid: str | None, user: str | None) -> list[dict]:
    path = (prefix + "\\" if prefix else "") + r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    try:
        root = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view)
    except OSError:
        return []
    out: list[dict] = []
    try:
        for sub in _reg_subkeys(winreg, root):
            try:
                k = winreg.OpenKey(root, sub, 0, winreg.KEY_READ | view)
            except OSError:
                continue
            try:
                entry: dict[str, Any] = {"hive": hive_name, "scope": scope, "sid": sid, "user": user,
                                         "wow6432": wow, "key_name": sub}
                for reg_name, field in _VALUE_MAP.items():
                    v = _reg_value(winreg, k, reg_name)
                    entry[field] = v if field in ("system_component", "windows_installer") or v is None else str(v)
                if entry.get("display_name"):
                    out.append(entry)
            finally:
                winreg.CloseKey(k)
    finally:
        winreg.CloseKey(root)
    return out


def _live_os(winreg: Any) -> dict:
    out: dict[str, Any] = {}
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0,
                           winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except OSError:
        return out
    try:
        for reg_name, field in (("ProductName", "product_name"), ("DisplayVersion", "display_version"),
                                ("ReleaseId", "release_id"), ("CurrentBuild", "current_build"),
                                ("UBR", "ubr"), ("EditionID", "edition_id"),
                                ("InstallationType", "installation_type"), ("CurrentVersion", "current_version"),
                                ("CurrentMajorVersionNumber", "major"), ("CurrentMinorVersionNumber", "minor")):
            v = _reg_value(winreg, k, reg_name)
            if v is not None:
                out[field] = v if isinstance(v, int) else str(v)
    finally:
        winreg.CloseKey(k)
    return out


def _powershell_json(command: str, timeout: int = 120) -> list[dict] | None:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return None
    full = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
            f"$r = @({command}); ConvertTo-Json -InputObject $r -Depth 3 -Compress")
    try:
        cp = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", full],
                            capture_output=True, timeout=timeout, check=False)
        if cp.returncode != 0 or not cp.stdout.strip():
            return None
        data = json.loads(cp.stdout.decode("utf-8-sig"))
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return [d for d in (data if isinstance(data, list) else [data]) if isinstance(d, dict)]


def _scan_chocolatey(root: Path) -> list[dict]:
    out: list[dict] = []
    lib = root / "lib"
    if not lib.is_dir():
        return out
    for nuspec in sorted(lib.glob("*/*.nuspec")):
        try:
            meta = {c.tag.split("}")[-1]: (c.text or "").strip() for c in ET.parse(nuspec).getroot().iter()
                    if c.tag.split("}")[-1] in ("id", "version", "title", "authors", "projectUrl")}
        except (ET.ParseError, OSError):
            continue
        out.append({"id": meta.get("id"), "version": meta.get("version"), "title": meta.get("title"),
                    "authors": meta.get("authors"), "project_url": meta.get("projectUrl"),
                    "path": str(nuspec.parent)})
    return out


def _scan_scoop(roots: list[Path]) -> list[dict]:
    out: list[dict] = []
    for root in roots:
        for app in sorted((root / "apps").glob("*")) if (root / "apps").is_dir() else []:
            mf = app / "current" / "manifest.json"
            if not mf.is_file():
                continue
            try:
                man = json.loads(mf.read_text(encoding="utf-8-sig"))
                inst: dict = {}
                if (app / "current" / "install.json").is_file():
                    inst = json.loads((app / "current" / "install.json").read_text(encoding="utf-8-sig"))
            except (OSError, ValueError):
                continue
            out.append({"app": app.name, "version": man.get("version"), "bucket": inst.get("bucket"),
                        "architecture": inst.get("architecture"), "homepage": man.get("homepage"),
                        "root": str(root)})
    return out


def _scan_dotnet(roots: list[tuple[Path, str]]) -> list[dict]:
    out: list[dict] = []
    for root, arch in roots:
        shared = root / "shared"
        for fx in sorted(shared.glob("*")) if shared.is_dir() else []:
            for vd in sorted(fx.glob("*")):
                if vd.is_dir():
                    out.append({"name": fx.name, "version": vd.name, "arch": arch, "path": str(vd)})
    return out


def read_live_inventory() -> dict:
    """Build a `secmonk-windows-inventory/1` document from the running Windows host."""
    if sys.platform != "win32":
        raise RuntimeError("live Windows collection only works on Windows (sys.platform == 'win32')")
    import os
    import platform
    import winreg

    warnings: list[str] = []
    uninstall: list[dict] = []
    is64 = platform.machine().lower() in ("amd64", "arm64", "x86_64")
    uninstall += _live_uninstall(winreg, winreg.HKEY_LOCAL_MACHINE, "HKLM", "", winreg.KEY_WOW64_64KEY,
                                 False, "machine", None, None)
    if is64:
        uninstall += _live_uninstall(winreg, winreg.HKEY_LOCAL_MACHINE, "HKLM", "", winreg.KEY_WOW64_32KEY,
                                     True, "machine", None, None)
    try:
        sids = _reg_subkeys(winreg, winreg.HKEY_USERS)
    except OSError:
        sids = []
        warnings.append("cannot enumerate HKU")
    for sid in sids:
        if sid.endswith("_Classes") or not re.match(r"^S-1-(5-21|12-1)-", sid):
            continue
        uninstall += _live_uninstall(winreg, winreg.HKEY_USERS, "HKU", sid, winreg.KEY_WOW64_64KEY, False,
                                     "user", sid, None)
    os_info = _live_os(winreg)
    os_info["architecture"] = platform.machine()
    appx = _powershell_json(
        "Get-AppxPackage | Select-Object @{n='name';e={$_.Name}},@{n='package_full_name';e={$_.PackageFullName}},"
        "@{n='version';e={[string]$_.Version}},@{n='publisher';e={$_.Publisher}},"
        "@{n='architecture';e={[string]$_.Architecture}},@{n='signature_kind';e={[string]$_.SignatureKind}},"
        "@{n='is_framework';e={[bool]$_.IsFramework}},@{n='install_location';e={$_.InstallLocation}}")
    if appx is None:
        warnings.append("Appx packages unavailable (PowerShell missing or failed)")
    hot = _powershell_json(
        "Get-CimInstance Win32_QuickFixEngineering | Select-Object @{n='id';e={$_.HotFixID}},description,"
        "@{n='installed_on';e={if($_.InstalledOn){$_.InstalledOn.ToString('yyyy-MM-dd')}}}")
    if hot is None:
        warnings.append("hotfixes unavailable (PowerShell missing or failed)")
    pf = Path(os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles", r"C:\Program Files"))
    pf86 = os.environ.get("ProgramFiles(x86)")
    native = "arm64" if platform.machine().lower() == "arm64" else "x64"
    dn_roots = [(pf / "dotnet", native)] + ([(Path(pf86) / "dotnet", "x86")] if pf86 else [])
    choco_root = Path(os.environ.get("ChocolateyInstall") or Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "chocolatey")
    scoop_roots = [Path(p) for p in (os.environ.get("SCOOP"), os.environ.get("SCOOP_GLOBAL"),
                                     str(Path.home() / "scoop")) if p]
    return {"schema": SCHEMA, "collected_at": None, "hostname": socket.gethostname(),
            "os": os_info, "uninstall": uninstall, "appx": appx or [], "hotfixes": hot or [],
            "chocolatey": _scan_chocolatey(choco_root), "scoop": _scan_scoop(scoop_roots),
            "winget": None, "dotnet_runtimes": _scan_dotnet(dn_roots), "warnings": warnings}


def collect_live(include_system: bool = True) -> Inventory:
    """Inventory the Windows host this process runs on (guarded: raises elsewhere)."""
    return parse_inventory_json(read_live_inventory(), include_system=include_system)


# --------------------------------------------------------------------------- collector

@register
class WindowsCollector(Collector):
    name = "windows"
    description = ("Windows host: JSON from scripts/windows/secmonk-inventory.ps1 (target), osquery results "
                   "(-o osquery=<file>) or live on Windows")

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        include_system = opts.get("include_system", True) is not False
        osq = opts.get("osquery")
        if osq:
            return parse_osquery(load_json_file(osq), hostname=opts.get("hostname"), include_system=include_system)
        if target:
            data = load_json_file(target)
            if isinstance(data, dict) and str(data.get("schema", "")).startswith("secmonk-windows-inventory/"):
                inv = parse_inventory_json(data, include_system=include_system)
            elif isinstance(data, dict) and ("programs" in data or "os_version" in data):
                inv = parse_osquery(data, hostname=opts.get("hostname"), include_system=include_system)
            else:
                raise ValueError(f"{target}: neither a secmonk Windows inventory nor osquery results")
        elif sys.platform == "win32":
            inv = collect_live(include_system=include_system)
        else:
            raise ValueError("windows collector: pass the JSON from secmonk-inventory.ps1 "
                             "(`secmonk scan windows inventory.json`), `-o osquery=<file>`, or run on Windows")
        if opts.get("hostname"):
            inv.asset.id = f"windows:{opts['hostname']}"
            inv.asset.name = str(opts["hostname"])
        return inv
