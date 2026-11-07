"""Homebrew / Linuxbrew inventory collector (offline, read-only; never executes `brew` or formulae).

Target: a prefix directory (contains `Cellar/` or `Caskroom/`) or a root directory in which the
known prefixes are searched (/opt/homebrew, /usr/local, /home/linuxbrew/.linuxbrew, ~/.linuxbrew).
`collect_prefixes()` is also what the macOS collector calls.
See _docs/tech/collectors/homebrew.md and _docs/references/homebrew.md.
"""

from __future__ import annotations

import json
import os
import re
import socket
from functools import cmp_to_key
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from ..engine import purl as purls
from ..engine.versions import compare
from ..models import CAT_APPLICATION, CAT_LIBRARY, CAT_PACKAGE, Asset, Component, Inventory
from .base import Collector, read_within, register, resolve_within, strip_url_secrets
from .lang.walk import WalkLimits, walk_dir

KNOWN_PREFIXES = ("opt/homebrew", "usr/local", "home/linuxbrew/.linuxbrew")
_REVISION = re.compile(r"_\d+$")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
MAX_RB_BYTES = 1024 * 1024               # formula / cask Ruby source (data, never evaluated)
MAX_JSON_BYTES = 16 * 1024 * 1024        # receipts, SBOMs, cask JSON
MAX_LINE = 2000                          # longer lines are cut: keeps every regex below linear


# --------------------------------------------------------------------------- components

def _brew_purl(kind: str, name: str, version: str | None, tap: str | None) -> str:
    if kind == "cask":
        return purls.build("brew", name, version, namespace="homebrew/cask")
    if tap and tap.lower() != "homebrew/core":
        return purls.build("brew", name, version, namespace=tap.lower())
    return purls.build("brew", name, version)


def _formula_component(name: str, raw_version: str, tap: str | None, **meta: Any) -> Component:
    """`version` is the upstream version (`_N` revision stripped); the raw pkg_version stays in meta."""
    version = _REVISION.sub("", raw_version)
    m = {"brew_name": name, "brew_kind": "formula", "brew_version": raw_version, "tap": tap}
    m.update({k: v for k, v in meta.items() if v is not None})
    return Component(name=name, version=version, category=CAT_PACKAGE,
                     purl=_brew_purl("formula", name, raw_version, tap), meta=m)


def _cask_component(token: str, version: str | None, names: list[str] | None = None,
                    homepage: str | None = None, apps: list[str] | None = None,
                    tap: str | None = None, **extra: Any) -> Component:
    display = (names or [None])[0] or token
    meta = {"brew_name": token, "brew_kind": "cask", "brew_version": version,
            "homepage": homepage, "cask_apps": apps or [], "tap": tap, **extra}
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
        for inst in f.get("installed") or []:
            ver = inst.get("version")
            if not name or not ver:
                continue
            comps.append(_formula_component(
                name, ver, f.get("tap"),
                installed_on_request=inst.get("installed_on_request"),
                runtime_dependencies=len(inst.get("runtime_dependencies") or []),
                homepage=f.get("homepage"), license=f.get("license"),
                source_url=((f.get("urls") or {}).get("stable") or {}).get("url"),
            ))
    for c in data.get("casks", []) or []:
        token = c.get("token")
        if not token or not c.get("installed"):
            continue
        comps.append(_cask_component(token, c.get("installed") or c.get("version"), c.get("name"),
                                     c.get("homepage"), _cask_apps(c.get("artifacts")), c.get("tap")))
    return comps


# --------------------------------------------------------------------------- upstream identity

_FORGE_HOSTS = {  # host -> segments forming the repo path (None = 2)
    "gitlab.com": None, "gitlab.gnome.org": None, "gitlab.freedesktop.org": None, "invent.kde.org": None,
    "codeberg.org": 2, "bitbucket.org": 2,
}
_GITHUB_HOSTS = {"github.com", "www.github.com", "codeload.github.com", "raw.githubusercontent.com"}
_NOT_ORGS = {"downloads", "sponsors", "orgs", "apps", "repos"}


def repo_from_url(url: str | None) -> str | None:
    """`github.com/org/repo` (forge host + path, lowercase) from a homepage/source/download URL."""
    if not url:
        return None
    try:
        u = urlparse(url.strip())
    except ValueError:
        return None
    host = (u.hostname or "").lower()
    parts = [unquote(p) for p in u.path.split("/") if p]
    if host == "api.github.com" and parts[:1] == ["repos"]:
        host, parts = "github.com", parts[1:]
    if host in _GITHUB_HOSTS and len(parts) >= 2 and parts[0].lower() not in _NOT_ORGS:
        return f"github.com/{parts[0].lower()}/{re.sub(r'[.]git$', '', parts[1].lower())}"
    if host.endswith(".github.io") and host != "github.io":
        org = host.split(".")[0]
        return f"github.com/{org.lower()}/{parts[0].lower()}" if parts else None
    if host in _FORGE_HOSTS:
        if "-" in parts:
            parts = parts[:parts.index("-")]
        n = _FORGE_HOSTS[host]
        parts = parts[:n] if n else parts[:2]
        if len(parts) >= 2:
            return f"{host}/{'/'.join(parts).removesuffix('.git')}"
    # sourceforge
    m = re.match(r"^/projects?/([^/]+)", u.path)
    if host.endswith("sourceforge.net") and m:
        return f"sourceforge.net/projects/{m.group(1).lower()}"
    if host.endswith((".sourceforge.net", ".sourceforge.io")) and host.split(".")[0] not in (
            "downloads", "prdownloads", "www", "master", "sourceforge"):
        return f"sourceforge.net/projects/{host.split('.')[0]}"
    return None


_TAG_PATTERNS = (
    re.compile(r"/releases/download/([^/]+)/"),
    re.compile(r"/archive/refs/tags/(.+?)(?:\.tar\.(?:gz|bz2|xz)|\.tgz|\.zip)$"),
    re.compile(r"/-/archive/([^/]+)/"),
    re.compile(r"/archive/([^/]+?)(?:\.tar\.(?:gz|bz2|xz)|\.tgz|\.zip)$"),
)


def tag_from_url(url: str | None) -> str | None:
    if not url or not repo_from_url(url):
        return None
    for rx in _TAG_PATTERNS:
        m = rx.search(url)
        if m:
            return unquote(m.group(1))
    return None


def registry_purl_from_url(url: str | None) -> str | None:
    """Registry purl when the source URL is a registry artifact (PyPI, npm, crates.io, RubyGems)."""
    if not url:
        return None
    u = urlparse(url)
    host, path = (u.hostname or "").lower(), unquote(u.path)
    if host == "files.pythonhosted.org":
        m = re.match(r"^(?P<n>.+?)-(?P<v>\d[^/]*?)(?:\.tar\.gz|\.zip|\.tar\.bz2|-py[^/]*\.whl|\.whl)$",
                     path.rsplit("/", 1)[-1])
        if m:
            return purls.build("pypi", m.group("n").replace("_", "-").lower(), m.group("v"))
    elif host == "registry.npmjs.org":
        m = re.match(r"^/(@[^/]+/[^/]+|[^/]+)/-/[^/]+-(\d[^/]*)\.tgz$", path)
        if m:
            n = m.group(1)
            ns, _, name = n.rpartition("/")
            return purls.build("npm", name, m.group(2), namespace=ns or None)
    elif host in ("crates.io", "static.crates.io"):
        m = re.match(r"^/(?:api/v1/)?crates/([^/]+)/(?:[^/]+-)?(\d[^/]*?)(?:/download|\.crate)$", path)
        if m:
            return purls.build("cargo", m.group(1), m.group(2))
    elif host == "rubygems.org":
        m = re.match(r"^/downloads/(.+)-(\d[^-/]*)\.gem$", path)
        if m:
            return purls.build("gem", m.group(1), m.group(2))
    return None


# --------------------------------------------------------------------------- formula text (.brew/<name>.rb)

def _strings(s: str) -> list[str]:
    return re.findall(r'"([^"]*)"', s)


def _license_of(body: str) -> str | None:
    ids = [x for x in _strings(body) if x]
    if not ids:
        return None
    if len(ids) == 1:
        return ids[0]
    return (" AND " if "all_of" in body else " OR ").join(ids)


def _patch_cves(lines: list[str]) -> list[str]:
    """CVE ids mentioned in `patch` stanzas: the stanza itself (url, resolves, inline diff headers)
    and the comment lines immediately above it."""
    found: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^(\s*)patch\b(.*)$", line)
        if not m:
            i += 1
            continue
        indent, rest = m.group(1), m.group(2)
        chunk = [line]
        j = i - 1
        while j >= 0 and lines[j].lstrip().startswith("#"):
            chunk.append(lines[j])
            j -= 1
        k = i + 1
        hd = re.search(r"<<[~-]?['\"]?(\w+)['\"]?", rest)
        if hd:
            while k < len(lines) and lines[k].strip() != hd.group(1):
                chunk.append(lines[k])
                k += 1
        elif rest.rstrip().endswith("do") or re.search(r"\bdo\s*\|[^|]*\|\s*$", rest[:200]):
            while k < len(lines) and not re.match(rf"^{indent}end\b", lines[k]):
                chunk.append(lines[k])
                k += 1
        for cve in _CVE.findall("\n".join(chunk)):
            cve = cve.upper()
            if cve not in found:
                found.append(cve)
        i = max(k, i + 1)
    return found


_STANZA = re.compile(r"^  (\w+[!?]?)(?:\s+(.*))?$")
_STR = re.compile(r'^"([^"]*)"')


def parse_formula_rb(text: str) -> dict[str, Any]:
    """Line-based extraction from formula Ruby source (single pass, linear time). The text is data:
    nothing is evaluated."""
    out: dict[str, Any] = {}
    lines = [ln[:MAX_LINE] for ln in text[:MAX_RB_BYTES].splitlines()]
    block: str | None = None                  # "stable" / "head" while inside `stable do` / `head do`
    license_lines: list[str] | None = None
    stable_url = head_url = None
    for ln in lines:
        if license_lines is not None:
            if ln.startswith("  ") and not ln.startswith("   ") and ln.strip():
                out["license"] = _license_of(" ".join(license_lines))
                license_lines = None
            else:
                license_lines.append(ln)
                continue
        m = _STANZA.match(ln)
        if m:
            key, rest = m.group(1), (m.group(2) or "").strip()
            sm = _STR.match(rest)
            if key == "end":
                block = None
            elif key in ("stable", "head") and rest.startswith("do"):
                block = key
            elif key in ("desc", "homepage") and sm:
                out.setdefault(key, sm.group(1))
            elif key == "url" and sm:
                out.setdefault("url", sm.group(1))
            elif key == "head" and sm:
                head_url = head_url or sm.group(1)
            elif key == "license":
                license_lines = [rest]
            elif key == "deprecate!":
                out["deprecated"] = True
            elif key == "disable!":
                out["disabled"] = True
            continue
        if block and ln.startswith("    url"):
            sm = _STR.match(ln[7:].strip())
            if sm:
                if block == "stable":
                    stable_url = stable_url or sm.group(1)
                else:
                    head_url = head_url or sm.group(1)
    if license_lines is not None:
        out["license"] = _license_of(" ".join(license_lines))
    if "url" not in out and stable_url:
        out["url"] = stable_url
    if head_url:
        out["head"] = head_url
    if not out.get("license"):
        out.pop("license", None)
    cves = _patch_cves(lines)
    if cves:
        out["patched_cves"] = cves
    return out


# --------------------------------------------------------------------------- keg SBOM

def parse_sbom(data: dict) -> dict[str, Any]:
    """Source-archive package of a keg SBOM: registry/forge purls, download URL, upstream version."""
    for p in data.get("packages") or []:
        if not re.match(r"^SPDXRef-Archive-.*-src$", str(p.get("SPDXID", ""))):
            continue
        refs = [r.get("referenceLocator") for r in p.get("externalRefs") or []
                if r.get("referenceType") == "purl" and r.get("referenceLocator")]
        others = [r for r in refs if not r.startswith("pkg:brew/")]
        dl = p.get("downloadLocation")
        return {"purls": others, "download": dl if dl and dl != "NOASSERTION" else None,
                "version": p.get("versionInfo")}
    return {}


def _purl_parts(purl: str) -> tuple[str, str | None, str, str | None] | None:
    p = purls.parse(purl)
    if p is None:
        return None
    return p.type, p.namespace, p.name, p.version


# --------------------------------------------------------------------------- walker

def find_prefixes(root: Path) -> list[Path]:
    """`root` itself when it is a prefix, else the known prefixes below it (+ ~/.linuxbrew)."""
    root = Path(root)
    if (root / "Cellar").is_dir() or (root / "Caskroom").is_dir():
        return [root]
    cands = [root / p for p in KNOWN_PREFIXES]
    cands += sorted(root.glob("home/*/.linuxbrew")) + [root / "root/.linuxbrew"]
    if str(root) == "/":
        cands.append(Path.home() / ".linuxbrew")
    out: list[Path] = []
    for c in cands:
        if ((c / "Cellar").is_dir() or (c / "Caskroom").is_dir()) and c not in out:
            out.append(c)
    return out


def _rel(path: Path, root: Path | None) -> str:
    """Path shown relative to the scanned root ("/opt/homebrew/Cellar/..."); absolute when no root."""
    if root is None:
        return str(path)
    try:
        return "/" + path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _vkey(a: str, b: str) -> int:
    return compare(_REVISION.sub("", a), _REVISION.sub("", b), "generic") or (a > b) - (a < b)


def _link_target(p: Path) -> str | None:
    """Basename of a symlink target (never followed: works on extracted trees with dangling links)."""
    try:
        return Path(os.readlink(p)).name
    except OSError:
        return None


def _read_json(path: Path, root: Path | None, warnings: list[str], boundary: Path | None = None) -> dict | None:
    try:
        d = json.loads(read_within(path, boundary or root or path.parent, MAX_JSON_BYTES).decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        warnings.append(f"cannot read {_rel(path, root)}: {e}")
        return None
    return d if isinstance(d, dict) else None


def _read_text(path: Path, boundary: Path | None = None) -> str | None:
    """A formula/cask .rb (<= 1 MB), only when it resolves inside `boundary` (no symlink escapes)."""
    try:
        return read_within(path, boundary or path.parent, MAX_RB_BYTES).decode("utf-8", "replace")
    except (OSError, ValueError):
        return None


def _vendored(sub: Path, root: Path | None, formula: str | None, warnings: list[str],
              boundary: Path | None = None) -> list[Component]:
    if not sub.is_dir() or sub.is_symlink():
        return []
    if boundary is not None:
        try:
            resolve_within(sub, boundary)
        except ValueError:
            return []
    res = walk_dir(sub, limits=WalkLimits(binaries=False), path_prefix=_rel(sub, root).rstrip("/") + "/",
                   match_prefix=f"{sub.name}/")        # parsers key on node_modules/ and site-packages/
    warnings.extend(f"{formula or 'homebrew'}: {w}" for w in res.warnings)
    for c in res.components:
        if formula:
            c.meta["via_brew"] = formula
        else:
            c.meta["brew_global"] = True
    return res.components


def _formula_components(prefix: Path, root: Path | None, opts: dict, warnings: list[str],
                        boundary: Path | None = None) -> list[Component]:
    cellar = prefix / "Cellar"
    if not cellar.is_dir():
        return []
    all_kegs = str(opts.get("all_kegs", "")).lower() in ("1", "true", "yes")
    linked_dir = prefix / "var/homebrew/linked"
    pinned_dir = prefix / "var/homebrew/pinned"
    out: list[Component] = []
    for rack in sorted(cellar.iterdir()):
        if rack.is_symlink() or not rack.is_dir() or rack.name.startswith("."):
            continue          # symlinked racks alias renamed formulae
        name = rack.name
        kegs = sorted((k for k in rack.iterdir() if k.is_dir() and not k.is_symlink()
                       and not k.name.startswith(".")), key=cmp_to_key(lambda a, b: _vkey(a.name, b.name)))
        if not kegs:
            continue
        names = {k.name for k in kegs}
        active, guess = _link_target(prefix / "opt" / name), False
        if active not in names:
            active = _link_target(linked_dir / name)
        if active not in names:
            active, guess = kegs[-1].name, True
        linked = (linked_dir / name).is_symlink() if linked_dir.is_dir() else None
        pinned = (pinned_dir / name).is_symlink() or (pinned_dir / name).exists()
        for keg in kegs:
            is_active = keg.name == active
            if not is_active and not all_kegs:
                continue
            c = _keg_component(prefix, root, name, keg, is_active, guess and is_active, warnings, boundary)
            if is_active:
                c.meta["keg_only"] = (not linked) if linked is not None else None
                c.meta["linked"] = linked
            else:
                c.meta["keg_only"] = None
            c.meta["pinned"] = pinned or None
            c.meta = {k: v for k, v in c.meta.items() if v is not None}
            out.append(c)
            out.extend(_keg_libraries(keg, root, name, c, warnings, boundary))
    return out


def _keg_component(prefix: Path, root: Path | None, name: str, keg: Path, active: bool, guess: bool,
                   warnings: list[str], boundary: Path | None = None) -> Component:
    receipt: dict = {}
    rp = keg / "INSTALL_RECEIPT.json"
    if rp.is_file():
        receipt = _read_json(rp, root, warnings, boundary) or {}
    src = receipt.get("source") or {}
    deps = receipt.get("runtime_dependencies") or []
    rb = _read_text(keg / ".brew" / f"{name}.rb", boundary)
    f = parse_formula_rb(rb) if rb else {}
    meta: dict[str, Any] = {
        "active": active, "active_guess": guess or None,
        "installed_on_request": receipt.get("installed_on_request"),
        "runtime_dependencies": len(deps),
        "runtime_deps": [f"{d.get('full_name')}@{d.get('pkg_version') or d.get('version')}"
                         for d in deps if isinstance(d, dict)] or None,
        "homebrew_version": receipt.get("homebrew_version"),
        "poured_from_bottle": receipt.get("poured_from_bottle"),
        "installed_at": receipt.get("time"),
        "no_receipt": None if rp.is_file() else True,
        "desc": f.get("desc"), "homepage": f.get("homepage"), "source_url": strip_url_secrets(f.get("url")),
        "license": f.get("license"), "patched_cves": f.get("patched_cves"),
        "deprecated": f.get("deprecated"), "disabled": f.get("disabled"),
    }
    # SBOM + upstream identity
    sbom: dict = {}
    sp = keg / "sbom.spdx.json"
    if sp.is_file():
        d = _read_json(sp, root, warnings, boundary)
        sbom = parse_sbom(d) if d else {}
    download = sbom.get("download") or f.get("url")
    purl_list = list(sbom.get("purls") or [])
    if not any(_purl_parts(p) and _purl_parts(p)[0] in purls.PURL_TO_OSV for p in purl_list):
        rp_ = registry_purl_from_url(download) or registry_purl_from_url(f.get("url"))
        if rp_:
            purl_list.append(rp_)
    repo = None
    tag = None
    for p in purl_list:                      # forge purl (pkg:github/org/repo@tag)
        parts = _purl_parts(p)
        if parts and parts[0] in ("github", "gitlab", "bitbucket") and parts[1]:
            repo = repo or f"{'github.com' if parts[0] == 'github' else parts[0] + '.com'}/{parts[1]}/{parts[2]}".lower()
            tag = tag or parts[3]
    for cand in (download, f.get("url"), f.get("head"), f.get("homepage")):
        repo = repo or repo_from_url(cand)
    tag = tag or tag_from_url(download) or tag_from_url(f.get("url"))
    meta.update({"upstream_purls": purl_list or None, "upstream_repo": repo, "upstream_tag": tag,
                 "upstream_version": sbom.get("version")})
    c = _formula_component(name, keg.name, src.get("tap"), **meta)
    c.source_path = _rel(keg, root)
    return c


def _keg_libraries(keg: Path, root: Path | None, name: str, formula: Component,
                   warnings: list[str], boundary: Path | None = None) -> list[Component]:
    """Registry component for the formula itself + vendored language dependencies."""
    out: list[Component] = []
    for p in formula.meta.get("upstream_purls") or []:
        parts = _purl_parts(p)
        if not parts or parts[0] not in purls.PURL_TO_OSV or not parts[3]:
            continue
        ptype, ns, pname, pver = parts
        display = f"{ns}/{pname}" if ns and ptype == "npm" else pname
        out.append(Component(name=display, version=pver, category=CAT_LIBRARY, purl=p,
                             source_path=formula.source_path,
                             meta={"evidence": "brew-source", "parser": "homebrew", "via_brew": name,
                                   "paths": [formula.source_path]}))
        break
    subs = [keg / "libexec", keg / "lib/node_modules", *sorted(keg.glob("lib/python3.*/site-packages"))]
    for sub in subs:
        for c in _vendored(sub, root, name, warnings, boundary):
            c.meta["brew_keg_version"] = formula.meta["brew_version"]
            out.append(c)
    return out


# --------------------------------------------------------------------------- casks

def _cask_text_fields(rb: str) -> dict[str, Any]:
    """Line-based (linear time) extraction of the stanzas sec-monk uses from a cask's Ruby source."""
    f: dict[str, Any] = {"auto_updates": False, "names": [], "homepage": None, "apps": []}
    quit_ids: list[str] = []
    pending: list[str] | None = None          # lines of a multi-line `quit: [ ... ]`
    for ln in rb[:MAX_RB_BYTES].splitlines():
        ln = ln[:MAX_LINE]
        if pending is not None:
            pending.append(ln)
            if "]" in ln or len(pending) > 50:
                quit_ids += _strings(" ".join(pending).split("]", 1)[0])
                pending = None
            continue
        t = ln.strip()
        if "version" not in f:
            m = re.match(r"^version\s+(:latest|\"([^\"]*)\"|'([^']*)')", t)
            if m:
                f["latest"] = m.group(1) == ":latest"
                f["version"] = None if f["latest"] else (m.group(2) or m.group(3))
        if re.match(r"^auto_updates\s+true", t):
            f["auto_updates"] = True
        m = re.match(r'^name\s+"([^"]+)"', t)
        if m:
            f["names"].append(m.group(1))
        m = re.match(r'^homepage\s+"([^"]+)"', t)
        if m and not f["homepage"]:
            f["homepage"] = m.group(1)
        m = re.match(r'^app\s+"([^"]+\.app)"', t)
        if m:
            f["apps"].append(m.group(1))
        i = t.find("quit:")
        if i >= 0:
            rest = t[i + 5:].strip()
            if rest.startswith("["):
                if "]" in rest:
                    quit_ids += _strings(rest.split("]", 1)[0])
                else:
                    pending = [rest]
            elif rest.startswith('"'):
                quit_ids += _strings(rest)[:1]
    f["bundle_ids"] = quit_ids
    return f


def _cask_components(prefix: Path, root: Path | None, warnings: list[str],
                     boundary: Path | None = None) -> list[Component]:
    caskroom = prefix / "Caskroom"
    if not caskroom.is_dir():
        return []
    pinned_dir = prefix / "var/homebrew/pinned_casks"
    out: list[Component] = []
    for cask in sorted(caskroom.iterdir()):
        if not cask.is_dir() or cask.name.startswith("."):
            continue
        token = cask.name
        vdirs = sorted((v for v in cask.iterdir() if v.is_dir() and not v.name.startswith(".")),
                       key=cmp_to_key(lambda a, b: _vkey(a.name, b.name)))
        # installed version = newest metadata timestamp (Caskroom.cask_installed_version)
        stamps = sorted(cask.glob(".metadata/*/*"), key=lambda p: p.name)
        stamps = [s for s in stamps if s.is_dir()]
        newest = stamps[-1] if stamps else None
        version = newest.parent.name if newest else (vdirs[-1].name if vdirs else None)
        if version is None:
            continue
        names: list[str] = []
        homepage = tap = None
        apps: list[str] = []
        auto_updates = False
        latest = version == "latest"
        bundle_ids: list[str] = []
        if newest is not None:
            casks_dir = newest / "Casks"
            rb = _read_text(casks_dir / f"{token}.rb", boundary)
            if rb:
                f = _cask_text_fields(rb)
                names, homepage, apps = f["names"], f["homepage"], f["apps"]
                auto_updates, bundle_ids = f["auto_updates"], f["bundle_ids"]
                latest = latest or bool(f.get("latest"))
                if f.get("version") and not latest:
                    version = f["version"]
            for jn in (f"{token}.json", f"{token}.internal.json"):
                jp = casks_dir / jn
                if jp.is_file():
                    j = _read_json(jp, root, warnings, boundary) or {}
                    n = j.get("name")
                    names = names or ([n] if isinstance(n, str) else list(n or []))
                    homepage = homepage or j.get("homepage")
                    tap = tap or j.get("tap")
                    apps = apps or _cask_apps(j.get("artifacts"))
                    auto_updates = auto_updates or bool(j.get("auto_updates"))
                    if isinstance(j.get("version"), str) and j["version"] != "latest":
                        version = j["version"]
        receipt = _read_json(cask / ".metadata/INSTALL_RECEIPT.json", root, [], boundary) \
            if (cask / ".metadata/INSTALL_RECEIPT.json").is_file() else {}
        receipt = receipt or {}
        tap = tap or (receipt.get("source") or {}).get("tap")
        if not apps:
            for v in vdirs:
                apps = [p.name for p in v.glob("*.app")] or apps
        stale = bool(auto_updates and not latest)
        c = _cask_component(
            token, None if latest else version, names, homepage, apps, tap,
            auto_updates=auto_updates or None, version_latest=latest or None,
            version_stale_possible=stale or None, cask_bundle_ids=bundle_ids or None,
            installed_on_request=receipt.get("installed_on_request"),
            pinned=(pinned_dir / token).exists() or (pinned_dir / token).is_symlink() or None)
        c.meta["brew_version"] = version
        c.source_path = _rel(cask / version, root) if (cask / version).exists() else _rel(cask, root)
        out.append(c)
    return out


# --------------------------------------------------------------------------- entry points

def collect_prefixes(root: Path, opts: dict | None = None) -> tuple[list[Component], list[str]]:
    """Formulae, casks and vendored language packages of every Homebrew prefix at/under `root`."""
    opts = opts or {}
    root = Path(root)
    warnings: list[str] = []
    comps: list[Component] = []
    boundary = root.resolve()                         # nothing outside the scanned tree is ever read
    for prefix in find_prefixes(root):
        base = None if prefix == root else root       # root is the prefix itself: show absolute paths
        comps += _formula_components(prefix, base, opts, warnings, boundary)
        comps += _cask_components(prefix, base, warnings, boundary)
        for sub in [prefix / "lib/node_modules", *sorted(prefix.glob("lib/python3.*/site-packages"))]:
            comps += _vendored(sub, base, None, warnings, boundary)
    return _dedupe(comps), warnings


def _dedupe(comps: list[Component]) -> list[Component]:
    """Same purl from several kegs (shared vendored library): keep one, list every `via_brew`."""
    seen: dict[str, Component] = {}
    out: list[Component] = []
    for c in comps:
        key = c.purl or c.key
        prev = seen.get(key)
        if prev is None:
            seen[key] = c
            out.append(c)
            continue
        vb = c.meta.get("via_brew")
        if vb and vb != prev.meta.get("via_brew"):
            allv = prev.meta.setdefault("via_brew_all", [prev.meta.get("via_brew")])
            if vb not in allv:
                allv.append(vb)
        for p in c.meta.get("paths") or []:
            paths = prev.meta.setdefault("paths", [])
            if p not in paths:
                paths.append(p)
    return out


@register
class HomebrewCollector(Collector):
    name = "homebrew"
    description = "Homebrew/Linuxbrew formulae (active kegs), casks and vendored language dependencies"

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        root = Path(target or "/")
        live = str(root) == "/"
        comps, warnings = collect_prefixes(root, opts)
        if not find_prefixes(root):
            warnings.append(f"no Homebrew prefix found under {root}")
        hostname = opts.get("hostname") or (socket.gethostname() if live else (root.resolve().name or "homebrew"))
        asset = Asset(id=f"homebrew:{hostname}", type="server", name=hostname)
        return Inventory(asset=asset, collector=self.name, components=comps, warnings=warnings)
