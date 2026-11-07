"""JavaScript parsers: npm / yarn (v1 + berry) / pnpm / bun lockfiles and installed node_modules.

PURL type `npm` (scope -> namespace `@scope`), OSV ecosystem `npm`.
See _docs/references/package-formats/javascript.md.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import unquote, urlparse

import yaml

from ...models import Component
from .base import EV_INSTALLED, EV_LOCKFILE, LangParser, basename, push, register, safe_library

ECO = "npm"
_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.+~_-]+)?$")
_NM_PKG_RE = re.compile(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/@][^/]*)/package\.json$")

try:  # libyaml is ~10x faster on big lockfiles
    _FastYamlLoader: Any = yaml.CSafeLoader
except AttributeError:  # pragma: no cover
    _FastYamlLoader = yaml.SafeLoader

MAX_YAML_DEPTH = 200      # real lockfiles nest < 10 levels; libyaml recurses on the C stack
_FAST_YAML_DEPTH = 40     # deeper than this goes to the pure-Python loader (RecursionError, not a segfault)
_FLOW_CHARS = re.compile(r"[\[\]{}]")
_LEADING = re.compile(r"^( *)((?:- )*)", re.MULTILINE)


def yaml_depth(text: str) -> int:
    """Cheap upper estimate of the nesting depth of a YAML document: flow brackets/braces
    (`[[[[`) and block structure (indentation width, `- - - -` chains; each level needs at least one
    column). No parsing, so it is safe to run before the real parser."""
    depth = cur = 0
    for m in _FLOW_CHARS.finditer(text):
        cur = max(0, cur + (1 if m[0] in "[{" else -1))
        depth = max(depth, cur)
    for m in _LEADING.finditer(text):
        depth = max(depth, len(m[1]) + len(m[2]) // 2)
    return depth


def load_yaml(text: str | bytes) -> Any:
    """yaml.safe_load with a nesting guard. Pathologically deep documents crash libyaml's C parser
    (SIGSEGV kills the whole scan), so they are rejected up front; moderately deep ones use the
    pure-Python SafeLoader."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    depth = yaml_depth(text)
    if depth > MAX_YAML_DEPTH:
        raise ValueError(f"YAML nesting too deep ({depth} > {MAX_YAML_DEPTH}); not parsed")
    loader = _FastYamlLoader if depth <= _FAST_YAML_DEPTH else yaml.SafeLoader
    return yaml.load(text, Loader=loader)


# --------------------------------------------------------------------------- helpers

def _split_scope(full: str) -> tuple[str | None, str]:
    if full.startswith("@") and "/" in full:
        ns, _, nm = full.partition("/")
        return ns, nm
    return None, full


def _host(url: str | None) -> str | None:
    if not url or not isinstance(url, str):
        return None
    if url.startswith(("git+", "github:", "git://")):
        return "git"
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def _mk(full_name: str, version: str | None, *, path: str, evidence: str, parser: str, **meta) -> Component | None:
    ns, nm = _split_scope(full_name)
    ver = version if version and _VERSION_RE.match(version) else None
    if version and ver is None:
        meta["non_registry_version"] = version
    return safe_library("npm", nm, ver, path=path, evidence=evidence, parser=parser, namespace=ns, **meta)


def _alias(name: str, version: str) -> tuple[str, str]:
    """`npm:real@1.2.3` alias values -> (real, 1.2.3)."""
    if isinstance(version, str) and version.startswith("npm:"):
        inner = version[4:]
        i = inner.rfind("@")
        if i > 0:
            return inner[:i], inner[i + 1:]
        if i < 0 and inner:                  # `npm:real` without a version: keep the aliased spec
            return name, version
    return name, version


def _uniq(comps: list[Component]) -> list[Component]:
    seen: dict[tuple, Component] = {}
    for c in comps:
        k = (c.purl, c.meta.get("non_registry_version"))
        if k not in seen:
            seen[k] = c
    return list(seen.values())


# --------------------------------------------------------------------------- npm

def parse_package_lock(path: str, data: bytes) -> list[Component]:
    d = json.loads(data)
    if not isinstance(d, dict):
        return []
    lv = d.get("lockfileVersion")
    out: list[Component] = []
    pkgs = d.get("packages")
    if isinstance(pkgs, dict):
        for key, e in pkgs.items():
            if not key or not isinstance(e, dict) or e.get("link"):
                continue
            if "node_modules/" not in key:      # workspace folders ("packages/foo") are local code
                continue
            name = e.get("name") or key.rsplit("node_modules/", 1)[1]
            ver = e.get("version")
            if not isinstance(ver, str):
                continue
            if isinstance(e.get("resolved"), str) and e["resolved"].startswith("file:"):
                continue
            push(out, _mk(name, ver, path=path, evidence=EV_LOCKFILE, parser="npm-package-lock",
                           dev=True if e.get("dev") else None, optional=True if e.get("optional") else None,
                           peer=True if e.get("peer") else None,
                           dev_optional=True if e.get("devOptional") else None,
                           bundled=True if (e.get("inBundle") or e.get("bundled")) else None,
                           resolved_host=_host(e.get("resolved")), lockfile_version=lv,
                           lock_key=key if key.count("node_modules/") > 1 else None))
    elif isinstance(d.get("dependencies"), dict):
        _walk_v1(d["dependencies"], path, lv, out)
    return out


def _walk_v1(deps: dict, path: str, lv, out: list[Component], depth: int = 0) -> None:
    if depth > 64:
        return
    for name, e in deps.items():
        if not isinstance(e, dict):
            continue
        ver = e.get("version")
        if isinstance(ver, str) and not ver.startswith("file:"):
            name2, ver2 = _alias(name, ver)
            push(out, _mk(name2, ver2, path=path, evidence=EV_LOCKFILE, parser="npm-package-lock",
                               bundled=True if e.get("bundled") else None,
                               dev=True if e.get("dev") else None, optional=True if e.get("optional") else None,
                               resolved_host=_host(e.get("resolved")), lockfile_version=lv))
        if isinstance(e.get("dependencies"), dict):
            _walk_v1(e["dependencies"], path, lv, out, depth + 1)


# --------------------------------------------------------------------------- yarn

def parse_yarn_lock(path: str, data: bytes) -> list[Component]:
    text = data.decode("utf-8", "replace")
    if re.search(r"^__metadata:", text, re.MULTILINE):
        return _parse_yarn_berry(path, text)
    return _parse_yarn_v1(path, text)


def _parse_yarn_v1(path: str, text: str) -> list[Component]:
    out: list[Component] = []
    key: str | None = None
    fields: dict[str, str] = {}

    def flush() -> None:
        if key is None or "version" not in fields:
            return
        first = key.split(",")[0].strip().strip('"')
        ver = fields["version"]
        if "@npm:" in first:                            # alias "foo@npm:bar@^1" -> real package is bar
            name = first.partition("@npm:")[2].rsplit("@", 1)[0]
            if not name:
                return
        else:
            i = first.find("@", 1)             # name ends at the first '@' after index 0
            if i <= 0:
                return
            name = first[:i]
        res = fields.get("resolved")
        push(out, _mk(name, ver, path=path, evidence=EV_LOCKFILE, parser="yarn-lock",
                       resolved_host=_host(res.split("#")[0]) if res else None, lockfile_format="yarn-v1"))

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[0] not in " \t":
            flush()
            key = raw.rstrip().rstrip(":")
            fields = {}
        elif raw.startswith("  ") and not raw.startswith("    ") and key is not None:
            k, _, v = raw.strip().partition(" ")
            if k in ("version", "resolved"):
                fields[k] = v.strip().strip('"')
    flush()
    return _uniq(out)


_BERRY_NPM = re.compile(r"^(?P<name>@?[^@]+)@npm:(?P<ver>[^#:]+)(?:::.*)?(?:#.*)?$")
_BERRY_PATCH_INNER = re.compile(r"^(?P<name>@?[^@]+)@patch:.*?@npm(?:%3A|:)(?P<ver>[^#:%]+)")


def _parse_yarn_berry(path: str, text: str) -> list[Component]:
    d = load_yaml(text)
    out: list[Component] = []
    if not isinstance(d, dict):
        return out
    meta_v = (d.get("__metadata") or {}).get("version")
    for k, e in d.items():
        if k == "__metadata" or not isinstance(e, dict):
            continue
        res = e.get("resolution")
        if not isinstance(res, str):
            continue
        m = _BERRY_NPM.match(res)
        if m:
            name, ver = m["name"], m["ver"]
        else:
            m = _BERRY_PATCH_INNER.match(res)       # patch:foo@npm%3A1.2.3#... -> inner npm version
            if not m:
                continue                            # workspace:, portal:, link:, git, https, exec:
            name, ver = m["name"], unquote(m["ver"])
        push(out, _mk(name, ver, path=path, evidence=EV_LOCKFILE, parser="yarn-lock",
                       lockfile_format="yarn-berry", lockfile_version=meta_v,
                       patched=True if "@patch:" in res else None))
    return _uniq(out)


# --------------------------------------------------------------------------- pnpm

def _pnpm_split(key: str, lockv: float) -> tuple[str, str] | None:
    k = key.strip().strip("'\"")
    if lockv < 6:                                   # /name/1.2.3_peer@1 , /@scope/name/1.2.3
        if not k.startswith("/"):
            return None
        parts = k[1:].split("/")
        if len(parts) < 2:
            return None
        ver = re.split(r"[_(]", parts[-1], maxsplit=1)[0]
        return "/".join(parts[:-1]), ver
    k = k.lstrip("/")
    k = k.split("(", 1)[0]
    i = k.rfind("@")
    if i <= 0:
        return None
    return k[:i], k[i + 1:]


def parse_pnpm_lock(path: str, data: bytes) -> list[Component]:
    d = load_yaml(data)
    if not isinstance(d, dict):
        return []
    try:
        lockv = float(str(d.get("lockfileVersion", "0")).strip("'\""))
    except ValueError:
        lockv = 0.0
    out: list[Component] = []
    for section in ("packages", "snapshots"):
        sec = d.get(section)
        if not isinstance(sec, dict):
            continue
        for key, e in sec.items():
            if not isinstance(key, str):
                continue
            e = e if isinstance(e, dict) else {}
            sp = _pnpm_split(key, lockv)
            if not sp:
                continue
            name, ver = sp
            if isinstance(e.get("name"), str) and isinstance(e.get("version"), str):   # tarball/git deps
                name, ver = e["name"], e["version"]
            if ver.startswith(("link:", "file:")) or "/" in ver:
                continue
            push(out, _mk(name, ver, path=path, evidence=EV_LOCKFILE, parser="pnpm-lock",
                           dev=True if e.get("dev") is True else None,
                           optional=True if e.get("optional") is True else None,
                           lockfile_version=str(d.get("lockfileVersion"))))
    return _uniq(out)


# --------------------------------------------------------------------------- bun

def _strip_jsonc(text: str) -> str:
    """Remove trailing commas (bun.lock is JSONC). Strings are skipped so URLs/commas inside survive."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def parse_bun_lock(path: str, data: bytes) -> list[Component]:
    d = json.loads(_strip_jsonc(data.decode("utf-8", "replace")))
    out: list[Component] = []
    root = (d.get("workspaces") or {}).get("") or {}
    dev_direct = set(root.get("devDependencies") or {})
    for key, arr in (d.get("packages") or {}).items():
        if not isinstance(arr, list) or not arr or not isinstance(arr[0], str):
            continue
        ident = arr[0]                              # "name@1.2.3" / "name@workspace:x" / "name@github:..."
        if "@npm:" in ident:                        # alias "al@npm:real@2.0.0"
            name, ver = _alias("", "npm:" + ident.partition("@npm:")[2])
        else:
            i = ident.rfind("@")
            if i <= 0:
                continue
            name, ver = ident[:i], ident[i + 1:]
            if not _VERSION_RE.match(ver):
                continue                            # workspace:, file:, github:, link:, https:
        push(out, _mk(name, ver, path=path, evidence=EV_LOCKFILE, parser="bun-lock",
                       dev_direct=True if key in dev_direct else None, lockfile_version=d.get("lockfileVersion")))
    return _uniq(out)


# --------------------------------------------------------------------------- installed

def parse_installed_package_json(path: str, data: bytes) -> list[Component]:
    d = json.loads(data)
    if not isinstance(d, dict):
        return []
    name, ver = d.get("name"), d.get("version")
    if not isinstance(name, str) or not isinstance(ver, str) or not name or not ver:
        return []
    lic = d.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    c = _mk(name, ver, path=path, evidence=EV_INSTALLED, parser="node-modules",
            license=lic if isinstance(lic, str) else None)
    return [c] if c else []


# --------------------------------------------------------------------------- registration

register(LangParser("npm-package-lock", "npm", EV_LOCKFILE,
                    lambda p: basename(p) in ("package-lock.json", "npm-shrinkwrap.json"), parse_package_lock))
register(LangParser("yarn-lock", "npm", EV_LOCKFILE, lambda p: basename(p) == "yarn.lock", parse_yarn_lock))
register(LangParser("pnpm-lock", "npm", EV_LOCKFILE, lambda p: basename(p) == "pnpm-lock.yaml", parse_pnpm_lock))
register(LangParser("bun-lock", "npm", EV_LOCKFILE, lambda p: basename(p) == "bun.lock", parse_bun_lock))
register(LangParser("node-modules", "npm", EV_INSTALLED, lambda p: bool(_NM_PKG_RE.search(p)),
                    parse_installed_package_json, max_bytes=2 * 1024 * 1024))
