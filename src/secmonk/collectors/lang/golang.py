"""Go: go.mod, go.sum and compiled Go binaries (embedded build info).

OSV ecosystem "Go", PURL type ``golang``. Format notes: _docs/references/package-formats/go.md

Version format: OSV Go ranges (SEMVER/ECOSYSTEM) never carry a leading ``v`` (checked over the whole
Go database: 0 of 31k events), so versions are normalized by stripping it (``v0.3.7`` -> ``0.3.7``) both
in ``Component.version`` and in the PURL. Pseudo-versions and ``+incompatible`` are kept verbatim.
The standard library is OSV package ``stdlib`` (purl ``pkg:golang/stdlib``) with plain ``1.22.3`` versions.

Precedence: go.sum over-approximates (it keeps hashes of every version ever needed while resolving,
and never lists replaced modules' replacements); go.mod (Go >= 1.17) lists the selected versions and
applies ``replace``. When both exist go.mod is the truth: go.sum components carry ``meta.gosum=True``
so a consumer can drop them when a sibling go.mod was parsed (parsers are per-file and cannot see
siblings).
"""

from __future__ import annotations

import ast
import re
import struct

from ...engine import purl as purls
from ...models import CAT_RUNTIME, Component
from .base import (
    EV_BINARY,
    EV_LOCKFILE,
    EV_MANIFEST,
    LangParser,
    basename,
    push,
    register,
    safe_library,
)

ECOSYSTEM = "Go"
_PURL = "golang"


def _norm_version(v: str | None) -> str | None:
    if not v or v == "(devel)":
        return None
    return v[1:] if v[:1] in ("v", "V") else v


def _split(module: str) -> tuple[str | None, str]:
    ns, _, name = module.rpartition("/")
    return (ns or None), name


def _lib(module: str, version: str | None, path: str, evidence: str, parser: str,
         **meta) -> Component | None:
    ns, name = _split(module)
    return safe_library(_PURL, name, _norm_version(version), path=path, evidence=evidence, parser=parser,
                   namespace=ns, **meta)


def _is_local(target: str) -> bool:
    """`replace x => ../y` / `./y` / `/abs` / `C:\\y` — a directory, not a module."""
    return target.startswith(("./", "../", "/", ".\\", "..\\")) or target in (".", "..") \
        or bool(re.match(r"^[A-Za-z]:[\\/]", target))


def _unquote(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"`":
        return tok[1:-1]
    return tok


# --------------------------------------------------------------------------- go.mod

def parse_go_mod(path: str, data: bytes) -> list[Component]:
    text = data.decode("utf-8", "replace")
    requires: list[tuple[str, str, bool]] = []
    replaces: list[tuple[str, str | None, str, str | None]] = []   # old, old_ver, new, new_ver
    meta: dict[str, str] = {}
    block: str | None = None
    for raw in text.splitlines():
        line, _, comment = raw.partition("//")
        indirect = comment.strip().startswith("indirect")
        toks = [_unquote(t) for t in line.split()]
        if not toks:
            continue
        if block:
            if toks == [")"]:
                block = None
                continue
            directive, args = block, toks
        elif len(toks) >= 2 and toks[-1] == "(":
            block = toks[0]
            continue
        else:
            directive, args = toks[0], toks[1:]
        if directive == "require" and len(args) >= 2:
            requires.append((args[0], args[1], not indirect))
        elif directive == "replace" and "=>" in args:
            i = args.index("=>")
            left, right = args[:i], args[i + 1:]
            if left and right:
                replaces.append((left[0], left[1] if len(left) > 1 else None, right[0],
                                 right[1] if len(right) > 1 else None))
        elif directive in ("go", "toolchain") and args:
            meta[directive] = args[0]
        elif directive == "module" and args:
            meta["main_module"] = args[0]

    out: list[Component] = []
    for mod, ver, direct in requires:
        target, tver, replaced_from = mod, ver, None
        rule = next((r for r in replaces if r[0] == mod and r[1] == ver), None) \
            or next((r for r in replaces if r[0] == mod and r[1] is None), None)
        if rule:
            _, _, new, nver = rule
            if nver is None or _is_local(new):
                target = None   # local directory replacement: not a published module
            else:
                target, tver, replaced_from = new, nver, f"{mod}@{ver}"
        if target is None:
            continue
        push(out, _lib(target, tver, path, EV_MANIFEST, "go-mod", direct=direct,
                             replaced_from=replaced_from, **meta))
    return out


# --------------------------------------------------------------------------- go.sum

def parse_go_sum(path: str, data: bytes) -> list[Component]:
    """One component per `module version h1:` line. `module version/go.mod h1:` lines are skipped:
    they only prove the module's go.mod was read for the dependency graph, not that its code was used."""
    seen: set[tuple[str, str]] = set()
    out: list[Component] = []
    for line in data.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[1].endswith("/go.mod"):
            continue
        key = (parts[0], parts[1])
        if key in seen:
            continue
        seen.add(key)
        push(out, _lib(parts[0], parts[1], path, EV_LOCKFILE, "go-sum", gosum=True))
    return out


# --------------------------------------------------------------------------- binaries

BUILDINFO_MAGIC = b"\xff Go buildinf:"
SCAN_LIMIT = 256 * 1024 * 1024        # fallback magic scan; matches the parser's max_bytes
_SENTINEL = 16
_MARKER_WINDOW = 1024 * 1024
_GO_MARKER = b"Go build ID"


def _sections(data: bytes):
    """Yield (name, file_offset, size) for the sections of an ELF / thin Mach-O / PE image.
    Only headers are read (random access), never the section contents. Malformed headers just end
    the iteration."""
    try:
        yield from _elf_sections(data)
        yield from _macho_sections(data)
        yield from _pe_sections(data)
    except (struct.error, IndexError):
        return


def _elf_sections(data: bytes):
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return
    is64 = data[4] == 2
    e = "<" if data[5] == 1 else ">"
    if is64:
        shoff, = struct.unpack_from(e + "Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x3A)
    else:
        shoff, = struct.unpack_from(e + "I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x2E)
    if not shoff or not shnum or shstrndx >= shnum or shoff + shnum * shentsize > len(data):
        return

    def sh(i: int) -> tuple[int, int, int]:
        pos = shoff + i * shentsize
        if is64:
            name, _t, _f, _a, off, size = struct.unpack_from(e + "IIQQQQ", data, pos)
        else:
            name, _t, _f, _a, off, size = struct.unpack_from(e + "IIIIII", data, pos)
        return name, off, size

    _, stroff, strsize = sh(shstrndx)
    strtab = bytes(data[stroff:stroff + min(strsize, 1 << 20)])
    for i in range(shnum):
        name, off, size = sh(i)
        end = strtab.find(b"\0", name)
        yield strtab[name:end if end >= 0 else None].decode("latin-1"), off, size


def _macho_sections(data: bytes):
    magic = data[:4]
    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        e = "<"
    elif magic in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        e = ">"
    else:
        return
    is64 = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    ncmds, = struct.unpack_from(e + "I", data, 16)
    pos = 32 if is64 else 28
    for _ in range(min(ncmds, 4096)):
        cmd, size = struct.unpack_from(e + "II", data, pos)
        if cmd in (0x19, 0x1):                      # LC_SEGMENT_64 / LC_SEGMENT
            if cmd == 0x19:
                nsects, = struct.unpack_from(e + "I", data, pos + 64)
                sp, step = pos + 72, 80
            else:
                nsects, = struct.unpack_from(e + "I", data, pos + 48)
                sp, step = pos + 56, 68
            for _ in range(nsects):
                sectname = bytes(data[sp:sp + 16]).rstrip(b"\0").decode("latin-1")
                if cmd == 0x19:
                    sec_size, = struct.unpack_from(e + "Q", data, sp + 40)
                    sec_off, = struct.unpack_from(e + "I", data, sp + 48)
                else:
                    sec_size, sec_off = struct.unpack_from(e + "II", data, sp + 36)
                yield sectname, sec_off, sec_size
                sp += step
        if size < 8:
            break
        pos += size


def _pe_sections(data: bytes):
    if data[:2] != b"MZ" or len(data) < 0x40:
        return
    pe, = struct.unpack_from("<I", data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        return
    nsec, = struct.unpack_from("<H", data, pe + 6)
    optsize, = struct.unpack_from("<H", data, pe + 20)
    sp = pe + 24 + optsize
    for _ in range(min(nsec, 256)):
        name = bytes(data[sp:sp + 8]).rstrip(b"\0").decode("latin-1")
        vsize, _va, rawsize, rawptr = struct.unpack_from("<IIII", data, sp + 8)
        yield name, rawptr, (min(vsize, rawsize) if vsize else rawsize)
        sp += 40


# sections that can hold the header: ELF `.go.buildinfo`, Mach-O `__go_buildinfo`, PE `.data`
_BUILDINFO_SECTIONS = {".go.buildinfo", "__go_buildinfo", ".data"}


def _parse_header(data: bytes, off: int) -> tuple[str, str] | None:
    """Validate and decode a buildinfo header at `off` (Go >= 1.18 inline form), else None.
    Header (32 bytes): magic(14) | ptrsize(1) | flags(1) | 16 bytes unused. flags&2 => the two strings
    follow inline as uvarint-length-prefixed bytes (version, then modinfo). Without it (Go < 1.18) the
    header holds *pointers* that need the section/segment tables to resolve -- not supported."""
    if off < 0 or off + 32 > len(data) or data[off:off + 14] != BUILDINFO_MAGIC:
        return None
    ptrsize, flags = data[off + 14], data[off + 15]
    if ptrsize not in (4, 8) or flags & ~3 or not flags & 2:
        return None
    try:
        pos = off + 32
        n, pos = _uvarint(data, pos)
        if n > 4096 or pos + n > len(data):
            return None
        version = bytes(data[pos:pos + n]).decode("utf-8", "replace")
        pos += n
        n, pos = _uvarint(data, pos)
        if pos + n > len(data):
            return None
        mod = bytes(data[pos:pos + n]).decode("utf-8", "replace")
    except (IndexError, ValueError):
        return None
    if not version.startswith(("go", "devel")):
        return None
    if len(mod) >= 2 * _SENTINEL + 1 and mod[-_SENTINEL - 1] == "\n":
        mod = mod[_SENTINEL:-_SENTINEL]
    return version, mod


def _aligned_magics(data: bytes, start: int, end: int):
    pos = start
    while True:
        i = data.find(BUILDINFO_MAGIC, pos, end)
        if i < 0:
            return
        if i % 16 == 0:
            yield i
        pos = i + 1


def find_buildinfo(data: bytes) -> int | None:
    """Offset of a *valid* build-info header. The section table (ELF `.go.buildinfo`, Mach-O
    `__go_buildinfo`, PE `.data`) gives the location directly, wherever in the file it sits (an
    81 MB binary has it past 64 MiB); only when that fails (stripped section headers, odd containers)
    is the whole file scanned for the 16-byte aligned magic, up to SCAN_LIMIT. Every candidate is
    validated (pointer size, flags, varints) so the magic string quoted in .rodata by the Go linker
    or by unrelated programs is skipped."""
    for name, off, size in _sections(data):
        if name in _BUILDINFO_SECTIONS and 0 <= off < len(data):
            for i in _aligned_magics(data, off, min(len(data), off + size)):
                if _parse_header(data, i):
                    return i
    for i in _aligned_magics(data, 0, min(len(data), SCAN_LIMIT)):
        if _parse_header(data, i):
            return i
    return None


def _uvarint(data: bytes, pos: int) -> tuple[int, int]:
    x = shift = 0
    while True:
        b = data[pos]
        pos += 1
        x |= (b & 0x7F) << shift
        if b < 0x80:
            return x, pos
        shift += 7
        if shift > 63:
            raise ValueError("bad varint")


def read_buildinfo(data: bytes) -> tuple[str, str] | None:
    """(runtime version, modinfo text) from a Go >= 1.18 binary, else None."""
    off = find_buildinfo(data)
    return _parse_header(data, off) if off is not None else None


def looks_like_go(data: bytes) -> bool:
    """Cheap evidence that an executable was built by Go even though no build info could be read:
    the `Go build ID` note, or a Go-specific section. Plain C / Rust / .NET binaries have neither."""
    if _GO_MARKER in bytes(data[:_MARKER_WINDOW]):
        return True
    return any(n in (".go.buildinfo", "__go_buildinfo", ".note.go.buildid", ".gopclntab", "__gopclntab")
               for n, _o, _s in _sections(data))


def stdlib_version(goversion: str) -> str | None:
    """`go1.22.3` -> 1.22.3, `go1.21` -> 1.21.0, `go1.22rc1` -> 1.22.0-rc.1, `go1.24.7 X:foo` -> 1.24.7.
    `devel go1.25-abc` -> None."""
    tok = goversion.split()[0] if goversion.split() else ""
    m = re.fullmatch(r"go(\d+)\.(\d+)(?:\.(\d+))?(?:(rc|beta|alpha)(\d+))?", tok)
    if not m:
        return None
    major, minor, patch, pre, pren = m.groups()
    v = f"{major}.{minor}.{patch or 0}"
    return f"{v}-{pre}.{pren}" if pre else v


def _setting(value: str) -> tuple[str, str]:
    if value.startswith('"'):
        try:
            value = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            pass
    k, _, v = value.partition("=")
    return k, v


def parse_go_binary(path: str, data: bytes) -> list[Component]:
    """Components only (see `parse_go_binary_ex` for the warnings)."""
    return parse_go_binary_ex(path, data)[0]


def parse_go_binary_ex(path: str, data: bytes) -> tuple[list[Component], list[str]]:
    info = read_buildinfo(data)
    if info is None:
        if looks_like_go(data):
            msg = "looks like a Go binary but no readable build info was found (stripped, or Go < 1.18)"
            return [], [msg]
        return [], []
    return _components_from_buildinfo(path, info), []


def _components_from_buildinfo(path: str, info: tuple[str, str]) -> list[Component]:
    goversion, modinfo = info
    main_path: str | None = None
    main: tuple[str, str | None] | None = None
    deps: list[list] = []          # [module, version, replacement-or-None]
    settings: dict[str, str] = {}
    last: list | None = None
    for line in modinfo.splitlines():
        f = line.split("\t")
        kind = f[0]
        if kind == "path" and len(f) > 1:
            main_path = f[1]
        elif kind == "mod" and len(f) > 1:
            main = (f[1], f[2] if len(f) > 2 else None)
        elif kind == "dep" and len(f) > 1:
            last = [f[1], f[2] if len(f) > 2 else None, None]
            deps.append(last)
        elif kind == "=>" and last is not None and len(f) > 1:
            last[2] = (f[1], f[2] if len(f) > 2 else None)
        elif kind == "build" and len(f) > 1:
            k, v = _setting(f[1])
            settings[k] = v
    build = {k: settings[k] for k in ("GOOS", "GOARCH", "vcs.revision", "vcs.time", "vcs.modified",
                                      "-buildmode", "-trimpath", "CGO_ENABLED") if k in settings}
    common = {"go_version": goversion, "build": build or None}

    out: list[Component] = []
    sv = stdlib_version(goversion)
    purl = purls.build(_PURL, "stdlib", sv)
    out.append(Component(name="stdlib", version=sv, category=CAT_RUNTIME, purl=purl, ecosystem=ECOSYSTEM,
                         source_path=path, meta={"evidence": EV_BINARY, "parser": "go-binary",
                                                 "runtime": "go", **{k: v for k, v in common.items() if v}}))
    mpath, mver = main if main else (main_path, None)
    if mpath:
        push(out, _lib(mpath, mver, path, EV_BINARY, "go-binary", main=True, **common))
    for mod, ver, repl in deps:
        replaced_from = None
        if repl:
            rpath, rver = repl
            if not rver or rver == "(devel)" or _is_local(rpath):
                continue            # local-directory replacement: not a published module
            replaced_from, mod, ver = f"{mod}@{ver}", rpath, rver
        push(out, _lib(mod, ver, path, EV_BINARY, "go-binary", replaced_from=replaced_from))
    return out


_MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")


def sniff_executable(head: bytes) -> bool:
    """ELF, thin Mach-O (either endianness / width) or PE. 0xCAFEBABE (fat Mach-O) is deliberately
    skipped: it collides with Java class files."""
    return head[:4] == b"\x7fELF" or head[:4] in _MACHO or head[:2] == b"MZ"


_BIN_DIRS = ("bin/", "sbin/", "app/", "opt/", "srv/", "go/bin/", "ko-app/")


def _match_binary(path: str) -> bool:
    low = path.lower()
    name = basename(low)
    if low.endswith(".exe"):
        return True
    in_bin = any(low.startswith(d) or f"/{d}" in low for d in _BIN_DIRS)
    return in_bin or "." not in name


register(LangParser("go-mod", ECOSYSTEM, EV_MANIFEST, lambda p: basename(p) == "go.mod", parse_go_mod))
register(LangParser("go-sum", ECOSYSTEM, EV_LOCKFILE, lambda p: basename(p) == "go.sum", parse_go_sum))
register(LangParser("go-binary", ECOSYSTEM, EV_BINARY, _match_binary, parse_go_binary_ex,
                    sniff=sniff_executable, max_bytes=256 * 1024 * 1024, binary=True))
