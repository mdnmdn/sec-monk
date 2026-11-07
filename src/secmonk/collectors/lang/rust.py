"""Rust: Cargo.lock and cargo-auditable binaries.

OSV ecosystem "crates.io", PURL type ``cargo``. Format notes: _docs/references/package-formats/rust.md

* Cargo.lock (v1-v4): every ``[[package]]`` with a crates.io registry source (``registry+...crates.io-index``
  or ``sparse+https://index.crates.io/``) becomes ``pkg:cargo/<name>@<version>``.
  Skipped on purpose: packages without ``source`` (the workspace's own / path crates), git sources and
  alternative registries (OSV's crates.io data cannot be matched against them; emitting them would risk
  false positives for same-named crates).
* Cargo.toml is NOT parsed: its requirements (``^1.2``) are unpinned; only the lockfile or the binary
  tells what was really built.
* cargo-auditable binaries: section ``.dep-v0`` (ELF / Mach-O 64 / PE) holds zlib-compressed JSON.
  Ordinary Rust binaries carry no dependency list: known gap (only panic-message paths / strings remain).
"""

from __future__ import annotations

import json
import struct
import tomllib
import zlib

from ...models import Component
from .base import EV_BINARY, EV_LOCKFILE, LangParser, basename, library, register

ECOSYSTEM = "crates.io"
SECTION = ".dep-v0"
MAX_JSON = 64 * 1024 * 1024


def _is_crates_io(source: str | None) -> bool:
    if not source:
        return False
    if source in ("crates.io",):      # cargo-auditable spelling
        return True
    return source.startswith(("registry+", "sparse+")) and (
        "crates.io-index" in source or "index.crates.io" in source)


def _crate(name: str, version: str, path: str, evidence: str, parser: str, **meta) -> Component:
    return library("cargo", name, version, path=path, evidence=evidence, parser=parser, **meta)


# --------------------------------------------------------------------------- Cargo.lock

def parse_cargo_lock(path: str, data: bytes) -> list[Component]:
    doc = tomllib.loads(data.decode("utf-8", "replace"))
    lock_version = doc.get("version")
    out = []
    for pkg in doc.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version or not _is_crates_io(pkg.get("source")):
            continue
        out.append(_crate(name, version, path, EV_LOCKFILE, "cargo-lock", lock_version=lock_version))
    return out


# --------------------------------------------------------------------------- section readers

def _elf_section(data: bytes, want: bytes) -> bytes | None:
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return None
    is64 = data[4] == 2
    e = "<" if data[5] == 1 else ">"
    if is64:
        shoff, = struct.unpack_from(e + "Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x3A)
    else:
        shoff, = struct.unpack_from(e + "I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x2E)
    if not shoff or not shnum or shstrndx >= shnum:
        return None

    def sh(i: int) -> tuple[int, int, int]:       # name, offset, size
        base = shoff + i * shentsize
        if is64:
            name, _t, _f, _a, off, size = struct.unpack_from(e + "IIQQQQ", data, base)
        else:
            name, _t, _f, _a, off, size = struct.unpack_from(e + "IIIIII", data, base)
        return name, off, size

    _, stroff, strsize = sh(shstrndx)
    strtab = data[stroff:stroff + strsize]
    for i in range(shnum):
        name, off, size = sh(i)
        end = strtab.find(b"\0", name)
        if strtab[name:end if end >= 0 else None] == want:
            return data[off:off + size]
    return None


def _macho_section(data: bytes, want: bytes) -> bytes | None:
    magic = data[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        e = "<"
    elif magic == b"\xfe\xed\xfa\xcf":
        e = ">"
    else:
        return None                                # 32-bit Mach-O: not produced by Rust targets we care about
    ncmds, = struct.unpack_from(e + "I", data, 16)
    pos = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from(e + "II", data, pos)
        if cmd == 0x19:                            # LC_SEGMENT_64
            nsects, = struct.unpack_from(e + "I", data, pos + 64)
            sp = pos + 72
            for _ in range(nsects):
                sectname = data[sp:sp + 16].rstrip(b"\0")
                sec_size, = struct.unpack_from(e + "Q", data, sp + 40)
                sec_off, = struct.unpack_from(e + "I", data, sp + 48)
                if sectname == want:
                    return data[sec_off:sec_off + sec_size]
                sp += 80
        if size < 8:
            break
        pos += size
    return None


def _pe_section(data: bytes, want: bytes) -> bytes | None:
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    pe, = struct.unpack_from("<I", data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        return None
    nsec, = struct.unpack_from("<H", data, pe + 6)
    optsize, = struct.unpack_from("<H", data, pe + 20)
    sp = pe + 24 + optsize
    for _ in range(nsec):
        name = data[sp:sp + 8].rstrip(b"\0")
        vsize, _va, rawsize, rawptr = struct.unpack_from("<IIII", data, sp + 8)
        if name == want:
            return data[rawptr:rawptr + (min(vsize, rawsize) if vsize else rawsize)]
        sp += 40
    return None


def read_dep_section(data: bytes) -> bytes | None:
    """Raw (still compressed) `.dep-v0` bytes from an ELF, 64-bit Mach-O or PE image."""
    want = SECTION.encode()
    for fn in (_elf_section, _macho_section, _pe_section):
        sec = fn(data, want)
        if sec:
            return sec
    return None


def parse_auditable(path: str, data: bytes) -> list[Component]:
    sec = read_dep_section(data)
    if not sec:
        return []
    d = zlib.decompressobj()
    raw = d.decompress(sec, MAX_JSON)
    doc = json.loads(raw)
    out = []
    for pkg in doc.get("packages", []):
        if pkg.get("root"):
            continue                               # the binary's own crate
        if not _is_crates_io(pkg.get("source")):
            continue                               # local / git / other registry
        kind = pkg.get("kind")
        out.append(_crate(pkg["name"], pkg["version"], path, EV_BINARY, "cargo-auditable",
                          kind=kind if kind != "runtime" else None))
    return out


def sniff_executable(head: bytes) -> bool:
    return head[:4] == b"\x7fELF" or head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") \
        or head[:2] == b"MZ"


_BIN_DIRS = ("bin/", "sbin/", "app/", "opt/", "srv/", "usr/local/bin/", ".cargo/bin/")


def _match_binary(path: str) -> bool:
    low = path.lower()
    name = basename(low)
    if low.endswith(".exe"):
        return True
    return any(low.startswith(d) or f"/{d}" in low for d in _BIN_DIRS) or "." not in name


register(LangParser("cargo-lock", ECOSYSTEM, EV_LOCKFILE, lambda p: basename(p) == "Cargo.lock",
                    parse_cargo_lock))
register(LangParser("cargo-auditable", ECOSYSTEM, EV_BINARY, _match_binary, parse_auditable,
                    sniff=sniff_executable, max_bytes=256 * 1024 * 1024, binary=True))
