from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path

import pytest

from secmonk.collectors import lang
from secmonk.collectors.lang import rust
from secmonk.engine.versions import in_osv_range, scheme_for_ecosystem

FX = Path(__file__).parents[2] / "fixtures" / "lang" / "rust"

PKGS = {"packages": [
    {"name": "app", "version": "1.0.0", "source": "local", "kind": "runtime", "dependencies": [1], "root": True},
    {"name": "smallvec", "version": "1.6.0", "source": "crates.io", "kind": "runtime"},
    {"name": "gitdep", "version": "0.1.0", "source": "git", "kind": "runtime"},
    {"name": "cc", "version": "1.0.0", "source": "crates.io", "kind": "build"},
]}
COMPRESSED = zlib.compress(json.dumps(PKGS).encode())


def macho64(section: bytes, endian: str = "<") -> bytes:
    e = endian
    magic = b"\xcf\xfa\xed\xfe" if e == "<" else b"\xfe\xed\xfa\xcf"
    # header(32) + LC_SEGMENT_64(72 + 2 sections*80)
    sect = lambda name, off, size: (
        name.ljust(16, b"\0") + b"__DATA".ljust(16, b"\0") + struct.pack(e + "QQIIIIIIII", 0, size, off, 0, 0, 0, 0, 0, 0, 0))
    cmdsize = 72 + 160
    off = 32 + cmdsize
    seg = struct.pack(e + "II", 0x19, cmdsize) + b"__DATA".ljust(16, b"\0") + struct.pack(e + "QQQQiiII", 0, 0, 0, 0, 3, 3, 2, 0)
    body = seg + sect(b"__other", 0, 0) + sect(b".dep-v0", off, len(section))
    hdr = magic + struct.pack(e + "IIIIIII", 0x0100000C, 0, 2, 1, cmdsize, 0, 0)
    return hdr + body + section


def test_cargo_lock_real():
    comps = rust.parse_cargo_lock("Cargo.lock", (FX / "Cargo.lock").read_bytes())
    p = {c.purl: c for c in comps}
    assert "pkg:cargo/smallvec@1.6.0" in p and "pkg:cargo/time@0.1.43" in p
    assert len(comps) == 6                                    # workspace crate (no source) skipped
    assert all(c.ecosystem == "crates.io" and c.meta["lock_version"] == 4 for c in comps)
    assert not any("secmonk-rs-demo" in c.name for c in comps)


def test_cargo_lock_sources_and_v1():
    lock = b'''
[[package]]
name = "a"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "b"
version = "2.0.0"
source = "sparse+https://index.crates.io/"
[[package]]
name = "c"
version = "0.1.0"
source = "git+https://github.com/x/c?branch=main#abcdef"
[[package]]
name = "d"
version = "0.1.0"
source = "registry+https://my.registry/index"
[[package]]
name = "e"
version = "0.1.0"
[metadata]
"checksum a 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)" = "00"
'''
    assert [c.purl for c in rust.parse_cargo_lock("Cargo.lock", lock)] == ["pkg:cargo/a@1.0.0", "pkg:cargo/b@2.0.0"]


def test_auditable_elf_fixture():
    data = (FX / "hello-auditable-linux-x86_64").read_bytes()
    comps, warnings = lang.parse_file("usr/local/bin/hello", data)
    assert not warnings
    c = {x.purl: x for x in comps if x.meta["parser"] == "cargo-auditable"}
    assert set(c) == {"pkg:cargo/smallvec@1.6.0", "pkg:cargo/time@0.1.43", "pkg:cargo/libc@0.2.191",
                      "pkg:cargo/cc@1.0.0"}
    assert c["pkg:cargo/cc@1.0.0"].meta["kind"] == "build"
    assert all(x.meta["evidence"] == "binary" for x in c.values())      # root crate "hello" skipped


def test_plain_rust_binary_has_nothing():
    data = (FX / "hello-plain-linux-x86_64").read_bytes()
    assert rust.parse_auditable("bin/hello", data) == []


@pytest.mark.parametrize("endian", ["<", ">"])
def test_macho_section(endian):
    comps = rust.parse_auditable("bin/app", macho64(COMPRESSED, endian))
    assert sorted(c.purl for c in comps) == ["pkg:cargo/cc@1.0.0", "pkg:cargo/smallvec@1.6.0"]  # git+root dropped


def test_pe_section():
    nm = b".dep-v0\0"
    pe_off = 0x80
    raw_off = 0x200
    dos = b"MZ" + b"\0" * 0x3A + struct.pack("<I", pe_off)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0)
    sec = nm + struct.pack("<IIII", len(COMPRESSED), 0x1000, len(COMPRESSED), raw_off) + b"\0" * 16
    data = dos.ljust(pe_off, b"\0") + coff + sec
    data = data.ljust(raw_off, b"\0") + COMPRESSED
    assert [c.name for c in rust.parse_auditable("x.exe", data)] == ["smallvec", "cc"]


def test_sniff_match_registry():
    names = lambda path, head: {p.name for p in lang.parsers_for(path, head)}
    assert "cargo-lock" in names("proj/Cargo.lock", b"")
    assert "cargo-auditable" in names("usr/bin/rg", b"\x7fELF")
    assert "cargo-auditable" not in names("usr/bin/rg", b"#!/bin/sh")
    assert not names("proj/Cargo.toml", b"")                  # Cargo.toml deliberately not parsed


def test_bomb_and_garbage():
    assert rust.parse_auditable("a", b"\x7fELF" + b"\0" * 100) == []
    assert rust.read_dep_section(b"hello") is None


def test_osv_range_smallvec():
    # RUSTSEC-2021-0003 / GHSA-... style: smallvec < 1.6.1 affected (crates.io ranges carry no "v")
    comps = rust.parse_cargo_lock("Cargo.lock", (FX / "Cargo.lock").read_bytes())
    sv = next(c for c in comps if c.name == "smallvec")
    events = [{"introduced": "0.6.5"}, {"fixed": "1.6.1"}]
    scheme = scheme_for_ecosystem("crates.io")
    assert in_osv_range(sv.version, events, scheme)
    assert not in_osv_range("1.6.1", events, scheme)
