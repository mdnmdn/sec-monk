from __future__ import annotations

import json
from pathlib import Path

import pytest

from secmonk.collectors import lang
from secmonk.collectors.lang import golang
from secmonk.engine.versions import in_osv_range, scheme_for_ecosystem
from secmonk.models import CAT_RUNTIME

FX = Path(__file__).parents[2] / "fixtures" / "lang" / "go"


def by_purl(comps):
    return {c.purl: c for c in comps}


def test_go_mod_replace_and_local():
    comps = golang.parse_go_mod("go.mod", (FX / "go.mod").read_bytes())
    p = by_purl(comps)
    assert "pkg:golang/golang.org/x/text@0.3.7" in p
    # replace uuid v1.3.0 => v1.3.1
    uuid = p["pkg:golang/github.com/google/uuid@1.3.1"]
    assert uuid.meta["replaced_from"] == "github.com/google/uuid@v1.3.0"
    assert uuid.meta["go"] == "1.21" and uuid.meta["direct"] is True
    # local path replacement dropped
    assert not any("localfork" in (c.purl or "") for c in comps)
    assert all(c.ecosystem == "Go" for c in comps)


def test_go_mod_blocks_indirect_toolchain():
    text = b"""module m
go 1.22.0
toolchain go1.22.5
require (
\tgithub.com/a/b v1.0.0
\tgithub.com/c/d v0.0.0-20200101000000-abcdef123456 // indirect
)
require github.com/x/y/v2 v2.1.0+incompatible
replace (
\tgithub.com/a/b => github.com/fork/b v1.0.1
)
"""
    p = by_purl(golang.parse_go_mod("go.mod", text))
    assert p["pkg:golang/github.com/fork/b@1.0.1"].meta["toolchain"] == "go1.22.5"
    d = p["pkg:golang/github.com/c/d@0.0.0-20200101000000-abcdef123456"]
    assert d.meta["direct"] is False
    y = next(c for c in p.values() if c.name == "github.com/x/y/v2")
    assert y.version == "2.1.0+incompatible" and "@2.1.0%2Bincompatible" in y.purl


def test_go_sum_skips_gomod_lines():
    comps = golang.parse_go_sum("go.sum", (FX / "go.sum").read_bytes())
    assert sorted(c.purl for c in comps) == ["pkg:golang/github.com/google/uuid@1.3.1",
                                             "pkg:golang/golang.org/x/text@0.3.7"]
    assert all(c.meta["gosum"] is True for c in comps)


@pytest.mark.parametrize("name,goos", [("hello-linux-amd64", "linux"), ("hello-darwin-arm64", "darwin")])
def test_binary_elf_and_macho(name, goos):
    data = (FX / name).read_bytes()
    comps, warnings = lang.parse_file(f"usr/local/bin/{name}", data)
    assert not warnings
    p = by_purl(comps)
    std = next(c for c in comps if c.category == CAT_RUNTIME)
    assert std.purl.startswith("pkg:golang/stdlib@1.24") and std.ecosystem == "Go"
    assert std.meta["build"]["GOOS"] == goos and std.meta["evidence"] == "binary"
    main = p["pkg:golang/example.com/secmonk-hello"]
    assert main.version is None and main.meta["main"] is True
    assert "pkg:golang/golang.org/x/text@0.3.7" in p
    assert "pkg:golang/github.com/google/uuid@1.3.1" in p       # replacement applied
    assert p["pkg:golang/github.com/google/uuid@1.3.1"].meta["replaced_from"].endswith("@v1.3.0")
    assert not any("localfork" in k for k in p)                   # local replacement dropped


def test_sniff_and_match():
    assert lang.parsers_for("usr/bin/tool", b"\x7fELF....")
    assert not [p for p in lang.parsers_for("usr/bin/Tool.class", b"\xca\xfe\xba\xbe") if p.name == "go-binary"]
    assert any(p.name == "go-binary" for p in lang.parsers_for("app/svc", b"\xcf\xfa\xed\xfe"))
    assert any(p.name == "go-binary" for p in lang.parsers_for("svc.exe", b"MZ\x90\x00"))
    assert all(p.binary for p in lang.parsers_for("app/svc", b"\x7fELF") if p.name == "go-binary")


@pytest.mark.parametrize("v,expect", [("go1.22.3", "1.22.3"), ("go1.21", "1.21.0"), ("go1.22rc1", "1.22.0-rc.1"),
                                      ("go1.24.7 X:boringcrypto", "1.24.7"), ("devel go1.25-abc", None)])
def test_stdlib_version(v, expect):
    assert golang.stdlib_version(v) == expect


def test_pre_118_and_garbage_ignored():
    blob = b"\xff Go buildinf:" + bytes([8, 0]) + b"\0" * 16 + b"padding"
    assert golang.parse_go_binary("x", b"\x7fELF" + b"\0" * 12 + blob) == []
    assert golang.parse_go_binary("x", b"\x7fELF" + b"\0" * 100) == []


def test_buildinfo_alignment_and_sentinels():
    mod = "path\tm\nmod\tm\t(devel)\t\ndep\tgolang.org/x/net\tv0.1.0\th1:x\n"
    sent = b"0123456789abcdef"
    modbytes = sent + mod.encode() + sent
    ver = b"go1.20"
    hdr = b"\xff Go buildinf:" + bytes([8, 2]) + b"\0" * 16
    blob = hdr + bytes([len(ver)]) + ver + bytes([len(modbytes) & 0x7F | 0x80, len(modbytes) >> 7]) + modbytes
    # a misaligned decoy first, real header at 16-aligned offset
    data = b"\x7fELF" + b"\0" * 3 + b"\xff Go buildinf:" + b"\0" * 20 + b"\0" * (16 - (4 + 3 + 14 + 20) % 16) + blob
    # sentinel must end with '\n' at -17 for stripping: emulate Go (mod text ends with newline)
    comps = golang.parse_go_binary("bin/x", data)
    assert any(c.purl == "pkg:golang/golang.org/x/net@0.1.0" for c in comps)
    assert any(c.purl == "pkg:golang/stdlib@1.20.0" for c in comps)


OSV = FX / "osv"


def test_osv_range_real_records():
    scheme = scheme_for_ecosystem("Go")
    data = (FX / "hello-linux-amd64").read_bytes()
    comps, _ = lang.parse_file("app/hello", data)
    text = next(c for c in comps if c.name == "golang.org/x/text")
    std = next(c for c in comps if c.category == CAT_RUNTIME)
    rec = json.loads((OSV / "GO-2022-1059.json").read_text())
    aff = next(a for a in rec["affected"] if a["package"]["name"] == "golang.org/x/text")
    assert aff["package"]["purl"] == "pkg:golang/golang.org/x/text"
    events = aff["ranges"][0]["events"]
    assert not any(str(v).startswith("v") for e in events for v in e.values())   # OSV: no "v" prefix
    assert in_osv_range(text.version, events, scheme)              # 0.3.7 < fixed 0.3.8
    assert not in_osv_range("0.3.8", events, scheme)
    # stdlib record: package name "stdlib", versions without v
    rec = json.loads((OSV / "GO-2021-0069.json").read_text())
    aff = next(a for a in rec["affected"] if a["package"]["name"] == "stdlib")
    assert aff["package"]["purl"] == "pkg:golang/stdlib"
    ev = aff["ranges"][0]["events"]
    assert in_osv_range("1.15.4", ev, scheme) and not in_osv_range("1.15.5", ev, scheme)
    assert not in_osv_range(std.version, ev, scheme)               # 1.24.7 is long past those fixes


# --------------------------------------------------------------------------- review fixes (L2, L3, L5)
from secmonk.collectors.lang import parse_file

from .builders import GO_MAGIC, elf_with_section, go_blob, macho_with_section, pe_with_data


def _purls(comps):
    return {c.purl for c in comps}


def test_buildinfo_found_via_section_table_beyond_64mib():
    """L2: an 81 MB real Go binary has .go.buildinfo past 64 MiB; the section table finds it directly."""
    data = elf_with_section(go_blob(), pad=70 * 1024 * 1024)
    assert len(data) > 70 * 1024 * 1024
    comps, warns = parse_file("usr/local/bin/big", data)
    assert not warns
    assert "pkg:golang/golang.org/x/net@0.1.0" in _purls(comps)
    assert any(c.name == "stdlib" and c.version == "1.22.3" for c in comps)


def test_buildinfo_fallback_scan_without_section_headers():
    """L2: no section table (stripped / odd container) -> aligned magic scan of the whole file."""
    data = elf_with_section(go_blob(), pad=66 * 1024 * 1024, with_sections=False)
    comps, _ = parse_file("usr/local/bin/big", data)
    assert "pkg:golang/golang.org/x/net@0.1.0" in _purls(comps)


@pytest.mark.parametrize("build", [macho_with_section, pe_with_data])
def test_buildinfo_via_macho_and_pe_section_tables(build, monkeypatch):
    monkeypatch.setattr(golang, "SCAN_LIMIT", 16)          # prove the section path, not the scan, is used
    path = "usr/local/bin/app.exe" if build is pe_with_data else "usr/local/bin/app"
    comps, _ = parse_file(path, build(go_blob()))
    assert "pkg:golang/golang.org/x/net@0.1.0" in _purls(comps)


def test_go_looking_binary_without_buildinfo_warns_but_plain_elf_does_not():
    plain = elf_with_section(b"\0" * 64, pad=4096, section_name=b".text")
    assert parse_file("bin/plain", plain) == ([], [])
    gobin = elf_with_section(b"\0" * 64, pad=4096, section_name=b".text") + b"\0" * 8
    gobin = gobin[:200] + b"Go build ID: abc" + gobin[216:]
    comps, warns = parse_file("bin/stripped-go", gobin)
    assert comps == [] and len(warns) == 1 and "Go binary" in warns[0]


def test_go_buildinfo_header_validation_skips_decoys():
    """L5: the magic quoted in .rodata (bad ptrsize / flags / truncated varints) must not shadow
    the real, later header, even when the decoy happens to be 16-byte aligned."""
    bad_ptr = GO_MAGIC + bytes([0x41, 2]) + b"\0" * 16 + b"\x06go1.22"
    bad_flags = GO_MAGIC + bytes([8, 0xF2]) + b"\0" * 16 + b"\x06go1.22"
    trunc = GO_MAGIC + bytes([8, 2]) + b"\0" * 16 + b"\xff\xff"
    for decoy in (bad_ptr, bad_flags, trunc):
        data = b"\x7fELF" + b"\0" * 12 + decoy.ljust(64, b"\0") + go_blob()
        assert golang.find_buildinfo(data) is not None
        info = golang.read_buildinfo(data)
        assert info is not None and info[0] == "go1.22.3"


def test_gosum_dropped_only_for_go_117_plus():
    """L3: go < 1.17 go.mod lacks indirect deps, so go.sum entries must be kept."""
    sum_ = b"github.com/a/b v1.0.0 h1:x\ngithub.com/c/d v2.0.0 h1:y\n"

    def run(gomod: bytes):
        c1, _ = parse_file("app/go.mod", gomod)
        c2, _ = parse_file("app/go.sum", sum_)
        return {c.purl for c in lang.dedupe(c1 + c2)}

    new = run(b"module m\ngo 1.21\nrequire github.com/a/b v1.0.0\n")
    assert new == {"pkg:golang/github.com/a/b@1.0.0"}
    old = run(b"module m\ngo 1.16\nrequire github.com/a/b v1.0.0\n")
    assert old == {"pkg:golang/github.com/a/b@1.0.0", "pkg:golang/github.com/c/d@2.0.0"}
    nodirective = run(b"module m\nrequire github.com/a/b v1.0.0\n")
    assert "pkg:golang/github.com/c/d@2.0.0" in nodirective
