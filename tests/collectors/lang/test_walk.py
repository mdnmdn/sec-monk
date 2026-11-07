"""walk_dir / LangAccumulator behaviour: race-safe reads, binary candidates, pruning, layer generations."""

from __future__ import annotations

import os
import struct

import pytest

from secmonk.collectors.lang import walk

from .builders import elf_with_section, go_blob

NET = "pkg:golang/golang.org/x/net@0.1.0"


def purls(res):
    return {c.purl for c in res.components}


# --------------------------------------------------------------------------- SEC14
def test_read_capped_refuses_fifo_and_symlink_and_respects_cap(tmp_path):
    fifo = tmp_path / "requirements.txt"
    os.mkfifo(fifo)
    with pytest.raises(OSError):
        walk.read_capped(str(fifo), 1024)                  # must not block on a FIFO
    real = tmp_path / "real"
    real.write_bytes(b"a" * 100)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(OSError):
        walk.read_capped(str(link), 1024)                  # O_NOFOLLOW
    data, size, head = walk.read_capped(str(real), 100)
    assert data == b"a" * 100 and size == 100 and head == b"a" * 100
    data, size, _ = walk.read_capped(str(real), 99)
    assert data is None and size == 100


def test_walk_dir_survives_fifo_named_like_a_lockfile(tmp_path):
    os.mkfifo(tmp_path / "package-lock.json")
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n")
    res = walk.walk_dir(tmp_path)
    assert purls(res) == {"pkg:pypi/requests@2.0.0"}


# --------------------------------------------------------------------------- L11
def test_binary_candidates_skip_shared_objects_by_name_and_header():
    elf_exec = elf_with_section(go_blob(), pad=4096, etype=2)
    elf_dyn = elf_with_section(go_blob(), pad=4096, etype=3)
    elf_rel = elf_with_section(go_blob(), pad=4096, etype=1)
    for name in ("lib/libfoo.so", "lib/libfoo.so.1.2", "x/addon.node", "x/lib.dylib"):
        assert not walk.binary_candidate(name, elf_exec[:512])
    assert walk.binary_candidate("bin/app", elf_exec[:512], 0o644)               # ET_EXEC
    assert walk.binary_candidate("bin/app", elf_dyn[:512], 0o755)                # PIE, exec bit
    assert not walk.binary_candidate("bin/app", elf_dyn[:512], 0o644)            # ET_DYN, no exec, no interp
    assert walk.binary_candidate("bin/app", elf_dyn[:512], None)                 # unknown mode (tar)
    assert not walk.binary_candidate("bin/app", elf_rel[:512], 0o755)
    assert walk.binary_candidate("bin/app.exe", b"MZ" + b"\0" * 100, 0o644)


def test_walk_dir_reads_executables_not_libraries(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "app").write_bytes(elf_with_section(go_blob(), pad=4096))
    (tmp_path / "bin" / "libplugin.so").write_bytes(elf_with_section(go_blob(), pad=4096))
    os.chmod(tmp_path / "bin" / "app", 0o755)
    res = walk.walk_dir(tmp_path)
    assert NET in purls(res) and "pkg:golang/stdlib@1.22.3" in purls(res)
    assert {c.source_path for c in res.components} == {"bin/app"}


def test_walk_dir_non_exec_pie_library_without_so_name_is_skipped(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "plugin").write_bytes(elf_with_section(go_blob(), pad=4096, etype=3))
    assert walk.walk_dir(tmp_path).components == []


# --------------------------------------------------------------------------- L17
def test_next_and_nuxt_output_scanned_but_caches_pruned(tmp_path):
    for d in (".next/standalone", ".next/cache", ".nuxt/dist", ".nuxt/cache", ".tox/py", ".nox/s"):
        p = tmp_path / d
        p.mkdir(parents=True)
        (p / "requirements.txt").write_text(f"pkg{d.strip('.').replace('/', '-')}==1.0.0\n")
    res = walk.walk_dir(tmp_path)
    assert {c.name for c in res.components} == {"pkgnext-standalone", "pkgnuxt-dist"}


# --------------------------------------------------------------------------- L18
def _feed(acc, path, text, layer=None):
    data = text.encode()
    import io
    acc.feed(path, len(data), io.BytesIO(data).read, layer=layer)


def test_accumulator_remove_under_honours_layer_generation():
    acc = walk.LangAccumulator()
    _feed(acc, "app/requirements.txt", "a==1\n", layer=1)
    acc.remove_under("app", only_older=True, layer=2)       # whiteout in layer 2 removes layer-1 file
    assert acc.components() == []

    _feed(acc, "app/requirements.txt", "a==1\n", layer=1)
    _feed(acc, "app/other/requirements.txt", "b==2\n", layer=2)
    acc.remove_under("app", only_older=True, layer=2)       # same-layer additions survive
    assert [c.name for c in acc.components()] == ["b"]


def test_accumulator_old_signatures_still_work():
    acc = walk.LangAccumulator()
    _feed(acc, "app/requirements.txt", "a==1\n")
    acc.remove_under("app")
    assert acc.components() == []
    _feed(acc, "app/requirements.txt", "a==1\n")
    acc.clear()
    assert acc.components() == []


def test_accumulator_skips_shared_objects():
    acc = walk.LangAccumulator()
    elf = elf_with_section(go_blob(), pad=4096)
    import io
    acc.feed("usr/lib/libx.so.1", len(elf), io.BytesIO(elf).read)
    acc.feed("usr/bin/app", len(elf), io.BytesIO(elf).read, mode=0o755)
    assert {c.source_path for c in acc.components()} == {"/usr/bin/app"}


def test_elf_header_helper_roundtrip():
    # sanity of the synthetic builder used above
    assert struct.unpack_from("<H", elf_with_section(b"x" * 16, pad=64, etype=3), 16)[0] == 3
