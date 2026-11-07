"""Linux root filesystem inventory engine (shared by `rootfs`, `docker-image`, `docker-engine`).

Everything is read through an `FsView` — either a real directory (`DirView`) or an in-memory
subset of a layered container image (`LayeredTarView`) — and nothing is ever executed or
extracted to disk. Symlinks are resolved *inside* the view (absolute targets are re-rooted).

See _docs/tech/collectors/rootfs.md and docker-image.md.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import sqlite3
import stat
import struct
import tarfile
import tempfile
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO

from ..engine import purl as purls
from ..models import CAT_OS, CAT_OS_PACKAGE, Asset, Component, Inventory
from .base import Collector, register

MAX_LANG_FILES = 20_000
MAX_FILE_BYTES = 256 * 1024 * 1024      # package DBs can be large, but cap anyway
MAX_META_BYTES = 4 * 1024 * 1024        # METADATA / package.json
MAX_SYMLINK_DEPTH = 40
# LayeredTarView resource budgets (a hostile layer must not be able to exhaust memory)
MAX_VIEW_BYTES = 512 * 1024 * 1024      # total bytes retained across all kept files
MAX_DPKG_TEXT_BYTES = 64 * 1024 * 1024  # one dpkg status / status.d file
MAX_STATUS_D_FILES = 10_000
MAX_STATUS_D_BYTES = 64 * 1024 * 1024    # all status.d files together (real ones are a few KB each)
MAX_LINKS = 1_000_000
# rpmdb.sqlite is attacker-controlled input: bound the work done on it
MAX_RPM_ROWS = 200_000
MAX_RPM_BLOB = 4 * 1024 * 1024
RPM_VM_BUDGET = 20_000_000              # SQLite VM instructions
RPM_TIME_BUDGET = 30.0                  # seconds

OS_RELEASE_PATHS = ("etc/os-release", "usr/lib/os-release")
FIXED_PATHS = frozenset({
    "etc/os-release", "usr/lib/os-release", "etc/alpine-release", "etc/debian_version",
    "etc/redhat-release", "var/lib/dpkg/status", "lib/apk/db/installed",
    "var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite-wal", "var/lib/rpm/Packages",
    "var/lib/rpm/Packages.db", "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "usr/lib/sysimage/rpm/rpmdb.sqlite-wal", "usr/lib/sysimage/rpm/Packages",
    "usr/lib/sysimage/rpm/Packages.db",
})
DPKG_STATUS_D = "var/lib/dpkg/status.d"
RPM_SQLITE = ("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite")
RPM_LEGACY = ("var/lib/rpm/Packages", "usr/lib/sysimage/rpm/Packages",
              "var/lib/rpm/Packages.db", "usr/lib/sysimage/rpm/Packages.db")


# --------------------------------------------------------------------------- path helpers

def norm_path(path: str) -> str:
    """Normalize to a relative posix path without './', leading '/', or '..' escapes."""
    parts: list[str] = []
    for p in path.replace("\\", "/").split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            if parts:
                parts.pop()
            continue
        parts.append(p)
    return "/".join(parts)


def lang_kind(path: str) -> str | None:
    """'pypi' / 'npm' when `path` (relative, posix) is a language-package metadata file we read."""
    if path.endswith(".dist-info/METADATA"):
        parts = path.split("/")
        if len(parts) >= 3 and parts[-3] in ("site-packages", "dist-packages"):
            return "pypi"
    elif path.endswith("/package.json") or path == "package.json":
        parts = path.split("/")
        if len(parts) >= 3 and parts[-3] == "node_modules":
            return "npm"
        if len(parts) >= 4 and parts[-3].startswith("@") and parts[-4] == "node_modules":
            return "npm"
    return None


def is_interesting(path: str) -> bool:
    return (path in FIXED_PATHS or path.startswith(DPKG_STATUS_D + "/") or lang_kind(path) is not None)


# --------------------------------------------------------------------------- FsView

class FsView(ABC):
    """Read-only file access to a Linux filesystem image. Paths are relative posix paths."""

    @abstractmethod
    def _readlink(self, path: str) -> str | None:
        """Target of the symlink at `path` (a fully resolved parent + name), else None."""

    @abstractmethod
    def _read_raw(self, path: str, limit: int) -> bytes | None: ...

    @abstractmethod
    def _listdir_raw(self, path: str) -> list[str]: ...

    @abstractmethod
    def iter_lang_files(self) -> Iterator[tuple[str, str]]:
        """Yield (path, kind) for every python/npm metadata file (capped at MAX_LANG_FILES)."""

    # ---- shared symlink-aware logic

    def resolve(self, path: str, follow_last: bool = True) -> str:
        """Resolve symlinks within the view; absolute targets are re-rooted at the view root."""
        pending = [p for p in norm_path(path).split("/") if p]
        resolved: list[str] = []
        hops = 0
        while pending:
            comp = pending.pop(0)
            if comp == ".":
                continue
            if comp == "..":
                if resolved:
                    resolved.pop()
                continue
            cand = "/".join([*resolved, comp])
            if pending or follow_last:
                target = self._readlink(cand)
                if target is not None:
                    hops += 1
                    if hops > MAX_SYMLINK_DEPTH:
                        raise OSError(f"too many symlinks resolving {path}")
                    if target.startswith("/"):
                        resolved = []
                    pending = [p for p in target.split("/") if p] + pending
                    continue
            resolved.append(comp)
        return "/".join(resolved)

    def read(self, path: str, limit: int = MAX_FILE_BYTES) -> bytes | None:
        try:
            real = self.resolve(path)
        except OSError:
            return None
        return self._read_raw(real, limit)

    def read_text(self, path: str, limit: int = MAX_META_BYTES) -> str | None:
        data = self.read(path, limit)
        return None if data is None else data.decode("utf-8", "replace")

    def exists(self, path: str) -> bool:
        return self.read(path, 1) is not None

    def listdir(self, path: str) -> list[str]:
        try:
            return self._listdir_raw(self.resolve(path))
        except OSError:
            return []


class DirView(FsView):
    """A directory on the host treated as `/` of a Linux system."""

    _SKIP_TOP = frozenset({"proc", "sys", "dev", "run"})
    truncated = False

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise NotADirectoryError(str(root))

    def _abs(self, path: str) -> str:
        return os.path.join(self.root, path) if path else str(self.root)

    def _readlink(self, path: str) -> str | None:
        try:
            return os.readlink(self._abs(path))
        except OSError:
            return None

    def _read_raw(self, path: str, limit: int) -> bytes | None:
        p = self._abs(path)
        try:
            st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode):
                return None
            with open(p, "rb") as f:
                return f.read(limit)
        except OSError:
            return None

    def _listdir_raw(self, path: str) -> list[str]:
        try:
            return sorted(os.listdir(self._abs(path)))
        except OSError:
            return []

    def iter_lang_files(self) -> Iterator[tuple[str, str]]:
        found = 0
        for dirpath, dirs, files in os.walk(self.root, followlinks=False):
            rel = os.path.relpath(dirpath, self.root)
            rel = "" if rel == "." else rel.replace(os.sep, "/")
            if rel == "":
                dirs[:] = [d for d in dirs if d not in self._SKIP_TOP]
            else:
                parts = rel.split("/")
                base = parts[-1]
                # inside a node_modules package dir only nested node_modules matter
                in_pkg = (len(parts) >= 2 and parts[-2] == "node_modules" and not base.startswith("@")) or (
                    len(parts) >= 3 and parts[-2].startswith("@") and parts[-3] == "node_modules")
                if in_pkg:
                    dirs[:] = [d for d in dirs if d == "node_modules"]
                elif base == ".git":
                    dirs[:] = []
            dirs.sort()
            for fn in sorted(files):
                path = f"{rel}/{fn}" if rel else fn
                kind = lang_kind(path)
                if kind and not os.path.islink(os.path.join(dirpath, fn)):
                    yield path, kind
                    found += 1
                    if found >= MAX_LANG_FILES:
                        return


class UnsupportedLayer(Exception):
    """Layer compression we cannot read (e.g. zstd without a zstd module)."""


class _PeekReader(io.RawIOBase):
    def __init__(self, f: Any):
        self.f = f

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        data = self.f.read(len(b))
        n = len(data)
        b[:n] = data
        return n


def open_maybe_compressed(fileobj: BinaryIO) -> BinaryIO:
    """Wrap a (possibly non-seekable) stream, transparently decompressing gzip / zstd."""
    buf = io.BufferedReader(_PeekReader(fileobj), 1 << 20)
    magic = buf.peek(4)[:4]
    if magic[:2] == b"\x1f\x8b":
        import gzip

        return gzip.GzipFile(fileobj=buf)  # type: ignore[return-value]
    if magic == b"\x28\xb5\x2f\xfd":
        try:
            from compression import zstd  # type: ignore[import-not-found]  # py3.14+

            return zstd.ZstdFile(buf)  # type: ignore[return-value]
        except ImportError:
            pass
        try:
            import zstandard  # type: ignore[import-not-found]

            return zstandard.ZstdDecompressor().stream_reader(buf)  # type: ignore[return-value]
        except ImportError as e:
            raise UnsupportedLayer("zstd layer but no zstd module (install `zstandard`)") from e
    return buf


class LayeredTarView(FsView):
    """In-memory view of the whitelisted files of a stack of tar layers.

    `add_layer()` is called bottom layer first. Only paths accepted by `is_interesting()` plus all
    symlinks are kept; whiteouts (`.wh.<name>`) and opaque markers (`.wh..wh..opq`) are applied to
    what is stored so far, so the final view equals the merged image for those paths.
    """

    def __init__(self, binaries: bool = True) -> None:
        self.files: dict[str, bytes] = {}
        self.links: dict[str, str] = {}
        self._gen: dict[str, int] = {}
        # directory -> names of its children (files, links, sub-directories): lets a whiteout find
        # everything below a prefix in O(matches) instead of scanning every stored path.
        self._dirs: dict[str, set[str]] = {}
        self._layer = 0
        self._lang_count = 0
        self._bytes = 0
        self._status_d = 0
        self._status_d_bytes = 0
        self._root_opq_layer = -1
        self.truncated = False
        from .lang.walk import LangAccumulator, WalkLimits

        self.lang = LangAccumulator(WalkLimits(binaries=binaries))

    # ---- building

    def _track(self, path: str) -> None:
        d, _, name = path.rpartition("/")
        while True:
            kids = self._dirs.setdefault(d, set())
            if name in kids:
                return
            kids.add(name)
            if not d:
                return
            d, _, name = d.rpartition("/")

    def _prune(self, node: str) -> None:
        """Forget `node` in its parent once nothing is stored at or below it."""
        while node:
            if node in self.files or node in self.links or self._dirs.get(node):
                return
            self._dirs.pop(node, None)
            parent, _, name = node.rpartition("/")
            kids = self._dirs.get(parent)
            if kids is not None:
                kids.discard(name)
            node = parent

    def _delete(self, path: str) -> None:
        data = self.files.pop(path, None)
        if data is not None:
            self._bytes -= len(data)
            if path.startswith(DPKG_STATUS_D + "/"):
                self._status_d -= 1
                self._status_d_bytes -= len(data)
        self.links.pop(path, None)
        self._gen.pop(path, None)

    def _remove_under(self, prefix: str, only_older: bool) -> None:
        self.lang.remove_under(prefix, only_older=only_older, layer=self._layer)
        nodes: list[str] = []
        stack = [prefix]
        while stack:
            n = stack.pop()
            nodes.append(n)
            stack.extend(f"{n}/{k}" if n else k for k in self._dirs.get(n, ()))
        for n in nodes:
            if (n in self.files or n in self.links) and not (only_older and self._gen.get(n, -1) >= self._layer):
                self._delete(n)
        for n in reversed(nodes):
            self._prune(n)

    def _remove_everything_older(self) -> None:
        self.lang.clear(only_older=True, layer=self._layer)
        if self._root_opq_layer == self._layer:
            return
        self._root_opq_layer = self._layer
        for p in [p for p in (*self.files, *self.links) if self._gen.get(p, -1) < self._layer]:
            self._delete(p)
            self._prune(p)

    def _put_file(self, path: str, data: bytes) -> None:
        was_link = self.links.pop(path, None) is not None
        if path not in self.files and lang_kind(path):
            if self._lang_count >= MAX_LANG_FILES:
                self.truncated = True
                return
            self._lang_count += 1
        old = self.files.get(path)
        self._bytes += len(data) - (len(old) if old is not None else 0)
        if path.startswith(DPKG_STATUS_D + "/"):
            self._status_d += old is None
            self._status_d_bytes += len(data) - (len(old) if old is not None else 0)
        if old is None or was_link:
            self._track(path)
        self.files[path] = data
        self._gen[path] = self._layer

    def _admit(self, path: str, size: int) -> bool:
        """Budget check before reading a member of `size` bytes that will be retained."""
        if path == "var/lib/dpkg/status" or path.startswith(DPKG_STATUS_D + "/"):
            if size > MAX_DPKG_TEXT_BYTES:
                return False
            if path.startswith(DPKG_STATUS_D + "/"):
                if path not in self.files and self._status_d >= MAX_STATUS_D_FILES:
                    return False
                old_n = len(self.files.get(path, b""))
                if self._status_d_bytes - old_n + size > MAX_STATUS_D_BYTES:
                    return False
        elif size > MAX_FILE_BYTES:
            return False
        old = self.files.get(path)
        return self._bytes - (len(old) if old is not None else 0) + size <= MAX_VIEW_BYTES

    def add_layer(self, source: BinaryIO | str | Path) -> None:
        """Apply one layer. `source` is a path or a binary stream (plain, gzip or zstd tar)."""
        if isinstance(source, (str, Path)):
            with open(source, "rb") as f:
                self._add_stream(f)
        else:
            self._add_stream(source)

    def _add_stream(self, source: BinaryIO) -> None:
        stream = open_maybe_compressed(source)
        with tarfile.open(fileobj=stream, mode="r|") as tf:  # type: ignore[call-overload]
            self._layer += 1
            for m in tf:
                self._apply_member(tf, m)

    def _apply_member(self, tf: tarfile.TarFile, m: tarfile.TarInfo) -> None:
        path = norm_path(m.name)
        if not path:
            return
        d, _, base = path.rpartition("/")
        if base == ".wh..wh..opq":
            if d:
                self._remove_under(d, only_older=True)
            else:  # opaque root: everything older goes
                self._remove_everything_older()
            return
        if base.startswith(".wh."):
            target = f"{d}/{base[4:]}" if d else base[4:]
            self._remove_under(target, only_older=True)
            return
        if m.issym():
            self._remove_under(path, only_older=False)
            if len(self.links) >= MAX_LINKS:
                self.truncated = True
                return
            self.links[path] = m.linkname
            self._gen[path] = self._layer
            self._track(path)
        elif m.islnk():
            src = norm_path(m.linkname)
            if is_interesting(path) and src in self.files:
                self._put_file(path, self.files[src])
            self.lang.alias(path, src, layer=self._layer)
        elif m.isfile():
            wanted_fixed = path in FIXED_PATHS or path.startswith(DPKG_STATUS_D + "/")
            wanted_lang = self.lang.wants(path)
            if not (wanted_fixed or wanted_lang):
                return
            f = tf.extractfile(m)
            if f is None:
                return
            if wanted_fixed:
                if not self._admit(path, m.size):
                    self.truncated = True
                    return
                data = f.read()
                self._put_file(path, data)
                if wanted_lang:
                    self.lang.feed(path, m.size, _BytesReader(data).read, layer=self._layer, mode=m.mode)
            else:
                self.lang.feed(path, m.size, f.read, layer=self._layer, mode=m.mode)

    # ---- FsView

    def _readlink(self, path: str) -> str | None:
        return self.links.get(path)

    def _read_raw(self, path: str, limit: int) -> bytes | None:
        data = self.files.get(path)
        return None if data is None else data[:limit]

    def _listdir_raw(self, path: str) -> list[str]:
        return sorted(self._dirs.get(path, ()))

    def iter_lang_files(self) -> Iterator[tuple[str, str]]:
        for p in sorted(self.files):
            k = lang_kind(p)
            if k:
                yield p, k


# --------------------------------------------------------------------------- parsers

def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        out[k.strip()] = v
    return out


def _stanzas(text: str) -> Iterator[dict[str, str]]:
    cur: dict[str, str] = {}
    last: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if cur:
                yield cur
            cur, last = {}, None
        elif line[0] in " \t":
            if last:
                cur[last] += "\n" + line.strip()
        elif ":" in line:
            k, _, v = line.partition(":")
            last = k.strip().lower()
            cur[last] = v.strip()
    if cur:
        yield cur


_SRC_RE = re.compile(r"^(\S+)(?:\s+\(([^)]+)\))?$")


# Statuses whose files are on disk (unpacked but not yet configured, trigger processing pending, ...).
DPKG_PRESENT_STATES = frozenset({"installed", "unpacked", "half-configured", "triggers-awaited",
                                 "triggers-pending"})


def parse_dpkg_status(text: str) -> list[dict]:
    out = []
    for st in _stanzas(text):
        name, version = st.get("package"), st.get("version")
        status = st.get("status", "").split()
        if not name or not version or not status or status[-1] not in DPKG_PRESENT_STATES:
            continue
        src_name, src_version = name, version
        if st.get("source"):
            m = _SRC_RE.match(st["source"].strip())
            if m:
                src_name = m.group(1)
                src_version = m.group(2) or version
        out.append({"name": name, "version": version, "arch": st.get("architecture"), "state": status[-1],
                    "source": src_name, "source_version": src_version,
                    "maintainer": st.get("maintainer"), "homepage": st.get("homepage")})
    return out


def parse_apk_installed(text: str) -> list[dict]:
    out = []
    cur: dict[str, str] = {}

    def flush() -> None:
        if cur.get("P") and cur.get("V"):
            out.append({"name": cur["P"], "version": cur["V"], "arch": cur.get("A"),
                        "origin": cur.get("o") or cur["P"], "license": cur.get("L"),
                        "url": cur.get("U"), "maintainer": cur.get("m")})

    for line in text.splitlines():
        if not line.strip():
            flush()
            cur = {}
            continue
        if len(line) > 2 and line[1] == ":" and line[0] in "PVAoLUm":
            cur.setdefault(line[0], line[2:].strip())
    flush()
    return out


# rpm header (see _docs/tech/collectors/docker-image.md "Header blob format")
_RPM_NAME, _RPM_VERSION, _RPM_RELEASE, _RPM_EPOCH = 1000, 1001, 1002, 1003
_RPM_VENDOR, _RPM_LICENSE, _RPM_ARCH, _RPM_SOURCERPM = 1011, 1014, 1022, 1044
_RPM_WANT = {_RPM_NAME, _RPM_VERSION, _RPM_RELEASE, _RPM_EPOCH, _RPM_VENDOR, _RPM_LICENSE, _RPM_ARCH,
             _RPM_SOURCERPM}
_SRPM_RE = re.compile(r"^(.+)-[^-]+-[^-]+\.(?:src|nosrc)\.rpm$")


def parse_rpm_header(blob: bytes) -> dict[int, Any]:
    """Decode the wanted tags of one rpm header blob (as stored in rpmdb.sqlite)."""
    il, dl = struct.unpack(">II", blob[:8])
    if il > 100_000 or 8 + 16 * il + dl > len(blob):
        raise ValueError("bad rpm header")
    store = blob[8 + 16 * il: 8 + 16 * il + dl]
    out: dict[int, Any] = {}
    for i in range(il):
        tag, typ, off, cnt = struct.unpack(">IIiI", blob[8 + 16 * i: 24 + 16 * i])
        if tag not in _RPM_WANT or off < 0 or off >= max(dl, 1):
            continue
        if typ in (6, 9):
            out[tag] = store[off: store.index(b"\0", off)].decode("utf-8", "replace")
        elif typ == 8:
            vals, p = [], off
            for _ in range(cnt):
                e = store.index(b"\0", p)
                vals.append(store[p:e].decode("utf-8", "replace"))
                p = e + 1
            out[tag] = vals
        elif typ == 4:
            out[tag] = list(struct.unpack(f">{cnt}I", store[off: off + 4 * cnt]))
    return out


def rpm_source_name(srpm: str | None, fallback: str) -> str:
    if srpm:
        m = _SRPM_RE.match(srpm)
        if m:
            return m.group(1)
    return fallback


def _open_rpmdb_hardened(path: Path) -> sqlite3.Connection:
    """Open an untrusted rpmdb.sqlite read-only with SQLite's defensive settings."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        conn.execute("PRAGMA trusted_schema=OFF")
        setconfig = getattr(conn, "setconfig", None)       # Python 3.12+
        if setconfig is not None and hasattr(sqlite3, "SQLITE_DBCONFIG_DEFENSIVE"):
            setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        deadline = time.monotonic() + RPM_TIME_BUDGET
        left = [RPM_VM_BUDGET // 1000]

        def budget() -> int:
            left[0] -= 1
            return 1 if left[0] < 0 or time.monotonic() > deadline else 0   # non-zero aborts the query

        conn.set_progress_handler(budget, 1000)
        schema = conn.execute("SELECT type, name FROM sqlite_master").fetchall()
    except sqlite3.Error:
        conn.close()
        raise
    # A genuine rpmdb has the real table `Packages` and no views/triggers; a view named `Packages`
    # (e.g. a recursive CTE) is a denial-of-service vector.
    if any(t in ("view", "trigger") for t, _ in schema) or ("table", "Packages") not in schema:
        conn.close()
        raise sqlite3.DatabaseError("rpmdb.sqlite has no plain `Packages` table (or contains views/triggers)")
    return conn


def parse_rpmdb_sqlite(path: str | Path) -> list[dict]:
    """Packages of an rpmdb.sqlite. The db (and its -wal) is copied to a temp dir first so that
    it can be opened read-only without touching the source and with the WAL replayed.

    The file is untrusted: opened defensively (trusted_schema off, DEFENSIVE where available), only
    a real `Packages` table is read, with a VM-instruction/time budget, a row cap and a per-blob cap.
    """
    path = Path(path)
    with tempfile.TemporaryDirectory(prefix="secmonk-rpm-") as td:
        dst = Path(td) / "rpmdb.sqlite"
        shutil.copyfile(path, dst)
        wal = Path(str(path) + "-wal")
        if wal.is_file() and wal.stat().st_size > 0:
            shutil.copyfile(wal, Path(td) / "rpmdb.sqlite-wal")
        conn = _open_rpmdb_hardened(dst)
        try:
            rows = []
            cur = conn.execute("SELECT hnum, CASE WHEN length(blob) <= ? THEN blob END FROM Packages "
                               "ORDER BY hnum", (MAX_RPM_BLOB,))
            while batch := cur.fetchmany(1000):
                rows.extend(r for r in batch if r[1] is not None)
                if len(rows) >= MAX_RPM_ROWS:
                    break
        finally:
            conn.close()
    out = []
    for _, blob in rows:
        try:
            h = parse_rpm_header(bytes(blob))
        except (ValueError, struct.error):
            continue
        name = h.get(_RPM_NAME)
        if not name or name == "gpg-pubkey":
            continue
        epoch = h.get(_RPM_EPOCH)
        srpm = h.get(_RPM_SOURCERPM)
        if srpm == "(none)":
            srpm = None
        lic = h.get(_RPM_LICENSE)
        out.append({
            "name": name, "version": h.get(_RPM_VERSION), "release": h.get(_RPM_RELEASE),
            "epoch": epoch[0] if epoch else None, "arch": h.get(_RPM_ARCH),
            "source_rpm": srpm, "source_name": rpm_source_name(srpm, name),
            "vendor": h.get(_RPM_VENDOR), "license": lic,
        })
    return out


def parse_python_metadata(text: str) -> dict:
    """Core metadata (`METADATA` / `PKG-INFO`): RFC822 headers up to the first blank line."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            break
        if line[0] in " \t" or ":" not in line:
            continue
        k, _, v = line.partition(":")
        out.setdefault(k.strip().lower(), v.strip())
    return {"name": out.get("name"), "version": out.get("version"), "license": out.get("license"),
            "summary": out.get("summary"), "home_page": out.get("home-page")}


def parse_package_json(text: str) -> dict:
    try:
        d = json.loads(text)
    except ValueError:
        return {}
    if not isinstance(d, dict):
        return {}
    lic = d.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    return {"name": d.get("name") if isinstance(d.get("name"), str) else None,
            "version": d.get("version") if isinstance(d.get("version"), str) else None,
            "license": lic if isinstance(lic, str) else None, "private": bool(d.get("private"))}


# --------------------------------------------------------------------------- collection

_PURL_NS = {"rhel": "redhat", "redhat": "redhat"}


def detect_os(view: FsView) -> dict[str, str]:
    """os-release (or legacy release files) as a dict with at least ID/VERSION_ID when known."""
    for p in OS_RELEASE_PATHS:
        t = view.read_text(p)
        if t:
            d = parse_os_release(t)
            if d.get("ID") or d.get("NAME"):
                d.setdefault("ID", re.sub(r"[^a-z0-9._-]+", "-", d.get("NAME", "").lower()).strip("-"))
                return d
    t = view.read_text("etc/alpine-release")
    if t and t.strip():
        return {"ID": "alpine", "NAME": "Alpine Linux", "VERSION_ID": t.strip()}
    t = view.read_text("etc/redhat-release")
    if t:
        m = re.match(r"^(.*?)\s+release\s+(\d[\d.]*)", t.strip())
        if m:
            name = m.group(1)
            low = name.lower()
            rid = ("rhel" if "red hat" in low else "rocky" if "rocky" in low else "almalinux" if "alma" in low
                   else "centos" if "centos" in low else re.sub(r"\W+", "-", low))
            return {"ID": rid, "NAME": name, "VERSION_ID": m.group(2)}
    t = view.read_text("etc/debian_version")
    if t and t.strip() and t.strip()[0].isdigit():
        return {"ID": "debian", "NAME": "Debian GNU/Linux", "VERSION_ID": t.strip()}
    return {}


UBUNTU_CODENAMES = {
    "trusty": "14.04", "xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04",
    "kinetic": "22.10", "lunar": "23.04", "mantic": "23.10", "noble": "24.04", "oracular": "24.10",
    "plucky": "25.04", "questing": "25.10", "resolute": "26.04",
}
DEBIAN_CODENAMES = {
    "jessie": "8", "stretch": "9", "buster": "10", "bullseye": "11", "bookworm": "12",
    "trixie": "13", "forky": "14", "duke": "15",
}


def _debian_version_of(text: str | None) -> str | None:
    """Debian major release from /etc/debian_version ('12.5', 'bookworm/sid')."""
    t = (text or "").strip().lower()
    if not t:
        return None
    if re.fullmatch(r"\d+(\.\d+)*", t):
        return t.split(".")[0]
    return DEBIAN_CODENAMES.get(re.split(r"[/\s]", t)[0])


def _parent_release(like: str, osr: dict[str, str], debian_version: str | None) -> str | None:
    """Release of the parent distro of a derivative (Kali, Mint, ...), if the image says which one."""
    if like == "ubuntu":
        return UBUNTU_CODENAMES.get(osr.get("UBUNTU_CODENAME", "").lower())
    if like == "debian":
        return DEBIAN_CODENAMES.get(osr.get("DEBIAN_CODENAME", "").lower()) or _debian_version_of(debian_version)
    return None


def distro_ecosystem(osr: dict[str, str], debian_version: str | None = None,
                     warnings: list[str] | None = None) -> str | None:
    """OSV ecosystem for an os-release. A derivative's own VERSION_ID (Kali 2024.1, Mint 21.3) says
    nothing about its parent, so for ID_LIKE matches the parent release is derived from
    UBUNTU_CODENAME / DEBIAN_CODENAME / etc/debian_version; when that is unknown only the bare base
    ecosystem ('Debian') is returned, with a warning."""
    vid = osr.get("VERSION_ID")
    eco = purls.osv_distro_ecosystem(osr.get("ID", ""), vid)
    if eco:
        return eco
    first_bare: tuple[str, str] | None = None
    for like in osr.get("ID_LIKE", "").split():
        bare = purls.osv_distro_ecosystem(like, None)
        if not bare:
            continue
        rel = _parent_release(like, osr, debian_version)
        if rel:
            eco = purls.osv_distro_ecosystem(like, rel)
            if eco:
                return eco
        first_bare = first_bare or (like, bare)
    if first_bare:
        if warnings is not None:
            warnings.append(f"{osr.get('ID')} is derived from {first_bare[0]} but its release could not be "
                            f"determined; matching against all {first_bare[1]} advisories (less precise)")
        return first_bare[1]
    return None


def _distro_qualifier(osr: dict[str, str]) -> str | None:
    did, vid = osr.get("ID"), osr.get("VERSION_ID")
    if did and vid:
        return f"{did}-{vid}"
    return did or None


def _os_component(osr: dict[str, str], ecosystem: str | None) -> Component:
    did = osr.get("ID", "")
    vid = osr.get("VERSION_ID")
    name = osr.get("NAME") or did
    purl = purls.build("generic", did, vid) if did else None
    return Component(
        name=name, version=vid, category=CAT_OS, purl=purl, vendor=did or None,
        source_path="etc/os-release",
        meta={"pretty_name": osr.get("PRETTY_NAME"), "codename": osr.get("VERSION_CODENAME"),
              "id": did, "id_like": osr.get("ID_LIKE"), "cpe_name": osr.get("CPE_NAME"),
              "osv_ecosystem": ecosystem},
    )


def collect_from_view(view: FsView, asset: Asset, warnings: list[str] | None = None) -> list[Component]:
    """Inventory of one filesystem view. Fills `asset.os_name/os_version` when still empty."""
    warn = warnings if warnings is not None else []
    comps: dict[str, Component] = {}

    def add(c: Component) -> None:
        comps.setdefault(c.key, c)

    osr = detect_os(view)
    ecosystem = None
    if osr:
        needs_dv = not purls.osv_distro_ecosystem(osr.get("ID", ""), osr.get("VERSION_ID")) \
            and "debian" in osr.get("ID_LIKE", "").split()
        ecosystem = distro_ecosystem(osr, view.read_text("etc/debian_version", 256) if needs_dv else None, warn)
    ns_id = osr.get("ID") or ""
    qual = _distro_qualifier(osr)
    if osr:
        add(_os_component(osr, ecosystem))
        asset.os_name = asset.os_name or osr.get("NAME") or ns_id
        asset.os_version = asset.os_version or osr.get("VERSION_ID")
    found_db = False

    # ---- dpkg
    texts = []
    st = view.read_text("var/lib/dpkg/status", MAX_FILE_BYTES)
    if st:
        texts.append(("var/lib/dpkg/status", st))
    for fn in view.listdir(DPKG_STATUS_D):
        if fn.endswith((".md5sums", ".list", ".conffiles")):
            continue
        t = view.read_text(f"{DPKG_STATUS_D}/{fn}")
        if t:
            texts.append((f"{DPKG_STATUS_D}/{fn}", t))
    for src, text in texts:
        found_db = True
        for p in parse_dpkg_status(text):
            q = {"arch": p["arch"], "distro": qual}
            if p["source"] != p["name"]:
                q["upstream"] = p["source"]
            add(Component(
                name=p["name"], version=p["version"], category=CAT_OS_PACKAGE, ecosystem=ecosystem,
                purl=purls.build("deb", p["name"], p["version"], namespace=ns_id or "debian", qualifiers=q),
                vendor=ns_id or None, source_path=src,
                meta={"pkg_type": "deb", "arch": p["arch"], "source_package": p["source"],
                      "source_version": p["source_version"], "maintainer": p["maintainer"],
                      **({"dpkg_state": p["state"]} if p["state"] != "installed" else {})}))

    # ---- apk
    t = view.read_text("lib/apk/db/installed", MAX_FILE_BYTES)
    if t:
        found_db = True
        for p in parse_apk_installed(t):
            q = {"arch": p["arch"], "distro": qual}
            if p["origin"] != p["name"]:
                q["upstream"] = p["origin"]
            add(Component(
                name=p["name"], version=p["version"], category=CAT_OS_PACKAGE, ecosystem=ecosystem,
                purl=purls.build("apk", p["name"], p["version"], namespace=ns_id or "alpine", qualifiers=q),
                vendor=ns_id or None, source_path="lib/apk/db/installed",
                meta={"pkg_type": "apk", "arch": p["arch"], "source_package": p["origin"],
                      "source_version": p["version"], "license": p["license"]}))

    # ---- rpm
    rpm_found = False
    for path in RPM_SQLITE:
        data = view.read(path, MAX_FILE_BYTES)
        if not data:
            continue
        rpm_found = found_db = True
        if not data.startswith(b"SQLite format 3\x00"):
            warn.append(f"{path}: not an SQLite database, skipped")
            continue
        try:
            rows = _rpm_rows_from_bytes(data, view.read(path + "-wal", MAX_FILE_BYTES))
        except (sqlite3.Error, OSError) as e:
            warn.append(f"{path}: cannot read rpm database ({e})")
            continue
        for p in rows:
            if not p["version"]:
                continue
            epoch = p["epoch"]
            ver_rel = f"{p['version']}-{p['release']}" if p["release"] else p["version"]
            q = {"arch": p["arch"], "distro": qual}
            if epoch is not None:
                q["epoch"] = str(epoch)
            if p["source_name"] != p["name"]:
                q["upstream"] = p["source_name"]
            full = f"{epoch if epoch is not None else 0}:{ver_rel}"
            ns = _PURL_NS.get(ns_id, ns_id) or "redhat"
            add(Component(
                name=p["name"], version=full, category=CAT_OS_PACKAGE, ecosystem=ecosystem,
                purl=purls.build("rpm", p["name"], ver_rel, namespace=ns, qualifiers=q),
                vendor=ns_id or p["vendor"], source_path=path,
                meta={"pkg_type": "rpm", "arch": p["arch"], "epoch": epoch, "release": p["release"],
                      "source_package": p["source_name"], "source_version": full,
                      "source_rpm": p["source_rpm"], "rpm_vendor": p["vendor"], "license": p["license"]}))
        break  # /var/lib/rpm may be a symlink to the sysimage dir: do not read the same db twice
    if not rpm_found:
        for path in RPM_LEGACY:
            data = view.read(path, 16)
            if data:
                found_db = True
                warn.append(f"{path}: BerkeleyDB/NDB rpm database is not supported; rpm packages not listed")
                break

    if osr and not found_db:
        warn.append("no dpkg/apk/rpm package database found (distroless/scratch or unsupported layout)")
    if not osr:
        warn.append("operating system not identified (no os-release)")

    # ---- language packages (all ecosystems, see collectors/lang/)
    for c in lang_components(view, warn):
        add(c)
    if getattr(view, "truncated", False):
        warn.append("some files exceeded size/count limits")
    return list(comps.values())


class _BytesReader:
    """read(n=-1) over in-memory bytes (to feed already-read data to the lang accumulator)."""

    def __init__(self, data: bytes):
        self._data, self._pos = data, 0

    def read(self, n: int = -1) -> bytes:
        end = len(self._data) if n is None or n < 0 else self._pos + n
        out = self._data[self._pos:end]
        self._pos += len(out)
        return out


def lang_components(view: FsView, warn: list[str], binaries: bool = True) -> list[Component]:
    """Language dependencies of a view: parsed while streaming for image layers, walked for dirs."""
    if isinstance(view, LayeredTarView):
        warn.extend(view.lang.warnings)
        if view.lang.truncated:
            warn.append("language dependency file limit reached")
            view.truncated = True
        return view.lang.components()
    if isinstance(view, DirView):
        from .lang.walk import WalkLimits, walk_dir

        res = walk_dir(view.root, limits=WalkLimits(binaries=binaries), rootfs=True, path_prefix="/")
        warn.extend(res.warnings)
        if res.truncated:
            view.truncated = True
        return res.components
    return []


def _rpm_rows_from_bytes(db: bytes, wal: bytes | None) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="secmonk-rpmdb-") as td:
        p = Path(td) / "rpmdb.sqlite"
        p.write_bytes(db)
        if wal:
            Path(td, "rpmdb.sqlite-wal").write_bytes(wal)
        return parse_rpmdb_sqlite(p)


# --------------------------------------------------------------------------- collector

@register
class RootfsCollector(Collector):
    name = "rootfs"
    description = "Linux root filesystem directory (dpkg/apk/rpm + python/npm packages)"

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        if not target:
            raise ValueError("rootfs collector needs a directory (e.g. an extracted image or chroot)")
        view = DirView(target)
        asset = Asset(id=f"rootfs:{view.root}", type="server", name=view.root.name or str(view.root),
                      meta={"path": str(view.root)})
        warnings: list[str] = []
        comps = collect_from_view(view, asset, warnings)
        inv = Inventory(asset=asset, collector=self.name, components=comps, warnings=warnings)
        if view.truncated:
            inv.mark_partial("file/count limits reached while walking the tree")
        return inv

