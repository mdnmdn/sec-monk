#!/usr/bin/env python3
"""Regenerate the desktop app icon set from rust/assets/logo-orange.png (the single origin).

Steps: (1) crop the black rounded tile out of the source and make its outside corners transparent
(radius measured from the image, anti-aliased) -> rust/assets/app-icon.png; (2) `cargo tauri icon`
writes the set into apps/desktop/src-tauri/icons/. Stdlib only (no Pillow); needs the tauri CLI.

    python3 rust/scripts/make_icons.py            # from anywhere
"""
from __future__ import annotations

import math
import struct
import shutil
import subprocess
import zlib
from pathlib import Path

RUST = Path(__file__).resolve().parent.parent
SRC = RUST / "assets" / "logo-orange.png"
MASTER = RUST / "assets" / "app-icon.png"
TAURI = RUST / "apps" / "desktop" / "src-tauri"
DARK = 80  # luminance below this counts as tile


def read_rgb(path: Path):
    d = path.read_bytes()
    p, idat, w, h = 8, b"", 0, 0
    while p < len(d):
        n, t = struct.unpack(">I4s", d[p : p + 8])
        if t == b"IHDR":
            w, h, depth, ctype = struct.unpack(">IIBB", d[p + 8 : p + 18])
            assert (depth, ctype) == (8, 2), "expected 8-bit RGB"
        elif t == b"IDAT":
            idat += d[p + 8 : p + 8 + n]
        p += 12 + n
    raw, stride, rows, prev = zlib.decompress(idat), w * 3, [], bytearray(w * 3)
    for y in range(h):
        f, line = raw[y * (stride + 1)], bytearray(raw[y * (stride + 1) + 1 : (y + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - 3] if i >= 3 else 0
            b = prev[i]
            c = prev[i - 3] if i >= 3 else 0
            if f == 1: line[i] = (line[i] + a) & 255
            elif f == 2: line[i] = (line[i] + b) & 255
            elif f == 3: line[i] = (line[i] + (a + b) // 2) & 255
            elif f == 4:
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append(line)
        prev = line
    return w, h, rows


def dark(rows, x, y):
    r, g, b = rows[y][3 * x : 3 * x + 3]
    return (r + g + b) / 3 < DARK


def write_rgba(path: Path, w: int, h: int, rows):
    def chunk(t, c):
        return struct.pack(">I", len(c)) + t + c + struct.pack(">I", zlib.crc32(t + c))
    raw = b"".join(b"\0" + bytes(r) for r in rows)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def main() -> None:
    w, h, rows = read_rgb(SRC)
    mid = h // 2
    x0 = next(x for x in range(w) if dark(rows, x, mid))          # tile left edge
    x1 = next(x for x in range(w - 1, -1, -1) if dark(rows, x, mid)) + 1
    y0 = next(y for y in range(h) if dark(rows, mid, y))
    y1 = next(y for y in range(h - 1, -1, -1) if dark(rows, mid, y)) + 1
    s = min(x1 - x0, y1 - y0)
    # first dark pixel on the top-left diagonal: k = r * (1 - 1/sqrt2)
    k = next(k for k in range(s // 2) if dark(rows, x0 + k, y0 + k))
    r = k / (1 - math.sqrt(0.5))
    print(f"tile {x0},{y0} size {s}px, corner radius ~{r:.0f}px ({100 * r / s:.1f}% of the tile)")
    out = []
    for y in range(s):
        line = bytearray()
        for x in range(s):
            # signed distance to the rounded square, 1px linear anti-aliasing
            dx = max(r - x - 0.5, x + 0.5 - (s - r), 0)
            dy = max(r - y - 0.5, y + 0.5 - (s - r), 0)
            a = max(0.0, min(1.0, r - math.hypot(dx, dy) + 0.5)) if dx and dy else 1.0
            line += rows[y0 + y][3 * (x0 + x) : 3 * (x0 + x) + 3] + bytes([round(a * 255)])
        out.append(line)
    write_rgba(MASTER, s, s, out)
    subprocess.run(["cargo", "tauri", "icon", str(MASTER), "-o", str(TAURI / "icons")], check=True, cwd=RUST)
    for mobile in ("android", "ios"):  # desktop app only
        shutil.rmtree(TAURI / "icons" / mobile, ignore_errors=True)


if __name__ == "__main__":
    main()
