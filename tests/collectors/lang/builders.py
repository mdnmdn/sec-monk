"""Shared builders for synthetic executables (large / sparse binaries without committing any)."""

from __future__ import annotations

import struct

GO_MAGIC = b"\xff Go buildinf:"


def go_blob(mod_text: str = "path\tm\nmod\tm\t(devel)\t\ndep\tgolang.org/x/net\tv0.1.0\th1:x\n",
            version: str = "go1.22.3", ptrsize: int = 8, flags: int = 2) -> bytes:
    """A Go >= 1.18 buildinfo header + inline version/modinfo strings."""
    sent = b"0123456789abcdef"
    modbytes = sent + mod_text.encode() + sent
    ver = version.encode()
    return (GO_MAGIC + bytes([ptrsize, flags]) + b"\0" * 16 + bytes([len(ver)]) + ver
            + bytes([len(modbytes) & 0x7F | 0x80, len(modbytes) >> 7]) + modbytes)


def elf_with_section(blob: bytes, *, pad: int, etype: int = 2, section_name: bytes = b".go.buildinfo",
                     with_sections: bool = True) -> bytes:
    """Minimal ELF64-LE: `blob` placed `pad` bytes into the file (16-aligned), section headers
    (null, `section_name`, .shstrtab) at the very end. Zero padding keeps the test file cheap."""
    pad = (pad + 15) // 16 * 16
    strtab = b"\0" + section_name + b"\0.shstrtab\0"
    stroff = pad + len(blob)
    shoff = (stroff + len(strtab) + 7) // 8 * 8

    def sh(name, off, size):
        return struct.pack("<IIQQQQIIQQ", name, 1, 0, 0, off, size, 0, 0, 1, 0)

    shdrs = sh(0, 0, 0) + sh(1, pad, len(blob)) + sh(1 + len(section_name) + 1, stroff, len(strtab))
    hdr = bytearray(64)
    hdr[:4] = b"\x7fELF"
    hdr[4], hdr[5], hdr[6] = 2, 1, 1
    struct.pack_into("<H", hdr, 16, etype)
    if with_sections:
        struct.pack_into("<Q", hdr, 0x28, shoff)
        struct.pack_into("<HHH", hdr, 0x3A, 64, 3, 2)
    out = bytearray(shoff + len(shdrs))
    out[:64] = hdr
    out[pad:pad + len(blob)] = blob
    out[stroff:stroff + len(strtab)] = strtab
    out[shoff:] = shdrs
    return bytes(out)


def macho_with_section(blob: bytes, *, pad: int = 4096) -> bytes:
    """Thin 64-bit little-endian Mach-O with `__DATA,__go_buildinfo` at file offset `pad`."""
    sect = (b"__go_buildinfo".ljust(16, b"\0") + b"__DATA".ljust(16, b"\0")
            + struct.pack("<QQIIIIIIII", 0, len(blob), pad, 4, 0, 0, 0, 0, 0, 0))
    seg = (struct.pack("<II", 0x19, 72 + 80) + b"__DATA".ljust(16, b"\0")
           + struct.pack("<QQQQiiII", 0, 0x10000, pad, len(blob), 3, 3, 1, 0) + sect)
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(seg), 0, 0)
    out = bytearray(pad + len(blob))
    out[:len(hdr) + len(seg)] = hdr + seg
    out[pad:] = blob
    return bytes(out)


def pe_with_data(blob: bytes, *, pad: int = 4096) -> bytes:
    """Minimal PE with a `.data` section holding `blob` at raw offset `pad`."""
    e_lfanew = 0x80
    optsize = 0xF0
    out = bytearray(pad + len(blob))
    out[:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, e_lfanew)
    out[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HH", out, e_lfanew + 4, 0x8664, 1)
    struct.pack_into("<H", out, e_lfanew + 20, optsize)
    sp = e_lfanew + 24 + optsize
    out[sp:sp + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", out, sp + 8, len(blob), 0x1000, len(blob), pad)
    out[pad:] = blob
    return bytes(out)
