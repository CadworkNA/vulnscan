"""Seed corpus for the fuzz targets, generated rather than committed (no binaries in the repository).

    python fuzz/seeds.py binary|paths <corpus-dir>

The binary seeds are minimal but valid PE32+ DLLs with a VS_VERSIONINFO resource and embedded version banners,
so the fuzzer starts from inputs that reach the version-resource parser, the identification rules and the
signature scan instead of having to discover the PE format from scratch.
"""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

# First byte of a binary-target input picks the file name (identification rules match on it); the rest is the file.
NAMES = [
    "bin/target.dll", "bin/libcrypto-1_1-x64.dll", "bin/python311.dll", "bin/Qt5Core.dll", "bin/libcef.dll",
    "bin/electron.exe", "bin/sqlite3.dll", "bin/zlib1.dll", "bin/libcurl.dll", "bin/libxml2.dll", "bin/7z.dll",
    "bin/unzip.exe", "bin/zip.exe", "bin/opencv_world455.dll", "bin/avcodec-58.dll", "bin/node.exe",
    "bin/gsdll64.dll", "bin/icuuc72.dll", "bin/libpng16.dll", "bin/msvcr120.dll", "bin/vcruntime140.dll",
]


def _utf16z(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\0\0"


def _block(key: str, value: bytes = b"", *, text: bool = False, children: list[bytes] = ()) -> bytes:
    """One VS_VERSIONINFO node: wLength, wValueLength, wType, key, value, children (all 32-bit aligned)."""
    body = _utf16z(key)
    head_len = 6 + len(body)
    data = body + b"\0" * (-head_len % 4) + value
    for child in children:
        data += b"\0" * (-(6 + len(data)) % 4) + child
    value_len = len(value) // 2 if text else len(value)
    return struct.pack("<HHH", 6 + len(data), value_len, 1 if text else 0) + data


def _version_info(strings: dict[str, str], version: tuple[int, int, int, int]) -> bytes:
    ms, ls = (version[0] << 16) | version[1], (version[2] << 16) | version[3]
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x00010000, ms, ls, ms, ls, 0x3F, 0, 0x40004, 2, 0, 0, 0)
    table = _block("040904B0", text=True,
                   children=[_block(k, _utf16z(v), text=True) for k, v in strings.items()])
    sfi = _block("StringFileInfo", text=True, children=[table])
    vfi = _block("VarFileInfo", text=True, children=[_block("Translation", struct.pack("<HH", 0x409, 1200))])
    return _block("VS_VERSION_INFO", fixed, children=[sfi, vfi])


def _import_table(base: int, imports: dict[str, list[str | int]]) -> tuple[bytes, int]:
    """Import directory at RVA `base`: descriptors, lookup tables (PE32+), hint/name entries, DLL names.
    Functions given as int are imported by ordinal. Returns (bytes, size of the descriptor array)."""
    desc_size = 20 * (len(imports) + 1)
    data, descs = bytearray(), []
    for dll, funcs in imports.items():
        names = bytearray()
        names_at = desc_size + len(data) + 8 * (len(funcs) + 1)
        ilt = bytearray()
        for f in funcs:
            if isinstance(f, int):
                ilt += struct.pack("<Q", (1 << 63) | f)
            else:
                ilt += struct.pack("<Q", base + names_at + len(names))
                names += struct.pack("<H", 0) + f.encode() + b"\0"
                names += b"\0" * (len(names) % 2)
        ilt += struct.pack("<Q", 0)
        ilt_rva = base + desc_size + len(data)
        data += ilt + names
        name_rva = base + desc_size + len(data)
        data += dll.encode() + b"\0"
        data += b"\0" * (-len(data) % 8)
        descs.append(struct.pack("<IIIII", ilt_rva, 0, 0, name_rva, ilt_rva))
    return b"".join(descs) + b"\0" * 20 + bytes(data), desc_size


def build_pe(strings: dict[str, str], version: tuple[int, int, int, int], banner: bytes = b"",
             imports: dict[str, list[str | int]] | None = None) -> bytes:
    """A PE32+ DLL with one section holding an RT_VERSION resource, `banner` bytes and an optional import table."""
    rva = 0x1000
    vi = _version_info(strings, version)
    rsrc = b"".join([
        struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1), struct.pack("<II", 16, 0x80000000 | 24),       # type: RT_VERSION
        struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1), struct.pack("<II", 1, 0x80000000 | 48),        # name: 1
        struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1), struct.pack("<II", 0x409, 72),                 # language: en-US
        struct.pack("<IIII", rva + 88, len(vi), 0, 0),                                           # data entry
        vi,
    ]) + banner
    rsrc_len = len(rsrc) - len(banner)
    imp_dir = (0, 0)
    if imports:
        rsrc += b"\0" * (-len(rsrc) % 8)
        table, desc_size = _import_table(rva + len(rsrc), imports)
        imp_dir = (rva + len(rsrc), desc_size)
        rsrc += table
    raw = rsrc + b"\0" * (-len(rsrc) % 0x200)
    image_size = rva + ((len(rsrc) + 0xFFF) & ~0xFFF)
    dirs = [(0, 0)] * 16
    dirs[1] = imp_dir
    dirs[2] = (rva, rsrc_len)
    optional = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
                           0x20B, 14, 0, 0, len(raw), 0, 0, rva, 0x180000000, 0x1000, 0x200,
                           6, 0, 1, 0, 6, 0, 0, image_size, 0x200, 0, 2, 0x160,
                           0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    optional += b"".join(struct.pack("<II", *d) for d in dirs)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0x5F000000, 0, 0, len(optional), 0x2022)
    section = struct.pack("<8sIIIIIIHHI", b".rsrc", len(rsrc), rva, len(raw), 0x200, 0, 0, 0, 0, 0x40000040)
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    headers = dos + b"PE\0\0" + coff + optional + section
    return headers + b"\0" * (0x200 - len(headers)) + raw


def binary_seeds() -> dict[str, bytes]:
    def strings(company, product, version, original):
        return {"CompanyName": company, "FileDescription": product, "FileVersion": version,
                "InternalName": original.rsplit(".", 1)[0], "LegalCopyright": f"Copyright (C) {company}",
                "OriginalFilename": original, "ProductName": product, "ProductVersion": version}

    def seed(name, company, product, version, original, banner=b""):
        parts = (*map(int, re.findall(r"\d+", version)), 0, 0, 0, 0)[:4]
        return bytes([NAMES.index(name)]) + build_pe(strings(company, product, version, original), parts, banner)

    return {
        "openssl": seed("bin/libcrypto-1_1-x64.dll", "The OpenSSL Project, https://www.openssl.org/",
                        "The OpenSSL Toolkit", "1.1.1k", "libcrypto-1_1-x64.dll",
                        b"\0OpenSSL 1.1.1k  25 Mar 2021\0"),
        "python": seed("bin/python311.dll", "Python Software Foundation", "Python", "3.11.4", "python311.dll",
                       b"\x003.11.4 (tags/v3.11.4:d2340ef, Jun  7 2023)\0"),
        "qt": seed("bin/Qt5Core.dll", "The Qt Company Ltd.", "Qt5", "5.15.2.0", "Qt5Core.dll",
                   b"\0Qt 5.15.2 (x86_64-little_endian-llp64 shared (dynamic) release build; by MSVC 2019)\0"),
        "first-party": seed("bin/target.dll", "cadwork informatik AG", "cadwork", "30.0.1.0", "target.dll",
                            b"\0inflate 1.2.11 Copyright 1995-2017 Mark Adler \0libpng version 1.6.37\0"
                            b"SQLite version 3.31.1\0libcurl/7.68.0\0"),
        "oda": seed("bin/target.dll", "Open Design Alliance", "ODA Drawings SDK", "23.12.0.0", "TD_Db.dll"),
        "electron": seed("bin/electron.exe", "GitHub, Inc.", "Electron", "22.3.27", "electron.exe",
                         b"\0Chrome/108.0.5359.215 Electron/22.3.27\0"),
        "opencv": seed("bin/opencv_world455.dll", "", "OpenCV module", "4.5.5", "opencv_world455.dll",
                       b"\0General configuration for OpenCV 4.5.5 =\0FFmpeg version n4.4.1\0"),
        "importer": bytes([NAMES.index("bin/target.dll")]) + build_pe(
            strings("cadwork informatik AG", "cadwork", "30.0.1.0", "target.dll"), (30, 0, 1, 0),
            imports={"libcrypto-1_1-x64.dll": ["EVP_EncryptInit_ex", "SSL_CTX_new", 42],
                     "KERNEL32.dll": ["GetProcAddress"]}),
        "not-pe": bytes([0]) + b"MZ" + b"\0" * 100,
    }


def paths_seeds() -> dict[str, bytes]:
    return {name: rel.encode() for name, rel in {
        "plain": "files/bin/setup.zip", "nested": "archives/bin/setup.zip!/inner/data.7z",
        "msi": "archives/pkg.msi!/.:Windows/.:System32/.:./x.dll", "dotdot": "files/../archives/x.zip",
        "msi-dotdot": "archives/a.msi!/.:../.:../x", "outside": "../../etc/passwd",
    }.items()}


if __name__ == "__main__":
    target, out = sys.argv[1], Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    for name, data in {"binary": binary_seeds, "paths": paths_seeds}[target]().items():
        (out / f"seed-{name}").write_bytes(data)
