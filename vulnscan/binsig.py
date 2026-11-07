"""Version-signature detection of third-party libraries embedded in binaries.

Libraries are frequently compiled statically into first-party DLLs/EXEs, where
neither a version resource nor a package manifest reveals them. Each signature
is a cheap literal anchor (located with mmap.find at C speed) followed by a strict
regex applied around the hit, so false positives stay low.

Each entry: (vendor, product, anchor, regex-with-one-group, description)
vendor/product are NVD CPE identifiers used for matching.
"""
from __future__ import annotations

import mmap
import re

SIGNATURES: list[tuple] = [
    ("openssl", "openssl", b"OpenSSL ",
     rb"OpenSSL (\d\.\d+\.\d+[a-z]{0,2})(?:-fips|-dev)?\s+\d{1,2} [A-Z][a-z]{2} \d{4}", "OpenSSL version banner"),
    ("zlib", "zlib", b" Copyright 1995-",
     rb"(?:deflate|inflate) (\d\.\d+(?:\.\d+){0,2}(?:\.\d)?) Copyright 1995-", "zlib copyright banner"),
    ("libpng", "libpng", b"libpng version ",
     rb"libpng version (\d\.\d+\.\d+)", "libpng version string"),
    ("libjpeg-turbo", "libjpeg-turbo", b"libjpeg-turbo version ",
     rb"libjpeg-turbo version (\d\.\d+\.\d+)", "libjpeg-turbo version string"),
    ("libtiff", "libtiff", b"LIBTIFF, Version ",
     rb"LIBTIFF, Version (\d\.\d+\.\d+)", "libtiff version string"),
    ("haxx", "curl", b"libcurl/",
     rb"libcurl/(\d+\.\d+\.\d+)", "libcurl user-agent/version"),
    ("libexpat_project", "libexpat", b"expat_",
     rb"expat_(\d\.\d+\.\d+)", "expat version string"),
    ("python", "python", b" (tags/v",
     rb"(\d\.\d{1,2}\.\d{1,2}) \(tags/v\d\.\d{1,2}\.\d{1,2}", "CPython build string"),
    ("qt", "qt", b"Qt ",
     rb"Qt (\d\.\d{1,2}\.\d{1,2}) \((?:x86_64|i386|arm64|x86)-", "Qt build string"),
    ("ffmpeg", "ffmpeg", b"FFmpeg version ",
     rb"FFmpeg version n?(\d+\.\d+(?:\.\d+)?)", "FFmpeg version string"),
    ("7-zip", "7-zip", b"7-Zip ",
     rb"7-Zip (?:\([ar]\) )?(\d{1,2}\.\d{2}) (?:\(x64\)|\(x86\)|\(arm64\)|: Copyright)", "7-Zip banner"),
    ("bzip", "bzip2", (b", 13-Jul-2019", b", 27-Jun-2019", b", 6-Sept-2010", b", 10-Dec-2007", b", 20-Dec-2006"),
     rb"(1\.0\.\d), \d{1,2}-[A-Z][a-z]{2,3}-\d{4}", "bzip2 version string"),
    ("libarchive", "libarchive", b"libarchive ",
     rb"libarchive (\d\.\d+\.\d+)", "libarchive version string"),
    ("libssh2", "libssh2", b"SSH-2.0-libssh2_",
     rb"SSH-2\.0-libssh2_(\d\.\d+\.\d+)", "libssh2 banner"),
    ("libssh", "libssh", b"SSH-2.0-libssh_",
     rb"SSH-2\.0-libssh_(\d\.\d+\.\d+)", "libssh banner"),
    ("nghttp2", "nghttp2", b"nghttp2/",
     rb"nghttp2/(\d\.\d+\.\d+)", "nghttp2 version string"),
    ("artifex", "ghostscript", b"GPL Ghostscript ",
     rb"GPL Ghostscript (\d+\.\d+(?:\.\d+)?)", "Ghostscript banner"),
    ("lua", "lua", b"Lua 5.",
     rb"Lua (5\.\d\.\d+)\s+Copyright", "Lua banner"),
    ("arm", "mbed_tls", b"mbed TLS ",
     rb"mbed TLS (\d\.\d+\.\d+)", "Mbed TLS version string"),
    ("opencv", "opencv", b"General configuration for OpenCV ",
     rb"General configuration for OpenCV (\d\.\d+\.\d+)", "OpenCV build information"),
    ("hdfgroup", "hdf5", b"HDF5 library version: ",
     rb"HDF5 library version: (\d\.\d+\.\d+)", "HDF5 version string"),
    ("osgeo", "gdal", b"GDAL ",
     rb"GDAL (\d\.\d+\.\d+), released", "GDAL version string"),
    ("sqlite", "sqlite", b"SQLite version ",
     rb"SQLite version (3\.\d+\.\d+)", "SQLite shell banner"),
    ("libxml2", "libxml2", b"libxml2-",
     rb"libxml2-(2\.\d+\.\d+)", "libxml2 version string"),
    ("freetype", "freetype", b"FreeType ",
     rb"FreeType (2\.\d+\.\d+)", "FreeType version string"),
    ("webmproject", "libwebp", b"libwebp",
     rb"libwebp[- ](\d\.\d+\.\d+)", "libwebp version string"),
]
_COMPILED = [(v, p, anchor, re.compile(r), d)
             for v, p, a, r, d in SIGNATURES for anchor in (a if isinstance(a, tuple) else (a,))]
WINDOW = 160


def scan(abs_path: str, max_hits_per_sig: int = 20000) -> list[tuple[str, str, str, str]]:
    """Return [(vendor, product, version, description)] found in the file."""
    found: dict[tuple[str, str, str], str] = {}
    try:
        with open(abs_path, "rb") as fh:
            if fh.seek(0, 2) == 0:
                return []
            with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                for vendor, product, anchor, rx, desc in _COMPILED:
                    pos, hits = 0, 0
                    while hits < max_hits_per_sig:
                        i = mm.find(anchor, pos)
                        if i < 0:
                            break
                        hits += 1
                        lo = max(0, i - WINDOW)
                        m = rx.search(mm[lo:i + len(anchor) + WINDOW])
                        if m:
                            ver = m.group(1).decode("ascii", "replace")
                            found.setdefault((vendor, product, ver), desc)
                        pos = i + 1
    except (OSError, ValueError):
        return []
    return [(v, p, ver, d) for (v, p, ver), d in found.items()]
