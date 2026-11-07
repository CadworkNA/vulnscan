"""PE identification rules: version resource -> NVD CPE vendor/product/version."""
from __future__ import annotations

import pytest

from vulnscan import pe
from vulnscan.pe import PEInfo


def ident(tmp_path, path, content=b"", **res):
    f = tmp_path / "bin"
    f.write_bytes(content or b"\x00" * 64)
    info = PEInfo(path=path, size=f.stat().st_size, **res)
    return {(c.vendor, c.product, c.version) for c in pe.identify(info, str(f))}


@pytest.mark.parametrize("path, res, content, expected", [
    ("x/libssl-1_1-x64.dll", {"product": "The OpenSSL Toolkit", "product_version": "1.1.1k"}, b"",
     ("openssl", "openssl", "1.1.1k")),
    ("x/libcrypto-3.dll", {}, b"..OpenSSL 3.0.13 30 Jan 2024..", ("openssl", "openssl", "3.0.13")),
    ("python38.dll", {"company": "Python Software Foundation", "product": "Python", "product_version": "3.8.10"},
     b"", ("python", "python", "3.8.10")),
    ("Qt5Core.dll", {"company": "The Qt Company Ltd.", "product": "Qt5", "file_version": "5.15.14.0"}, b"",
     ("qt", "qt", "5.15.14")),
    ("libcef.dll", {"product_version": "120.1.10+g3ce3184+chromium-120.0.6099.129"}, b"",
     ("google", "chrome", "120.0.6099.129")),
    ("Qt6WebEngineCore.dll", {}, b"Mozilla/5.0 Chrome/122.0.6261.171 Safari", ("google", "chrome", "122.0.6261.171")),
    ("sqlite3.dll", {"product_version": "3.45.1"}, b"", ("sqlite", "sqlite", "3.45.1")),
    ("zlib1.dll", {"product_version": "1.2.11"}, b"", ("zlib", "zlib", "1.2.11")),
    ("libcurl.dll", {"product_version": "8.4.0"}, b"", ("haxx", "curl", "8.4.0")),
    ("7z.dll", {"product": "7-Zip", "product_version": "19.00"}, b"", ("7-zip", "7-zip", "19.00")),
    ("unzip.exe", {}, b"..UnZip 6.00 of 20 April 2009..", ("info-zip", "unzip", "6.00")),
    ("TD_Db.dll", {"company": "Open Design Alliance", "file_version": "24.6.0.0"}, b"",
     ("opendesign", "drawings_sdk", "2024.6")),
    ("node.exe", {"product": "Node.js", "product_version": "24.16.0"}, b"", ("nodejs", "node.js", "24.16.0")),
    ("gsdll64.dll", {"product": "GPL Ghostscript", "product_version": "10.02.1"}, b"",
     ("artifex", "ghostscript", "10.02.1")),
    ("libpng16.dll", {"product_version": "1.6.37"}, b"", ("libpng", "libpng", "1.6.37")),
])
def test_identify(tmp_path, path, res, content, expected):
    assert expected in ident(tmp_path, path, content, **res)


@pytest.mark.parametrize("path, res", [
    ("cadwork.dll", {"company": "cadwork informatik", "product": "cadwork 3d", "product_version": "34.0"}),
    ("Qt5Widgets.dll", {"company": "The Qt Company Ltd.", "file_version": "5.15.14.0"}),  # only Core maps Qt
    ("libcef.dll", {}),  # no version evidence -> no component
])
def test_identify_negative(tmp_path, path, res):
    assert ident(tmp_path, path, **res) == set()


def test_numeric_version():
    assert pe._numeric_version("5, 15, 2, 0") == "5.15.2"
    assert pe._numeric_version("1.2.11.0") == "1.2.11"
    assert pe._numeric_version("10.0.19041.1") == "10.0.19041.1"
    assert pe._numeric_version("v1.1.1k") == "1.1.1k"
    assert pe._numeric_version("") == ""


@pytest.mark.parametrize("company, expected", [
    ("cadwork informatik AG", "first-party"), ("Microsoft Corporation", "microsoft"),
    ("Igor Pavlov", "third-party"), ("", "unknown"),
])
def test_party(company, expected):
    assert PEInfo(path="x", size=0, company=company).party == expected


def test_msvc_eol():
    assert pe.msvc_eol("msvcr80.dll")[1] == "2016-04-12"
    assert pe.msvc_eol("MSVCP100.dll")[0].startswith("Visual C++ 2010")
    assert pe.msvc_eol("mfc120u.dll")
    assert pe.msvc_eol("msvcp140.dll") is None  # VC++ 2015-2022 still supported


def test_read_pe_on_non_pe_file(tmp_path):
    f = tmp_path / "fake.dll"
    f.write_bytes(b"MZ" + b"\x00" * 100)
    info = pe.read_pe(str(f), "fake.dll", 102)
    assert info.error and info.components == []


def test_read_pe_on_real_binary():
    """Parse a real PE if the environment has one (the container's 7-Zip is ELF, so use python if on Windows)."""
    import shutil
    import sys
    candidate = sys.executable if sys.platform == "win32" else shutil.which("osv-scanner.exe")
    if not candidate:
        pytest.skip("no Windows PE available in this environment")
    info = pe.read_pe(candidate, "python.exe", 1)
    assert info.machine in ("x64", "x86", "arm64")
