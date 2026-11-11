"""Windows PE (exe/dll/pyd/...) metadata extraction and component identification.

Native third-party DLLs are invisible to package-manifest scanners, so every PE
file's VS_VERSIONINFO resource is read and matched against curated rules that
map well-known libraries to their NVD CPE vendor/product. Unmatched third-party
binaries are surfaced for manual review instead of silently ignored.
"""
from __future__ import annotations

import mmap
import re
from dataclasses import asdict, dataclass, field

import pefile

# Companies whose binaries are first-party (not third-party components).
FIRST_PARTY_RE = re.compile(r"cadwork|lexocad", re.I)
MICROSOFT_RE = re.compile(r"^microsoft", re.I)


@dataclass
class Component:
    vendor: str
    product: str
    version: str
    rule: str
    confidence: str  # high | medium


@dataclass
class PEInfo:
    path: str
    size: int
    machine: str = ""
    is_dotnet: bool = False
    signed: bool = False
    timestamp: str = ""
    company: str = ""
    product: str = ""
    product_version: str = ""
    file_version: str = ""
    description: str = ""
    original_filename: str = ""
    internal_name: str = ""
    copyright: str = ""
    error: str = ""
    components: list[Component] = field(default_factory=list)
    # functions imported from non-system DLLs (import + delay-import tables): dll name (lower case) -> names,
    # used to tell which API of a third-party library our binaries actually call
    imports: dict[str, list[str]] = field(default_factory=dict)

    @property
    def party(self) -> str:
        blob = f"{self.company} {self.copyright} {self.product}"
        if not blob.strip():
            return "unknown"
        if FIRST_PARTY_RE.search(blob):
            return "first-party"
        if MICROSOFT_RE.search(self.company):
            return "microsoft"
        return "third-party"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["party"] = self.party
        return d


# Windows and C runtime DLLs: their imports say nothing about third-party library use
SYSTEM_DLL_RE = re.compile(
    # API sets
    r"^(?:api-ms-win-|ext-ms-)"
    # versioned runtimes: msvcp140.dll, vcruntime140_1.dll, mfc140u.dll, d3d11.dll, d3dcompiler_47.dll ...
    r"|^(?:msvc[rp]|vcruntime|vccorlib|concrt|vcomp|mfc|atl|ucrtbase|d3d|d3dcompiler|dxgi|xinput)[\d_]*[a-z]?d?"
    r"(?:_[a-z_]+)?\.dll$"
    # Windows system DLLs, by exact name
    r"|^(?:kernel32|kernelbase|ntdll|user32|gdi32|gdiplus|advapi32|ole32|oleaut32|shell32|shlwapi|ws2_32|wsock32|"
    r"comctl32|comdlg32|crypt32|bcrypt|ncrypt|secur32|sspicli|version|winmm|imm32|setupapi|rpcrt4|iphlpapi|dbghelp|"
    r"psapi|uxtheme|dwmapi|mscoree|opengl32|glu32|winhttp|wininet|urlmon|userenv|netapi32|normaliz|wldap32|mpr|"
    r"wtsapi32|cfgmgr32|powrprof|propsys|dwrite|d2d1|winspool|winspool\.drv|oleacc|msimg32|usp10|hid|wintrust|"
    r"dnsapi|mswsock|avrt|mfplat|mfreadwrite|windowscodecs|shcore|authz|uiautomationcore|odbc32|msi|msvcrt|"
    r"oledlg|olepro32|rasapi32|pdh|wevtapi|dxva2|evr|mf|ksuser|setupapi|devobj|netutils|srvcli)\.(?:dll|drv)$",
    re.I)
_DLL_NAME_RE = re.compile(r"^[\w.+ -]{1,128}$")
MAX_IMPORT_DLLS = 256
MAX_IMPORT_NAMES = 8192


def _imports(pe) -> dict[str, list[str]]:
    """Imported functions per non-system DLL, bounded (a hostile file can declare any number of imports)."""
    out: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    total = 0
    for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in getattr(pe, attr, None) or []:
            dll = _clean(getattr(entry, "dll", b"")).lower()
            if not _DLL_NAME_RE.match(dll) or SYSTEM_DLL_RE.match(dll):
                continue
            if dll not in out and len(out) >= MAX_IMPORT_DLLS:
                continue
            names, have = out.setdefault(dll, []), seen.setdefault(dll, set())
            for imp in getattr(entry, "imports", None) or []:
                if total >= MAX_IMPORT_NAMES:
                    return out
                name = _clean(imp.name)[:256] if imp.name else (
                    f"#{imp.ordinal}" if isinstance(imp.ordinal, int) else "")
                if name and name not in have:
                    names.append(name)
                    have.add(name)
                    total += 1
    return out


MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C0: "arm", 0x200: "ia64"}


def _clean(v) -> str:
    if isinstance(v, bytes):
        v = v.decode("utf-8", "replace")
    return str(v or "").replace("\x00", "").strip()


def _numeric_version(v: str) -> str:
    """'5, 15, 2, 0' / '5.15.2.0' -> '5.15.2' (drop trailing .0 beyond 3 parts)."""
    m = re.search(r"\d+(?:[.,]\s*\d+)*[a-z]?", v or "")
    if not m:
        return ""
    parts = [p.strip() for p in re.split(r"[.,]", m.group(0))]
    while len(parts) > 3 and parts[-1] == "0":
        parts.pop()
    return ".".join(parts)


def read_pe(abs_path: str, display_path: str, size: int, imports: bool = False) -> PEInfo:
    """Version resource and identification; with imports=True also the import tables (only --ai uses them)."""
    info = PEInfo(path=display_path, size=size)
    try:
        pe = pefile.PE(abs_path, fast_load=True)
    except Exception as exc:  # noqa: BLE001
        info.error = f"not a valid PE: {exc}"[:200]
        return info
    try:
        info.machine = MACHINES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
        info.timestamp = str(pe.FILE_HEADER.TimeDateStamp)
        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        sec = dirs[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        info.signed = sec.VirtualAddress != 0 and sec.Size > 0
        clr = dirs[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
        info.is_dotnet = clr.VirtualAddress != 0
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        strings: dict[str, str] = {}
        for fi in getattr(pe, "FileInfo", None) or []:
            for entry in fi:
                for st in getattr(entry, "StringTable", []) or []:
                    for k, v in st.entries.items():
                        strings.setdefault(_clean(k), _clean(v))
        fixed = getattr(pe, "VS_FIXEDFILEINFO", None)
        if fixed:
            f = fixed[0]
            fixed_ver = f"{f.FileVersionMS >> 16}.{f.FileVersionMS & 0xFFFF}.{f.FileVersionLS >> 16}.{f.FileVersionLS & 0xFFFF}"
        else:
            fixed_ver = ""
        info.company = strings.get("CompanyName", "")
        info.product = strings.get("ProductName", "")
        info.product_version = strings.get("ProductVersion", "")
        info.file_version = strings.get("FileVersion", "") or fixed_ver
        info.description = strings.get("FileDescription", "")
        info.original_filename = strings.get("OriginalFilename", "")
        info.internal_name = strings.get("InternalName", "")
        info.copyright = strings.get("LegalCopyright", "")
    except Exception as exc:  # noqa: BLE001
        info.error = f"partial parse: {exc}"[:200]
    try:
        if imports:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                                                   pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]])
            info.imports = _imports(pe)
    except Exception as exc:  # noqa: BLE001 - imports only feed the upgrade advice; never fail the analysis
        info.error = (info.error + f" imports not read: {exc}").strip()[:300]
    finally:
        pe.close()
    try:
        info.components = identify(info, abs_path)
    except Exception as exc:  # noqa: BLE001
        info.error = (info.error + f" identify failed: {exc}")[:300]
    return info


# ---------------------------------------------------------------------------
# Content probes: regexes run over the raw bytes for libraries whose version is
# not (reliably) in the version resource.
# ---------------------------------------------------------------------------
def _probe(abs_path: str, pattern: bytes) -> str:
    try:
        with open(abs_path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            m = re.search(pattern, mm)
            return m.group(1).decode("ascii", "replace") if m else ""
    except (ValueError, OSError):
        return ""


CHROME_RE = rb"Chrome/(\d{2,3}\.0\.\d{3,5}\.\d{1,4})"
ELECTRON_RE = rb"Electron/(\d{1,3}\.\d{1,3}\.\d{1,3})"
OPENSSL_RE = rb"OpenSSL (\d\.\d+\.\d+[a-z]{0,2})[ -]"
UNZIP_RE = rb"UnZip (\d\.\d+)"
ZIP_RE = rb"Zip (\d\.\d+) \("
FFMPEG_RE = rb"FFmpeg version n?(\d+\.\d+(?:\.\d+)?)"


def identify(pe: PEInfo, abs_path: str) -> list[Component]:
    name = pe.path.rsplit("/", 1)[-1].lower()
    orig = (pe.original_filename or "").lower()
    prod = pe.product or ""
    comp = pe.company or ""
    pv = pe.product_version or pe.file_version
    out: list[Component] = []

    def add(vendor, product, version, rule, confidence="high"):
        if version:
            out.append(Component(vendor, product, version, rule, confidence))

    # OpenSSL
    if re.search(r"openssl", prod, re.I) or re.match(r"(libssl|libcrypto|ssleay32|libeay32)", name):
        v = _probe(abs_path, OPENSSL_RE) or (pv if re.match(r"\d\.\d+\.\d+[a-z]?$", pv or "") else "")
        add("openssl", "openssl", v, "OpenSSL library")
    # Python interpreter
    if re.match(r"python3?\d*(_d)?\.dll$", name) or (
            "python software foundation" in comp.lower() and re.search(r"python", prod, re.I)):
        add("python", "python", _numeric_version(pv), "CPython runtime")
    # Qt (map once per installation via the Core module)
    if re.match(r"qt[456]?core[d]?\.dll$", name) or re.match(r"qt[456]core", orig):
        add("qt", "qt", _numeric_version(pe.file_version or pv), "Qt framework (Core module)")
    # Chromium embedded in CEF / Qt WebEngine / Electron / CefSharp
    if re.match(r"(libcef|qt[56]?webenginecore|qtwebenginecore)", name) or name == "electron.exe" \
            or re.search(r"electron", prod, re.I):
        v = _probe(abs_path, CHROME_RE)
        if not v:
            m = re.search(r"chromium-(\d+\.0\.\d+\.\d+)", pv or "")
            v = m.group(1) if m else ""
        add("google", "chrome", v, "Embedded Chromium engine")
        if name == "electron.exe" or re.search(r"electron", prod, re.I):
            add("electronjs", "electron", _probe(abs_path, ELECTRON_RE) or _numeric_version(pv),
                "Electron runtime")
    # SQLite
    if re.match(r"(sqlite3|sqlite)\.dll$", name) or prod.lower() == "sqlite":
        add("sqlite", "sqlite", _numeric_version(pv), "SQLite library")
    # zlib
    if re.match(r"(zlib1|zlib|zlibwapi)\.dll$", name) or prod.lower() == "zlib":
        add("zlib", "zlib", _numeric_version(pv), "zlib library")
    # curl
    if re.match(r"libcurl", name) or orig.startswith("libcurl") or prod.lower() in ("curl", "libcurl"):
        add("haxx", "curl", _numeric_version(pv), "libcurl library")
    # libxml2
    if re.match(r"libxml2", name):
        add("xmlsoft", "libxml2", _numeric_version(pv), "libxml2 library")
    # 7-Zip
    if re.match(r"7-?zip", prod, re.I) or re.match(r"(7z|7za|7zr|7zxa|7zg|7zfm)\.(dll|exe)$", name):
        add("7-zip", "7-zip", _numeric_version(pv), "7-Zip")
    # Info-ZIP
    if name == "unzip.exe" or name == "unzipsfx.exe":
        add("info-zip", "unzip", _probe(abs_path, UNZIP_RE), "Info-ZIP UnZip")
    if name == "zip.exe":
        add("info-zip", "zip", _probe(abs_path, ZIP_RE), "Info-ZIP Zip")
    # Open Design Alliance (Teigha / ODA Drawings SDK) - NVD uses year.month versions
    if re.search(r"open design alliance", f"{comp} {pe.copyright}", re.I):
        m = re.match(r"(\d+)[.,]\s*(\d+)", pe.file_version or pv or "")
        if m:
            major = int(m.group(1))
            year = major + 2000 if major < 100 else major
            add("opendesign", "drawings_sdk", f"{year}.{int(m.group(2))}",
                "Open Design Alliance SDK (version derived from file version)", "medium")
    # OpenCV + bundled FFmpeg
    if re.match(r"opencv_", name) and "ffmpeg" not in name:
        m = re.search(r"(\d)(\d)(\d{1,2})", name)
        v = _numeric_version(pv) or (f"{m.group(1)}.{m.group(2)}.{m.group(3)}" if m else "")
        add("opencv", "opencv", v, "OpenCV library", "high" if _numeric_version(pv) else "medium")
    if re.match(r"(avcodec|avformat|avutil|opencv_videoio_ffmpeg)", name):
        add("ffmpeg", "ffmpeg", _probe(abs_path, FFMPEG_RE), "FFmpeg library")
    # Node.js
    if name == "node.exe" or prod.lower() == "node.js":
        add("nodejs", "node.js", _numeric_version(pv), "Node.js runtime")
    # Ghostscript
    if re.match(r"gsdll(32|64)\.dll$", name) or re.search(r"ghostscript", prod, re.I):
        add("artifex", "ghostscript", _numeric_version(pv), "Ghostscript")
    # ICU
    if re.match(r"icu(uc|in|dt|io)\d*\.dll$", name):
        add("icu-project", "international_components_for_unicode", _numeric_version(pv), "ICU")
    # libpng / libjpeg-turbo / libtiff / freetype / expat / libwebp (resource-based)
    simple = [
        (r"libpng\d*\.dll$", "libpng", "libpng"),
        (r"(turbojpeg|jpeg62|libjpeg-?\d*)\.dll$", "libjpeg-turbo", "libjpeg-turbo"),
        (r"(libtiff|tiff)\d*\.dll$", "libtiff", "libtiff"),
        (r"freetype\d*\.dll$", "freetype", "freetype"),
        (r"libexpat\w*\.dll$", "libexpat_project", "libexpat"),
        (r"libwebp\w*\.dll$", "webmproject", "libwebp"),
        (r"gdal\d*\.dll$", "osgeo", "gdal"),
        (r"(proj|proj_\d+_\d+)\.dll$", "osgeo", "proj"),
        (r"hdf5\.dll$", "hdfgroup", "hdf5"),
        (r"libarchive\.dll$", "libarchive", "libarchive"),
        (r"lz4\.dll$", "lz4_project", "lz4"),
        (r"(liblzma|lzma)\.dll$", "tukaani", "xz"),
        (r"(libbz2|bz2|bzip2)\.dll$", "bzip", "bzip2"),
        (r"pcre2[-\w]*\.dll$", "pcre", "pcre2"),
        (r"pcre\d*\.dll$", "pcre", "pcre"),
        (r"(libzip|zip)\.dll$", "libzip", "libzip"),
        (r"openvdb\.dll$", "linuxfoundation", "openvdb"),
        (r"(openexr|iex|ilmimf)\w*\.dll$", "openexr", "openexr"),
        (r"assimp\w*\.dll$", "assimp", "assimp"),
        (r"libmysql\.dll$", "oracle", "mysql"),
        (r"libpq\.dll$", "postgresql", "postgresql"),
        (r"libssh2\.dll$", "libssh2", "libssh2"),
        (r"libssh\.dll$", "libssh", "libssh"),
        (r"nghttp2\.dll$", "nghttp2", "nghttp2"),
        (r"libiconv\w*\.dll$", "gnu", "libiconv"),
        (r"(libxslt|xslt)\.dll$", "xmlsoft", "libxslt"),
        (r"harfbuzz\.dll$", "harfbuzz_project", "harfbuzz"),
        (r"msvcr?t?\d*\.dll$", None, None),
    ]
    if not out:
        for pat, vendor, product in simple:
            if vendor and re.match(pat, name):
                add(vendor, product, _numeric_version(pv), f"{product} (filename match)", "medium")
                break
    return out


# ---------------------------------------------------------------------------
# End-of-life Microsoft Visual C++ runtimes (no CPE-based CVE data, but
# shipping unsupported runtimes is a reportable risk).
# ---------------------------------------------------------------------------
MSVC_EOL = {
    "70": ("Visual C++ 2002 (7.0) runtime", "2009-07-14"),
    "71": ("Visual C++ 2003 (7.1) runtime", "2013-10-08"),
    "80": ("Visual C++ 2005 (8.0) runtime", "2016-04-12"),
    "90": ("Visual C++ 2008 (9.0) runtime", "2018-04-10"),
    "100": ("Visual C++ 2010 (10.0) runtime", "2020-07-14"),
    "110": ("Visual C++ 2012 (11.0) runtime", "2023-01-10"),
    "120": ("Visual C++ 2013 (12.0) runtime", "2024-04-09"),
}
MSVC_RE = re.compile(r"^(?:msvc[pr]|mfc|vcomp|atl)(\d{2,3})u?d?\.dll$", re.I)


def msvc_eol(name: str):
    m = MSVC_RE.match(name)
    if m and m.group(1) in MSVC_EOL:
        return MSVC_EOL[m.group(1)]
    return None
