"""Build a scan tree for a repo: hardlinked copy without .svn metadata, plus
recursively extracted archives, then inventory every file (size, sha256, PE info).

Layout under /cache/stage/<repo>/:
    files/<path>                 hardlinks to the checkout (no .svn, no extra disk)
    archives/<path>!/<inner>     contents of archive <path>, nested archives recurse
The display path of any file is its path relative to files/ or archives/, so an
item inside an archive reads e.g.  setup/redist.zip!/bin/libssl-1_1-x64.dll
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from . import binsig
from . import pe as pe_mod
from .util import CACHE, fmt_size, log

STAGE = CACHE / "stage"

ARCHIVE_EXT = {".zip", ".7z", ".msi", ".msm", ".msp", ".cab", ".whl", ".nupkg", ".egg", ".tar",
               ".tgz", ".gz", ".bz2", ".xz", ".tbz2", ".txz", ".rar", ".vsix", ".xpi", ".appx",
               ".msix", ".apk", ".zst"}
# zip-based document formats: contents are not shipped code, skip by default
DOC_ZIP_EXT = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub", ".xlsm", ".dotx",
               ".kmz", ".3mf", ".ipynb", ".jar", ".war", ".ear", ".aar"}  # jars: scanners read them natively
MAGIC = {b"PK\x03\x04": "zip", b"7z\xbc\xaf\x27\x1c": "7z", b"MSCF": "cab", b"Rar!": "rar"}
# What the content of each archive extension must look like. A file whose content
# does not match its extension (e.g. zlib-compressed data named *.gz) is not an
# archive and is scanned as a plain file instead of being reported as a failure.
_ZIP = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
EXPECTED_MAGIC = {
    "zip": _ZIP, "whl": _ZIP, "nupkg": _ZIP, "egg": _ZIP, "vsix": _ZIP, "xpi": _ZIP, "appx": _ZIP,
    "msix": _ZIP, "apk": _ZIP, "7z": (b"7z\xbc\xaf\x27\x1c",), "cab": (b"MSCF",), "rar": (b"Rar!",),
    "msi": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",), "gz": (b"\x1f\x8b",), "tgz": (b"\x1f\x8b",),
    "bz2": (b"BZh",), "tbz2": (b"BZh",), "xz": (b"\xfd7zXZ\x00",), "txz": (b"\xfd7zXZ\x00",),
    "zst": (b"\x28\xb5\x2f\xfd",),
}
PE_EXT = {".dll", ".exe", ".pyd", ".sys", ".ocx", ".ax", ".cpl", ".drv", ".scr", ".efi", ".mui",
          ".node", ".tlb", ".winmd"}
MAX_DEPTH = 4


@dataclass
class FileRec:
    path: str          # display path
    abs: str
    size: int
    sha256: str = ""
    kind: str = ""     # pe | archive | elf | other
    in_archive: bool = False


@dataclass
class StageResult:
    root: Path
    files: list[FileRec] = field(default_factory=list)
    pe: list[pe_mod.PEInfo] = field(default_factory=list)
    archives_ok: list[str] = field(default_factory=list)
    archives_failed: list[tuple[str, str]] = field(default_factory=list)   # nothing extracted: a coverage gap
    archives_partial: list[tuple[str, str]] = field(default_factory=list)  # extracted with errors (warning)
    not_archives: list[str] = field(default_factory=list)  # archive extension, other content
    symlinks: list[str] = field(default_factory=list)  # links in the checkout (recorded, not followed)


_MSI_DIR = re.compile(r"(?<=/)\.:(?=[^/])|(?<=/)\.:/")


def tidy(path: str) -> str:
    """Normalise display paths (msiextract emits '.:Windows/.:System32/.:./x.dll')."""
    path = _MSI_DIR.sub("", path)
    while "/./" in path:
        path = path.replace("/./", "/")
    return path


def extraction_dir(stage_root: Path, abs_path: str) -> Path | None:
    """Where an archive is extracted: built from its real on-disk relative path - never
    from the tidied display path, which could turn crafted names such as '.:..' into
    '..' - and verified to stay inside the stage (fail closed otherwise)."""
    arch_dir = (stage_root / "archives").resolve()
    rel = Path(os.path.relpath(abs_path, stage_root))
    parts = rel.parts
    if not parts or parts[0] not in ("files", "archives") or any(p in ("..", ".") for p in parts):
        return None
    out = arch_dir.joinpath(*parts[1:-1], parts[-1] + "!")
    try:
        resolved = out.resolve()
    except (OSError, RuntimeError):
        return None
    return out if resolved.is_relative_to(arch_dir) else None


def display_path(stage_root: Path, abs_path: str) -> str:
    rel = os.path.relpath(abs_path, stage_root).replace(os.sep, "/")
    for prefix in ("files/", "archives/"):
        if rel.startswith(prefix):
            return tidy(rel[len(prefix):])
    return tidy(rel)


def _magic(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(264)  # tar's "ustar" marker sits at offset 257
    except OSError:
        return b""


def _claimed_type(path: str) -> str | None:
    """Archive type an extension claims, regardless of content."""
    ext = os.path.splitext(path.lower())[1]
    if ext in DOC_ZIP_EXT:
        return None
    if ext in (".msi", ".msm", ".msp"):
        return "msi"
    return ext.lstrip(".") if ext in ARCHIVE_EXT else None


def _archive_type(path: str, head: bytes) -> str | None:
    """Archive type, confirmed by content: the extension must match the file's signature,
    and files with an unknown extension are recognised by signature alone."""
    claimed = _claimed_type(path)
    if claimed == "tar":
        return "tar" if head[257:262] == b"ustar" else None
    if claimed:
        return claimed if any(head.startswith(m) for m in EXPECTED_MAGIC.get(claimed, ())) else None
    if os.path.splitext(path.lower())[1] in DOC_ZIP_EXT:
        return None
    for sig, kind in MAGIC.items():
        if head.startswith(sig):
            return kind
    return None


def _link_tree(src: Path, dst: Path, links: list[str]) -> int:
    """Hardlink (or copy) every regular file of src into dst, skipping .svn.
    Symbolic links are recorded in `links` and never followed: a link can point
    outside the checkout, and its target - if shipped - is scanned where it lives."""
    n = 0
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if d != ".svn"]
        rel = os.path.relpath(dirpath, src)
        target_dir = dst / rel if rel != "." else dst
        target_dir.mkdir(parents=True, exist_ok=True)
        for d in list(dirnames):
            if os.path.islink(os.path.join(dirpath, d)):
                links.append(os.path.normpath(os.path.join(rel, d)).replace(os.sep, "/"))
                dirnames.remove(d)
        for f in filenames:
            s = os.path.join(dirpath, f)
            if os.path.islink(s):
                links.append(os.path.normpath(os.path.join(rel, f)).replace(os.sep, "/"))
                continue
            t = target_dir / f
            try:
                os.link(s, t, follow_symlinks=False)
            except OSError:
                shutil.copy2(s, t, follow_symlinks=False)
            n += 1
    return n


def _sanitize_names(root: Path) -> int:
    """Rename extracted files/dirs whose names are not valid UTF-8 (archives may carry
    Latin-1 or other legacy-encoded names). Undecodable bytes become %XX, so every tool
    downstream (Node.js, syft, JSON output) can open and report the file."""
    renamed = 0
    for dirpath, dirnames, filenames in os.walk(os.fsencode(root), topdown=False):
        for name in dirnames + filenames:
            try:
                name.decode("utf-8")
                continue
            except UnicodeDecodeError:
                pass
            safe = "".join(chr(b) if 0x20 <= b < 0x7F and b != 0x25 else f"%{b:02X}" for b in name)
            src, dst = os.path.join(dirpath, name), os.path.join(dirpath, os.fsencode(safe))
            if not os.path.exists(dst):
                os.rename(src, dst)
                renamed += 1
    return renamed


def _extract(kind: str, src: str, out: Path) -> tuple[str, str]:
    """Returns (status, detail): status is ok | partial | failed."""
    status, detail = _extract_raw(kind, src, out)
    if status != "failed" and _sanitize_names(out):
        detail += " (non-UTF-8 file names percent-encoded)"
    return status, detail


def _extract_raw(kind: str, src: str, out: Path) -> tuple[str, str]:
    out.mkdir(parents=True, exist_ok=True)
    if kind == "msi":
        r = subprocess.run(["msiextract", "-C", str(out), src], capture_output=True, text=True)
        if r.returncode == 0 and any(out.rglob("*")):
            return "ok", "msiextract"
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True, exist_ok=True)
    # -p- : never prompt for passwords (fail instead). 7-Zip refuses absolute and ../ paths and
    # links pointing outside the output folder (zip-slip), reporting them as errors.
    r = subprocess.run(["7z", "x", "-y", "-p-", "-bd", "-bso0", "-bsp0", f"-o{out}", src],
                       capture_output=True, text=True)
    err = (r.stderr or r.stdout).strip().splitlines()
    detail = (err[-1] if err else f"7z exit {r.returncode}")[:300]
    if r.returncode in (0, 1):  # 1 = warnings
        return "ok", "7z" + (" (with warnings)" if r.returncode else "")
    if any(p.is_file() for p in out.rglob("*")):
        return "partial", detail  # e.g. one corrupt member: the rest was extracted and is scanned
    return "failed", detail


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(4 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _analyze_job(args):
    """Analyse one binary: PE version resource (if PE) + embedded version signatures."""
    abs_path, disp, size, kind = args
    if kind == "pe":
        info = pe_mod.read_pe(abs_path, disp, size)
    else:
        info = pe_mod.PEInfo(path=disp, size=size, machine=kind)
    have = {(c.vendor, c.product, c.version) for c in info.components}
    for vendor, product, version, desc in binsig.scan(abs_path):
        if (vendor, product, version) not in have:
            # the same library at a different version than the resource says is
            # still reported: statically linked copies are independent components
            info.components.append(pe_mod.Component(vendor, product, version,
                                                    f"embedded signature: {desc}", "high"))
            have.add((vendor, product, version))
    return info


def build(repo_name: str, checkout: Path, *, extract: bool = True, hash_files: bool = True,
          jobs: int = os.cpu_count() or 4) -> StageResult:
    tag = {"stage": f"stage:{repo_name}"}
    root = STAGE / repo_name
    if root.exists():
        shutil.rmtree(root)
    files_dir, arch_dir = root / "files", root / "archives"
    t0 = time.monotonic()
    res = StageResult(root=root)
    n = _link_tree(checkout, files_dir, res.symlinks)
    log.info("staged %d files from checkout (hardlinked, .svn excluded) in %.1fs", n,
             time.monotonic() - t0, extra=tag)
    for link in res.symlinks:
        log.warning("symbolic link not followed: %s", link, extra=tag)

    # --- recursive archive extraction --------------------------------------
    if extract:
        pending = [(str(p), 1) for p in files_dir.rglob("*") if p.is_file()]
        seen_archives = 0
        while pending:
            next_round = []
            for abs_path, depth in pending:
                if os.path.getsize(abs_path) == 0:
                    continue  # empty placeholder: nothing to extract or scan
                head = _magic(abs_path)
                kind = _archive_type(abs_path, head)
                if not kind:
                    if _claimed_type(abs_path):
                        res.not_archives.append(display_path(root, abs_path))
                    continue
                disp = display_path(root, abs_path)
                if depth > MAX_DEPTH:
                    res.archives_failed.append((disp, f"nesting deeper than {MAX_DEPTH} levels - not extracted"))
                    log.warning("archive nesting too deep, skipping %s", disp, extra=tag)
                    continue
                out = extraction_dir(root, abs_path)
                if out is None:
                    res.archives_failed.append((disp, "unsafe extraction path - not extracted"))
                    log.warning("refusing to extract %s: output would leave the stage", disp, extra=tag)
                    continue
                seen_archives += 1
                size = os.path.getsize(abs_path)
                status, how = _extract(kind, abs_path, out)
                if status == "failed":
                    res.archives_failed.append((disp, how))
                    log.warning("could not extract %s: %s", disp, how, extra=tag)
                    continue
                inner = [str(p) for p in out.rglob("*") if p.is_file() and not p.is_symlink()]
                res.archives_ok.append(disp)
                if status == "partial":
                    res.archives_partial.append((disp, how))
                    log.warning("partially extracted %s (%d files; %s)", disp, len(inner), how, extra=tag)
                else:
                    log.info("extracted %s archive %s (%s) -> %d files [%s]", kind, disp,
                             fmt_size(size), len(inner), how, extra=tag)
                next_round += [(p, depth + 1) for p in inner]
            pending = next_round
        log.info("archives: %d extracted (%d partially), %d could not be extracted, "
                 "%d files with an archive extension were not archives", len(res.archives_ok),
                 len(res.archives_partial), len(res.archives_failed), len(res.not_archives), extra=tag)

    # --- inventory ------------------------------------------------------------
    all_files = []
    for base in (files_dir, arch_dir):
        if base.exists():
            for dirpath, _, filenames in os.walk(base):
                for f in filenames:
                    p = os.path.join(dirpath, f)
                    if os.path.islink(p) or not os.path.isfile(p):
                        continue
                    all_files.append(FileRec(path=display_path(root, p), abs=p,
                                             size=os.path.getsize(p), in_archive=base == arch_dir))
    total = sum(f.size for f in all_files)
    log.info("inventory: %d files, %s total (%d inside archives)", len(all_files),
             fmt_size(total), sum(f.in_archive for f in all_files), extra=tag)

    bin_jobs = []
    for f in all_files:
        head = _magic(f.abs)
        if head[:2] == b"MZ":
            f.kind = "pe"
        elif head[:4] == b"\x7fELF":
            f.kind = "elf"
        elif head.startswith(b"!<arch>"):
            f.kind = "static-lib"
        elif head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe") \
                and not f.path.lower().endswith(".class"):  # Java classes share 0xCAFEBABE
            f.kind = "mach-o"
        elif _archive_type(f.abs, head):
            f.kind = "archive"
        else:
            f.kind = "other"
        if f.kind in ("pe", "elf", "static-lib", "mach-o"):
            bin_jobs.append((f.abs, f.path, f.size, f.kind))
        if f.kind == "pe" and os.path.splitext(f.path)[1].lower() not in PE_EXT:
            log.debug("PE binary with non-standard extension: %s", f.path, extra=tag)

    if hash_files:
        t0 = time.monotonic()
        done_bytes = 0
        last = time.monotonic()
        with ThreadPoolExecutor(max_workers=min(8, jobs)) as ex:
            futs = {ex.submit(_sha256, f.abs): f for f in all_files}
            for i, fut in enumerate(as_completed(futs), 1):
                rec = futs[fut]
                try:
                    rec.sha256 = fut.result()
                except OSError as exc:
                    rec.sha256 = f"error: {exc}"
                done_bytes += rec.size
                if time.monotonic() - last > 5:
                    last = time.monotonic()
                    log.info("hashing: %d/%d files, %s / %s (%.0f MB/s)", i, len(all_files),
                             fmt_size(done_bytes), fmt_size(total),
                             done_bytes / 1048576 / max(time.monotonic() - t0, 1e-6), extra=tag)
        log.info("sha256 computed for %d files in %.1fs", len(all_files), time.monotonic() - t0, extra=tag)

    t0 = time.monotonic()
    log.info("analysing %d binaries: version resources + %d embedded-library signatures (%d workers)",
             len(bin_jobs), len(binsig.SIGNATURES), jobs, extra=tag)
    last = time.monotonic()
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        for i, info in enumerate(ex.map(_analyze_job, bin_jobs, chunksize=4), 1):
            res.pe.append(info)
            for c in info.components:
                log.debug("identified %s %s %s in %s (%s)", c.vendor, c.product, c.version,
                          info.path, c.rule, extra=tag)
            if time.monotonic() - last > 5:
                last = time.monotonic()
                log.info("binary analysis: %d/%d", i, len(bin_jobs), extra=tag)
    ident = sum(1 for p in res.pe if p.components)
    third = sum(1 for p in res.pe if p.party == "third-party")
    libs = {(c.vendor, c.product, c.version) for p in res.pe for c in p.components}
    log.info("binary analysis done in %.1fs: %d binaries (%d third-party), %d contain %d distinct known libraries",
             time.monotonic() - t0, len(res.pe), third, ident, len(libs), extra=tag)
    res.files = all_files
    return res
