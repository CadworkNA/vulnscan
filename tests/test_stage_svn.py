"""Staging (hardlinks, archive extraction, inventory) and SVN handling against a
local file:// repository - no network involved."""
from __future__ import annotations

import io
import json
import shutil
import subprocess
import zipfile

import pytest

from vulnscan import stage, svn


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
def stage_root(tmp_path, monkeypatch):
    monkeypatch.setattr(stage, "STAGE", tmp_path / "stage")
    return tmp_path / "stage"


needs_7z = pytest.mark.skipif(shutil.which("7z") is None, reason="7z not installed")


@needs_7z
def test_build_extracts_nested_archives_and_inventories(tmp_path, stage_root):
    src = tmp_path / "src"
    (src / ".svn").mkdir(parents=True)
    (src / ".svn" / "wc.db").write_bytes(b"svn metadata must not be scanned")
    (src / "bin").mkdir()
    (src / "bin" / "app.dll").write_bytes(b"MZ" + b"\x00" * 200 + b" deflate 1.2.11 Copyright 1995-2017 ")
    inner = _zip({"lib/libz.dll": b"MZ" + b"\x00" * 50 + b"libpng version 1.6.37\x00"})
    (src / "pkg.zip").write_bytes(_zip({"inner.zip": inner, "readme.txt": b"hi"}))
    (src / "doc.docx").write_bytes(_zip({"word/document.xml": b"<x/>"}))  # office docs are not unpacked

    res = stage.build("demo", src, jobs=2)
    paths = {f.path for f in res.files}
    assert "bin/app.dll" in paths
    assert "pkg.zip!/inner.zip!/lib/libz.dll" in paths
    assert not any(".svn" in p for p in paths)
    assert not any(p.startswith("doc.docx!") for p in paths)
    assert set(res.archives_ok) == {"pkg.zip", "pkg.zip!/inner.zip"}
    assert all(len(f.sha256) == 64 for f in res.files)
    libs = {(c.product, c.version, b.path) for b in res.pe for c in b.components}
    assert ("zlib", "1.2.11", "bin/app.dll") in libs
    assert ("libpng", "1.6.37", "pkg.zip!/inner.zip!/lib/libz.dll") in libs


@needs_7z
def test_build_reports_broken_archives(tmp_path, stage_root):
    src = tmp_path / "src"
    src.mkdir()
    (src / "broken.zip").write_bytes(b"PK\x03\x04 this is not really a zip")
    res = stage.build("demo", src, jobs=1, hash_files=False)
    assert [a for a, _ in res.archives_failed] == ["broken.zip"]


@needs_7z
def test_extraction_folder_collision_is_a_coverage_gap(tmp_path, stage_root):
    """A crafted archive holding both 'x.zip' and a folder 'x.zip!' must not get merged contents."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "outer.zip").write_bytes(_zip({"x.zip": _zip({"a.dll": b"MZ a"}), "x.zip!/b.dll": b"MZ b"}))
    res = stage.build("demo", src, jobs=2, hash_files=False)
    assert [a for a, _ in res.archives_failed] == ["outer.zip!/x.zip"]
    assert "collides" in res.archives_failed[0][1]


@needs_7z
def test_parallel_extraction_is_deterministic(tmp_path, stage_root):
    src = tmp_path / "src"
    src.mkdir()
    for i in range(12):
        (src / f"p{i:02}.zip").write_bytes(_zip({f"lib{i}.dll": b"MZ" + bytes([i]) * 64}))
    res = stage.build("demo", src, jobs=4, hash_files=False)
    assert res.archives_ok == [f"p{i:02}.zip" for i in range(12)]


def test_display_path(tmp_path):
    root = tmp_path
    assert stage.display_path(root, str(root / "files" / "a" / "b.dll")) == "a/b.dll"
    assert stage.display_path(root, str(root / "archives" / "x.zip!" / "y.dll")) == "x.zip!/y.dll"


# --- svn ------------------------------------------------------------------------------
needs_svn = pytest.mark.skipif(shutil.which("svnadmin") is None, reason="subversion not installed")


@pytest.fixture
def local_repo(tmp_path):
    repo = tmp_path / "repo"
    subprocess.run(["svnadmin", "create", str(repo)], check=True)
    url = f"file://{repo}"
    wc = tmp_path / "seed"
    subprocess.run(["svn", "checkout", "-q", url, str(wc)], check=True)
    (wc / "a.dll").write_bytes(b"MZ v1")
    subprocess.run(["svn", "add", "-q", str(wc / "a.dll")], check=True)
    subprocess.run(["svn", "commit", "-q", "-m", "r1", str(wc)], check=True)
    return url, wc


@needs_svn
def test_sync_checkout_then_update(tmp_path, local_repo, monkeypatch):
    url, seed = local_repo
    r = svn.Repo(name="demo", url=url, checkout=tmp_path / "cache" / "demo")
    svn.sync(r)
    assert r.revision == "1" and (r.checkout / "a.dll").read_bytes() == b"MZ v1"
    # a new commit upstream + a local modification in the cache: update must win and stay pristine
    (seed / "a.dll").write_bytes(b"MZ v2")
    subprocess.run(["svn", "commit", "-q", "-m", "r2", str(seed)], check=True)
    (r.checkout / "a.dll").write_bytes(b"tampered")
    (r.checkout / "stray.txt").write_text("unversioned")
    svn.sync(r)
    assert r.revision == "2"
    assert (r.checkout / "a.dll").read_bytes() == b"MZ v2"
    assert not (r.checkout / "stray.txt").exists()


@needs_svn
def test_remote_listing_gives_file_sizes(tmp_path, local_repo):
    url, _ = local_repo
    r = svn.Repo(name="demo", url=url, checkout=tmp_path / "cache" / "demo")
    assert svn._remote_listing(r, *svn._auth_args()) == {"a.dll": 5}


@needs_svn
def test_wc_discovery_reads_url_without_touching_wc(tmp_path, local_repo, monkeypatch):
    url, seed = local_repo
    work = tmp_path / "work"
    work.mkdir()
    shutil.copytree(seed, work / "mything")
    before = (work / "mything" / ".svn" / "wc.db").read_bytes()
    monkeypatch.setattr(svn, "_wc_url", svn._wc_url)  # real implementation
    repos, notes = svn.load_repos(work)
    # file:// URLs are not accepted as scan targets, so it is reported but ignored
    assert "mything" not in repos and any("unsupported URL" in n for n in notes)
    assert svn._wc_url(work / "mything") == url
    assert (work / "mything" / ".svn" / "wc.db").read_bytes() == before


def test_load_repos_from_env_and_file(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNSCAN_REPOS", "alpha=https://svn.example.com/a, beta=https://svn.example.com/b")
    (tmp_path / "vulnscan-repos.json").write_text('{"beta": "https://svn.example.com/override", '
                                                  '"bad name!": "https://x", "evil": "file:///etc"}')
    repos, notes = svn.load_repos(tmp_path)
    assert repos["alpha"].url == "https://svn.example.com/a"
    assert repos["beta"].url == "https://svn.example.com/override"
    assert "evil" not in repos and "bad name!" not in repos
    assert len([n for n in notes if n.startswith("ignored")]) == 2


def test_secret_file_convention(tmp_path, monkeypatch):
    from vulnscan.util import get_secret
    (tmp_path / "pw").write_text("s3cret\n")
    monkeypatch.setenv("SVN_PASSWORD_FILE", str(tmp_path / "pw"))
    assert get_secret("SVN_PASSWORD") == "s3cret"
    monkeypatch.setenv("SVN_PASSWORD", "direct")
    assert get_secret("SVN_PASSWORD") == "direct"


def test_auth_args_keep_password_off_the_command_line(monkeypatch):
    monkeypatch.setenv("SVN_USERNAME", "bot")
    monkeypatch.setenv("SVN_PASSWORD", "hunter2")
    args, stdin = svn._auth_args()
    assert "hunter2" not in " ".join(args)
    assert stdin == "hunter2" and "--password-from-stdin" in args and "--no-auth-cache" in args


@needs_7z
def test_archive_extension_must_match_content(tmp_path, stage_root):
    """Data files named like archives (zlib data as *.gz) and empty placeholders are not coverage gaps."""
    import zlib
    src = tmp_path / "src"
    src.mkdir()
    (src / "pickle.gz").write_bytes(zlib.compress(b"not a gzip stream"))
    (src / "placeholder.whl").write_bytes(b"")
    (src / "fake.tar").write_bytes(b"x" * 600)
    (src / "real.whl").write_bytes(_zip({"pkg/__init__.py": b""}))
    res = stage.build("demo", src, jobs=1, hash_files=False)
    assert res.archives_failed == []
    assert set(res.not_archives) == {"pickle.gz", "fake.tar"}
    assert res.archives_ok == ["real.whl"]


def test_accepted_gaps(tmp_path, monkeypatch):
    from vulnscan import cli
    (tmp_path / "vulnscan-accepted-gaps.json").write_text(json.dumps([
        {"repo": "tools_2026", "path": "bin/*/templates", "reason": "password-protected archive"},
        {"repo": "*", "path": "old.zip", "reason": "x", "expires": "2000-01-01"},
        {"path": "no-reason.zip"},
    ]))
    gaps, notes = cli.load_accepted_gaps(tmp_path)
    assert len(gaps) == 1
    assert any("expired" in n for n in notes) and any("without path and reason" in n for n in notes)
    assert cli.accepted_gap("tools_2026", "bin/demo/templates", gaps)
    assert cli.accepted_gap("tools_2027", "bin/demo/templates", gaps) is None
    assert cli.accepted_gap("tools_2026", "old.zip", gaps) is None


def test_eol_not_tracked_is_not_a_problem(monkeypatch):
    from vulnscan import enrich
    from vulnscan.util import NotFound

    def not_found(url, *a, **k):
        raise NotFound(url)
    monkeypatch.setattr(enrich, "cached_download", not_found)
    rows, problems = enrich.eol_status([{"repo": "r", "name": "python", "version": "3.8.10", "path": "p",
                                         "type": "binary"}], offline=False)
    assert rows == [] and problems == []


def test_non_utf8_names_are_made_readable(tmp_path):
    """Archives can carry Latin-1 file names; Node-based tools cannot open them."""
    import os
    d = tmp_path / "x"
    d.mkdir()
    bad = os.path.join(os.fsencode(d), b"umlauts-\xe4\xf6\xfc")
    with open(bad, "wb") as fh:
        fh.write(b"data")
    assert stage._sanitize_names(d) == 1
    assert [p.name for p in d.iterdir()] == ["umlauts-%E4%F6%FC"]
    assert stage._sanitize_names(d) == 0  # idempotent
