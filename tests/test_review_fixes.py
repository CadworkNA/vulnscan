"""Regression tests for issues found in code review."""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from vulnscan import binsig, cli, notify, pe, stage, svn


def _repos(*names):
    return {n: svn.Repo(n, f"https://svn.example.com/{n}") for n in names}


def test_schedule_env_never_turns_a_manual_run_into_a_scheduler(monkeypatch):
    monkeypatch.setenv("VULNSCAN_SCHEDULE", "0 2 * * 1")
    _, args = cli.parse(["--app"], _repos("app"))
    assert args.schedule == ""
    _, args = cli.parse(["--app", "--scheduled"], _repos("app"))
    assert args.schedule == "0 2 * * 1"


def test_scheduled_requires_a_schedule():
    with pytest.raises(SystemExit):
        cli.parse(["--app", "--scheduled"], _repos("app"))


@pytest.mark.parametrize("engines", ["", ",", " , "])
def test_empty_engine_list_is_rejected(engines):
    with pytest.raises(SystemExit):
        cli.parse(["--app", "--engines", engines], _repos("app"))


def test_repo_flags_are_not_hijacked_by_option_prefixes():
    _, args = cli.parse(["--off"], _repos("off", "sb"))
    assert args.selected == ["off"] and not args.offline
    _, args = cli.parse(["--sb"], _repos("off", "sb"))
    assert args.selected == ["sb"] and not args.sbom


def test_repo_names_clashing_with_options_are_rejected():
    with pytest.raises(SystemExit):
        cli.parse(["--all"], _repos("sbom"))


def test_smtp_ssl_defaults_to_port_465(monkeypatch):
    for k, v in {"SMTP_HOST": "h", "SMTP_FROM": "f@example.com", "SMTP_TO": "t@example.com",
                 "SMTP_SECURITY": "ssl"}.items():
        monkeypatch.setenv(k, v)
    assert notify.config()["port"] == 465
    monkeypatch.setenv("SMTP_SECURITY", "starttls")
    assert notify.config()["port"] == 587


def test_signature_found_after_many_anchor_hits(tmp_path):
    f = tmp_path / "qt.dll"
    f.write_bytes(b"Qt is great. " * 500 + b"\x00Qt 5.15.2 (x86_64-little_endian-llp64 shared (dynamic) release build)")
    assert ("qt", "qt", "5.15.2") in {(v, p, ver) for v, p, ver, _ in binsig.scan(str(f))}


@pytest.mark.parametrize("name, expected", [
    ("libssh.dll", ("libssh", "libssh", "0.10.6")),
    ("libssh2.dll", ("libssh2", "libssh2", "0.10.6")),
    ("pcre2-8.dll", ("pcre", "pcre2", "0.10.6")),
    ("pcre.dll", ("pcre", "pcre", "0.10.6")),
])
def test_libssh_and_pcre2_are_distinct_products(tmp_path, name, expected):
    f = tmp_path / "x"
    f.write_bytes(b"\x00" * 16)
    info = pe.PEInfo(path=f"bin/{name}", size=16, product_version="0.10.6")
    assert {(c.vendor, c.product, c.version) for c in pe.identify(info, str(f))} == {expected}


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="needs POSIX symlinks")
def test_symlinks_are_recorded_not_followed(tmp_path, monkeypatch):
    monkeypatch.setattr(stage, "STAGE", tmp_path / "stage")
    src = tmp_path / "src"
    (src / "real").mkdir(parents=True)
    (src / "real" / "a.dll").write_bytes(b"MZ")
    os.symlink("/does/not/exist", src / "dangling.dll")
    os.symlink("/etc", src / "etc-link")
    os.symlink(src / "real", src / "dir-link")
    res = stage.build("demo", src, jobs=1, extract=False, hash_files=False)
    assert {f.path for f in res.files} == {"real/a.dll"}
    assert set(res.symlinks) == {"dangling.dll", "etc-link", "dir-link"}


# --- svn cache recovery ----------------------------------------------------------------
needs_svn = pytest.mark.skipif(shutil.which("svnadmin") is None, reason="subversion not installed")


@pytest.fixture
def local_repo(tmp_path):
    repo = tmp_path / "repo"
    subprocess.run(["svnadmin", "create", str(repo)], check=True)
    seed = tmp_path / "seed"
    subprocess.run(["svn", "checkout", "-q", f"file://{repo}", str(seed)], check=True)
    (seed / "a.dll").write_bytes(b"MZ")
    subprocess.run(["svn", "add", "-q", str(seed / "a.dll")], check=True)
    subprocess.run(["svn", "commit", "-q", "-m", "r1", str(seed)], check=True)
    return f"file://{repo}"


@needs_svn
def test_broken_cached_checkout_is_recovered(tmp_path, local_repo):
    r = svn.Repo("demo", local_repo, checkout=tmp_path / "cache" / "demo")
    svn.sync(r)
    (r.checkout / ".svn" / "wc.db").write_bytes(b"corrupted")  # e.g. killed mid-operation
    svn.sync(r)
    assert r.revision == "1" and (r.checkout / "a.dll").exists()


@needs_svn
def test_offline_without_cache_does_not_check_out(tmp_path, local_repo):
    r = svn.Repo("demo", local_repo, checkout=tmp_path / "cache" / "demo")
    with pytest.raises(RuntimeError, match="no usable cached checkout"):
        svn.sync(r, update=False)
    assert not (r.checkout / ".svn").exists()


def test_crafted_member_names_cannot_escape_the_stage(tmp_path, monkeypatch):
    """Security review: tidy() turns '.:..' into '..'; extraction paths must not come from display paths."""
    monkeypatch.setattr(stage, "STAGE", tmp_path / "stage")
    root = tmp_path / "stage" / "demo"
    evil = root / "archives" / "evil.zip!" / ".:.." / ".:.." / ".:.." / ".:.." / "x.zip"
    evil.parent.mkdir(parents=True)
    evil.write_bytes(b"PK")
    assert stage.display_path(root, str(evil)).startswith("evil.zip!/../")  # the display path is misleading...
    out = stage.extraction_dir(root, str(evil))
    assert out is not None and out.resolve().is_relative_to((root / "archives").resolve())  # ...the real one is not
    assert out.name == "x.zip!" and ".:.." in out.parts
    assert stage.extraction_dir(root, str(tmp_path / "elsewhere.zip")) is None


def test_hyperlinks_only_for_plain_ids():
    from vulnscan import report
    assert report.vuln_url('CVE-2024-1","x")&HYPERLINK("http://evil') == ""
    assert report.vuln_url("CVE-2024-1234") == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root (runs in the container)")
def test_privileges_are_dropped_before_scanning(tmp_path):
    import sys
    work, cache = tmp_path / "work", tmp_path / "cache"
    work.mkdir()
    (cache / "svn").mkdir(parents=True)
    (cache / "svn" / "old-root-file").write_text("x")
    os.chown(work, 1234, 1234)  # host user owning the mounted folder
    env = {k: v for k, v in os.environ.items() if k != "VULNSCAN_RUN_AS_ROOT"}
    env.update(VULNSCAN_CACHE=str(cache), PYTHONPATH=os.pathsep.join(sys.path))
    code = ("import os; from pathlib import Path; from vulnscan.util import drop_privileges; "
            f"print(drop_privileges(Path({str(work)!r}))); print(os.getuid(), os.getgid())")
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout
    assert out.splitlines()[-1] == "1234 1234"
    assert (cache / "svn" / "old-root-file").stat().st_uid == 1234
