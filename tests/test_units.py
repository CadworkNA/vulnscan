"""Unit tests for the deterministic parts of vulnscan (no network, no scanners)."""
from __future__ import annotations

from datetime import datetime

import pytest

from vulnscan import binsig, enrich, report, scanners
from vulnscan.schedule import Cron
from vulnscan.stage import tidy
from vulnscan.svn import parse_repo_spec


# --- cron ---------------------------------------------------------------------
@pytest.mark.parametrize("expr, now, expected", [
    ("0 2 * * 1", datetime(2026, 11, 6, 21, 0), datetime(2026, 11, 9, 2, 0)),      # Fri -> Mon 02:00
    ("*/15 * * * *", datetime(2026, 1, 1, 10, 7), datetime(2026, 1, 1, 10, 15)),
    ("30 6 1 * *", datetime(2026, 1, 31, 7, 0), datetime(2026, 2, 1, 6, 30)),
    ("0 0 29 2 *", datetime(2026, 3, 1), datetime(2028, 2, 29, 0, 0)),               # leap day
    ("@daily", datetime(2026, 12, 31, 23, 59), datetime(2027, 1, 1, 0, 0)),
    ("0 8 * * mon-fri", datetime(2026, 11, 7, 9, 0), datetime(2026, 11, 9, 8, 0)),  # Sat -> Mon
    ("0 3 * * 7", datetime(2026, 11, 7, 9, 0), datetime(2026, 11, 8, 3, 0)),        # 7 = Sunday
    ("0 0 13 * 5", datetime(2026, 11, 7), datetime(2026, 11, 13, 0, 0)),            # dom OR dow
])
def test_cron_next(expr, now, expected):
    assert Cron(expr).next_after(now) == expected


@pytest.mark.parametrize("bad", ["", "* * * *", "61 * * * *", "* * * 13 *", "*/0 * * * *", "5-1 * * * *"])
def test_cron_invalid(bad):
    with pytest.raises(ValueError):
        Cron(bad)


# --- repo configuration ---------------------------------------------------------
def test_parse_repo_spec_forms():
    assert parse_repo_spec("a=https://x/a, b=https://x/b;c=svn://y/c") == {
        "a": "https://x/a", "b": "https://x/b", "c": "svn://y/c"}
    assert parse_repo_spec('{"a": "https://x/a"}') == {"a": "https://x/a"}
    assert parse_repo_spec("  ") == {}
    with pytest.raises(ValueError):
        parse_repo_spec("just-a-name")


# --- paths ----------------------------------------------------------------------
def test_tidy_msiextract_paths():
    assert tidy("a.msi!/SOURCEDIR/.:Windows/.:System32/.:./x.dll") == "a.msi!/SOURCEDIR/Windows/System32/x.dll"
    assert tidy("plain/path/file.dll") == "plain/path/file.dll"


def test_path_mapper(tmp_path):
    m = scanners.PathMapper(tmp_path)
    assert m(f"{tmp_path}/files/bin/a.dll") == "bin/a.dll"
    assert m("/archives/setup.zip!/x/y.dll") == "setup.zip!/x/y.dll"


# --- merge / priority ---------------------------------------------------------------
def _f(**kw):
    base = scanners.finding(repo="r", path="p.dll", component="openssl", version="1.1.1k")
    base.update(kw)
    return base


def test_merge_unifies_ghsa_alias_and_keeps_highest_severity():
    a = _f(vuln_id="GHSA-xxxx-yyyy-zzzz", aliases={"CVE-2023-0001"}, severity="MEDIUM", sources={"osv-scanner"})
    b = _f(vuln_id="CVE-2023-0001", severity="HIGH", cvss_score=7.5, sources={"grype"}, description="d")
    merged = enrich.merge([a, b])
    assert len(merged) == 1
    m = merged[0]
    assert m["vuln_id"] == "CVE-2023-0001"
    assert m["severity"] == "HIGH" and m["cvss_score"] == 7.5
    assert m["sources"] == {"osv-scanner", "grype"}
    assert "GHSA-xxxx-yyyy-zzzz" in m["aliases"]


def test_merge_keeps_distinct_files_apart():
    merged = enrich.merge([_f(vuln_id="CVE-1", path="a.dll"), _f(vuln_id="CVE-1", path="b.dll")])
    assert len(merged) == 2


@pytest.mark.parametrize("sev, kev, epss, prio", [
    ("LOW", {"cve": "x"}, 0, "P1"), ("CRITICAL", None, 0.2, "P1"), ("CRITICAL", None, 0.0, "P2"),
    ("HIGH", None, 0.06, "P2"), ("HIGH", None, 0.0, "P3"), ("MEDIUM", None, 0.9, "P3"), ("LOW", None, 0, "P4"),
])
def test_priority(sev, kev, epss, prio):
    assert enrich.priority({"severity": sev, "kev": kev, "epss": epss}) == prio


def test_cvss_score_from_vector():
    assert enrich.cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1") == 9.8


# --- end of life ----------------------------------------------------------------------
def test_match_cycle_prefers_longest_prefix():
    rel = [{"name": "3"}, {"name": "3.8"}, {"name": "3.80"}]
    assert enrich._match_cycle(rel, "3.8.10")["name"] == "3.8"
    assert enrich._match_cycle(rel, "4.0") is None


# --- binary signatures ----------------------------------------------------------------
@pytest.mark.parametrize("blob, expected", [
    (b"\x00OpenSSL 1.1.1k  25 Mar 2021\x00", ("openssl", "openssl", "1.1.1k")),
    (b"\x00 deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly and Mark Adler \x00", ("zlib", "zlib", "1.2.11")),
    (b"\x00libpng version 1.6.37\x00", ("libpng", "libpng", "1.6.37")),
    (b"\x003.8.10 (tags/v3.8.10:3d8993a, May  3 2021, 11:48:03) [MSC v.1928 64 bit (AMD64)]\x00",
     ("python", "python", "3.8.10")),
    (b"\x001.0.8, 13-Jul-2019\x00", ("bzip", "bzip2", "1.0.8")),
])
def test_binsig_detects(tmp_path, blob, expected):
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x90" * 4096 + blob + b"\x90" * 4096)
    found = {(v, p, ver) for v, p, ver, _ in binsig.scan(str(f))}
    assert expected in found


def test_binsig_ignores_lookalikes(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"OpenSSL is great; Qt 5 rocks; deflate 9 Copyright someone; libcurl/abc")
    assert binsig.scan(str(f)) == []


def test_binsig_empty_file(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    assert binsig.scan(str(f)) == []


# --- report helpers ----------------------------------------------------------------------
def test_clean_neutralises_formulas_and_control_chars():
    assert report.clean("=HYPERLINK(\"http://evil\")").startswith("'=")
    assert report.clean("@SUM(A1)").startswith("'@")
    assert report.clean("-1.5") == "-1.5"
    assert report.clean("a\x00b\x07c") == "abc"


def test_vuln_url():
    assert report.vuln_url("CVE-2024-1234").endswith("/CVE-2024-1234")
    assert "github.com/advisories" in report.vuln_url("GHSA-aaaa-bbbb-cccc")
    assert report.vuln_url("RETIRE:jquery:x") == ""
