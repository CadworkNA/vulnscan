"""Upgrade paths: lowest version fixing every vulnerability of a component, step size, support of the target."""
from __future__ import annotations

import json

import openpyxl
import pytest

from vulnscan import cli, enrich, notify, report, scanners, upgrade
from vulnscan.util import DB_CACHE


def _f(vuln_id, fixed, component="openssl", version="1.1.1k", **kw):
    f = scanners.finding(repo=kw.pop("repo", "r1"), path=kw.pop("path", "bin/libcrypto-1_1-x64.dll"),
                         component=component, version=version, vuln_id=vuln_id, fixed=fixed,
                         severity=kw.pop("severity", "HIGH"), sources={"grype"}, **kw)
    f["priority"] = enrich.priority(f)
    return f


@pytest.mark.parametrize(("a", "b"), [
    ("1.0", "1.0.0"), ("v1.2.3", "1.2.3"), ("1.2.3+build.5", "1.2.3"),
])
def test_vkey_equal(a, b):
    assert upgrade.vkey(a) == upgrade.vkey(b)


@pytest.mark.parametrize(("lo", "hi"), [
    ("1.9", "1.10"), ("1.1.1k", "1.1.1w"), ("1.1.1", "1.1.1a"), ("1.0.0rc1", "1.0.0"), ("2.0b3", "2.0"),
    ("1.0.0-beta.2", "1.0.0"), ("3.0.0-alpha1", "3.0.0-beta1"), ("1.0.0", "1.0.0.1"), ("1.1.1w", "3.0.0"),
    ("8.0.0-preview.1", "8.0.0"), ("2.0.dev1", "2.0"),
])
def test_vkey_order(lo, hi):
    assert upgrade.vkey(lo) < upgrade.vkey(hi)


@pytest.mark.parametrize("v", ["", "abc", ">= 1.0", "deadbeef", "x" * 70, "1" * 70,
                               "7de3f1a2b3c4d5e6f708192a3b4c5d6e7f809a1b", "1a2b3c4d"])
def test_vkey_rejects_non_versions(v):
    assert upgrade.vkey(v) is None


@pytest.mark.parametrize(("a", "b", "step"), [
    ("1.1.1k", "1.1.1w", "patch"), ("2.19.1", "2.20.0", "minor"), ("1.1.1k", "3.0.12", "major"),
    ("0.4.2", "0.5.0", "major"), ("0.4.2", "0.4.9", "patch"), ("abc", "1.0", "unknown"), ("1.2", "1.2.1", "patch"),
])
def test_step(a, b, step):
    assert upgrade.step(a, b) == step


def test_parse_fixed():
    assert upgrade.parse_fixed("1.1.1w, 3.0.12") == ["1.1.1w", "3.0.12"]
    assert upgrade.parse_fixed(">= 3.5.0") == ["3.5.0"]
    assert upgrade.parse_fixed("") == [] and upgrade.parse_fixed("not fixed") == []


@pytest.mark.parametrize(("target", "ok"), [("3.0.5", False), ("3.0.12", True), ("1.1.1w", True),
                                            ("1.1.1v", False), ("3.1.0", True)])
def test_fixes_respects_release_lines(target, ok):
    assert upgrade.fixes(target, ["1.1.1w", "3.0.12"]) is ok


def test_fixes_keeps_lettered_lines_apart_and_errs_on_regressions():
    # OpenSSL 1.1.0 and 1.1.1 are separate lines: 1.1.1a does not contain the 1.1.1d fix
    assert not upgrade.fixes("1.1.1a", ["1.1.0l", "1.1.1d"])
    assert upgrade.fixes("1.1.0l", ["1.1.0l", "1.1.1d"])
    # fixed in 2.4.1, regressed, fixed again in 2.4.6: only 2.4.6 or later is safe
    assert not upgrade.fixes("2.4.4", ["2.4.1", "2.4.6"])
    rows = upgrade.plan([_f("CVE-2019-1547", "1.1.0l, 1.1.1d", version="1.1.0h"),
                         _f("CVE-X", "1.1.1a", version="1.1.0h")])
    assert rows[0]["target"] == "1.1.1d"


def test_commit_hashes_are_not_fixed_versions():
    r = upgrade.plan([_f("CVE-1", "7de3f1a2b3c4d5e6f708192a3b4c5d6e7f809a1b")])[0]
    assert r["target"] == "" and r["state"] == "no fix" and r["no_fix"] == ["CVE-1"]


def test_plan_stays_on_the_installed_line():
    rows = upgrade.plan([_f("CVE-1", "1.1.1l, 3.0.0"), _f("CVE-2", "1.1.1w, 3.0.12"),
                         _f("CVE-2", "1.1.1w, 3.0.12", path="bin/other.dll")])
    assert len(rows) == 1
    r = rows[0]
    assert (r["target"], r["step"], r["vulns"], r["fixed_by_target"], r["files"]) == ("1.1.1w", "patch", 2, 2, 2)


def test_plan_crosses_lines_when_one_fix_needs_it():
    rows = upgrade.plan([_f("CVE-1", "1.1.1l, 3.0.0"), _f("CVE-2", "1.1.1w, 3.0.12"), _f("CVE-3", "3.0.7")])
    assert (rows[0]["target"], rows[0]["step"]) == ("3.0.12", "major")


def test_plan_reports_missing_and_suspicious_fixes():
    rows = upgrade.plan([_f("CVE-1", ""), _f("CVE-2", "1.1.1a"), _f("CVE-3", "1.1.1w")])
    r = rows[0]
    assert r["target"] == "1.1.1w" and r["no_fix"] == ["CVE-1"] and r["at_fix"] == ["CVE-2"]
    assert "without a fixed version: CVE-1" in r["note"] and "verify the match" in r["note"]
    only = upgrade.plan([_f("CVE-1", "")])[0]
    assert only["target"] == "" and only["step"] == "" and only["state"] == "no fix"
    assert only["target_label"] == "no fix available"
    verify = upgrade.plan([_f("CVE-2", "1.1.1a")])[0]
    assert verify["state"] == "verify" and verify["target_label"].startswith("already at the fixed version")
    assert cli.summarize([], COVERAGE, [], ["r1"], upgrades=[verify])["upgrade_counts"]["no_fix"] == 0


def test_plan_unparsable_installed_version_is_an_unknown_step():
    r = upgrade.plan([_f("CVE-1", "2.0", version="git-abcdef")])[0]
    assert r["target"] == "2.0" and r["step"] == "unknown"


def test_plan_orders_by_priority_and_derives_ecosystem():
    rows = upgrade.plan([
        _f("CVE-1", "2.20.0", component="requests", version="2.19.1", purl="pkg:pypi/requests@2.19.1",
           severity="MEDIUM"),
        _f("CVE-2", "1.1.1w", kev={"cve": "CVE-2"}, cpe="cpe:2.3:a:openssl:openssl:1.1.1k"),
        _f("CVE-3", "3.5.0", component="jquery", version="1.12.4", comp_type="javascript", severity="LOW"),
    ])
    assert [r["component"] for r in rows] == ["openssl", "requests", "jquery"]
    assert [r["ecosystem"] for r in rows] == ["binary", "pypi", "npm"]
    assert rows[0]["kev"] == 1 and rows[0]["priority"] == "P1"


def test_plan_flags_an_end_of_life_target(monkeypatch):
    path = DB_CACHE / "eol" / "openssl.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"result": {"releases": [
        {"name": "3.0", "isEol": False, "latest": {"name": "3.0.15"}},
        {"name": "1.1.1", "isEol": True, "eolFrom": "2023-09-11", "latest": {"name": "1.1.1w"}},
        {"name": "1.0.2", "isEol": True, "eolFrom": "2019-12-31", "latest": {"name": "1.0.2u"}},
    ]}}), encoding="utf-8")
    try:
        eol = [{"name": "openssl", "version": "1.1.1k", "status": "End of life"}]
        r = upgrade.plan([_f("CVE-1", "1.1.1w")], eol)[0]
    finally:
        path.unlink()
    assert r["installed_eol"] == "End of life" and r["target_eol"] == "End of life"
    assert r["alternative"] == "3.0 (latest 3.0.15)" and "supported: 3.0 (latest 3.0.15)" in r["note"]


# --- report, console, email ------------------------------------------------------------------
META = {"run_id": "x", "started": "2026-01-01 00:00 UTC", "finished": "2026-01-01 00:01 UTC", "duration": "1:00",
        "command": "vulnscan --r1", "evidence_dir": "./e", "repos": [{"name": "r1", "revision": "1", "url": "u"}],
        "tools": {"vulnscan": "2.0.0"}, "databases": {}, "notes": []}
COVERAGE = [{"repo": "r1", "url": "u", "revision": "1", "files": 1, "engines": {}}]


def _advised(rows):
    rows[0]["advice"] = {
        "verdict": "likely", "affects": "yes: SSL_CTX_new", "summary": "=HYPERLINK(\"http://evil\")",
        "migration": ["Port to the EVP API"], "coverage": "complete", "dropped": 1, "problems": [],
        "requirements": [{"kind": "Python", "text": "requires Python >=3.10", "violated": "shipped Python 3.8"}],
        "sources": [{"title": "CHANGES.md", "url": "https://raw.githubusercontent.com/o/r/HEAD/CHANGES.md",
                     "complete": True}],
        "changes": [{"kind": "removed", "version": "3.0.0", "summary": "@SUM(1)", "quote": "+A1 removed",
                     "source": "CHANGES.md"}]}
    return rows


def test_report_upgrades_sheet(tmp_path):
    rows = upgrade.plan([_f("CVE-1", "1.1.1l, 3.0.0"), _f("CVE-3", "3.0.7"), _f("CVE-9", "", component="=cmd|x",
                                                                                  version="1")])
    path = tmp_path / "r.xlsx"
    report.Report(path).build(META, [], [], [], [], COVERAGE, rows)
    wb = openpyxl.load_workbook(path)
    assert "Upgrades" in wb.sheetnames and "Upgrade changes" not in wb.sheetnames
    data = list(wb["Upgrades"].iter_rows(values_only=True))
    h = data[0]
    by = {r[h.index("Component")]: r for r in data[1:]}
    assert by["openssl"][h.index("Upgrade to")] == "3.0.7" and by["openssl"][h.index("Step")] == "major"
    assert by["'=cmd|x"][h.index("Upgrade to")] == "no fix available"
    assert "Breaking changes (AI-assisted)" not in h


def test_report_advice_columns_and_changes_sheet(tmp_path):
    rows = _advised(upgrade.plan([_f("CVE-1", "3.0.7")]))
    path = tmp_path / "r.xlsx"
    report.Report(path).build({**META, "ai": {"model": "test:model", "requests": 2, "upgrades": 1}},
                              [], [], [], [], COVERAGE, rows)
    wb = openpyxl.load_workbook(path)
    data = list(wb["Upgrades"].iter_rows(values_only=True))
    h = data[0]
    assert data[1][h.index("Breaking changes (AI-assisted)")] == "likely"
    assert data[1][h.index("Affects our binaries")] == "yes: SSL_CTX_new"
    assert "shipped Python 3.8" in data[1][h.index("Requirements")]
    assert data[1][h.index("Max severity")] == "High"
    changes = list(wb["Upgrade changes"].iter_rows(values_only=True))
    assert changes[1][3] == "removed" and changes[1][6] == "'+A1 removed"
    for ws in wb.worksheets:  # untrusted model/notes text never becomes a formula
        for row in ws.iter_rows():
            for c in row:
                assert not (isinstance(c.value, str) and c.value.startswith(("=", "@", "+"))
                            and not c.value.startswith("=HYPERLINK(\"https://")), (ws.title, c.value)
    text = " ".join(str(c.value) for row in wb["Summary"].iter_rows() for c in row if c.value)
    assert "AI-assisted, verify before acting" in text and "test:model" in text


def test_summary_console_and_email_show_upgrades(capsys):
    rows = _advised(upgrade.plan([_f("CVE-1", "3.0.7"), _f("CVE-2", "", component="zlib", version="1.2.11")]))
    s = cli.summarize([], COVERAGE, [], ["r1"], upgrades=rows)
    assert s["upgrade_counts"] == {"total": 2, "major": 1, "no_fix": 1, "likely": 1, "advised": 1}
    cli.final_summary(s, "r.xlsx", "e", "1:00")
    out = capsys.readouterr().out
    assert "Upgrade paths (2)" in out and "likely" in out and "no fix" in out
    html = notify.render_html(s, {**META, "duration": "1:00"}, True, "r.xlsx")
    assert "Upgrade paths" in html and "Breaking (AI)" in html and "verify it on the Upgrades sheet" in html
    text = notify.render_text(s, META, True, "r.xlsx")
    assert "openssl 1.1.1k -> 3.0.7 (major), breaking: likely (AI-assisted)" in text
    assert "zlib 1.2.11 -> no fix (-)" in text


def test_target_support_ignores_cycles_without_a_version_name():
    path = DB_CACHE / "eol" / "openssl.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"result": {"releases": [
        {"name": "lts", "isEol": False, "latest": {"name": "3.0.15"}},
        {"isEol": False, "latest": {"name": "3.0.16"}},
        {"name": "1.1.1", "isEol": True, "eolFrom": "2023-09-11", "latest": {"name": "1.1.1w"}},
    ]}}), encoding="utf-8")
    try:
        r = upgrade.plan([_f("CVE-1", "1.1.1w")])[0]
    finally:
        path.unlink()
    assert r["target_eol"] == "End of life" and r["alternative"] == ""
