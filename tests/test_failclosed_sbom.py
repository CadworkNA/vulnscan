"""Fail-closed guarantees (never an all-clear when something went wrong) and the SBOM."""
from __future__ import annotations

import json
import smtplib
from email import message_from_bytes, policy

import pytest

from vulnscan import cli, enrich, notify, sbom, scanners, stage


def _cov(**kw):
    c = {"repo": "r1", "url": "https://svn.example.com/r1", "revision": "7", "files": 5,
         "engines": {"grype (packages)": {"status": "ok"}}}
    c.update(kw)
    return c


# --- summary status ---------------------------------------------------------------------
def test_clean_run_is_ok():
    assert cli.summarize([], [_cov()], [], ["r1"])["status_ok"]


@pytest.mark.parametrize("cov, run_problems", [
    (_cov(error="svn update failed"), []),
    (_cov(engines={"osv-scanner": {"status": "FAILED", "error": "x"}}), []),
    (_cov(archives_failed=1, archive_failures=[("a.zip", "password")]), []),
    (_cov(), ["vulnerability database update FAILED"]),
    (_cov(), ["self-test failed for grype: ..."]),
])
def test_any_problem_means_not_ok(cov, run_problems):
    s = cli.summarize([], [cov], [], ["r1"], run_problems)
    assert not s["status_ok"] and s["problems"]


def test_no_findings_but_incomplete_never_reads_as_clear():
    s = cli.summarize([], [_cov(error="boom")], [], ["r1"])
    subj = notify.subject(s, "[vulnscan]")
    assert "INCOMPLETE" in subj and "no known vulnerabilities" not in subj
    html = notify.render_html(s, {"started": "", "duration": "", "evidence_dir": "", "tools": {},
                                  "databases": {}, "run_id": "", "command": ""}, True, "r.xlsx")
    assert "Scan incomplete" in html and "Scan completed" not in html


def test_empty_repository_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(stage, "STAGE", tmp_path / "stage")
    (tmp_path / "empty").mkdir()
    repo = cli.svn.Repo("empty", "local:x", checkout=tmp_path / "empty", local=True)
    args = type("A", (), {"no_extract": False, "no_hash": False, "jobs": 1, "engines": [], "keep_stage": False,
                          "no_update": False, "offline": False})()
    with pytest.raises(RuntimeError, match="nothing was scanned"):
        cli.scan_repo(repo, args, tmp_path / "evidence")


def test_eol_download_failure_is_a_problem(monkeypatch):
    monkeypatch.setattr(enrich, "cached_download", lambda *a, **k: None)
    rows, problems = enrich.eol_status([{"repo": "r", "name": "python", "version": "3.8.10", "path": "p",
                                         "type": "binary"}], offline=False)
    assert rows == [] and problems and "python" in problems[0]


def test_grype_nonzero_exit_is_failure(tmp_path, monkeypatch):
    def fake_run(cmd, tag, **kw):
        (tmp_path / "out.json").write_text('{"matches": []}')
        return 2
    monkeypatch.setattr(scanners, "run_streamed", fake_run)
    with pytest.raises(scanners.ScannerError):
        scanners._grype("sbom:x", tmp_path / "out.json", "t")


def test_stale_output_is_never_reused(tmp_path, monkeypatch):
    out = tmp_path / "out.json"
    out.write_text('{"matches": []}')  # left over from an earlier run
    monkeypatch.setattr(scanners, "run_streamed", lambda cmd, tag, **kw: 0)  # tool "succeeds" but writes nothing
    with pytest.raises(scanners.ScannerError):
        scanners._grype("sbom:x", out, "t")


def test_failure_email(monkeypatch):
    sent = []

    class S:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def ehlo(self): pass
        def starttls(self, context=None): pass
        def send_message(self, m): sent.append(m)

    monkeypatch.setattr(smtplib, "SMTP", S)
    for k, v in {"SMTP_HOST": "h", "SMTP_FROM": "f@example.com", "SMTP_TO": "t@example.com"}.items():
        monkeypatch.setenv(k, v)
    notify.send_failure("no usable grype vulnerability database", {
        "repos": ["r1"], "started": "now", "evidence_dir": "./x", "run_id": "1", "command": "vulnscan --r1"})
    msg = message_from_bytes(sent[0].as_bytes(), policy=policy.default)
    assert "SCAN FAILED" in msg["Subject"]
    assert "not an all-clear" in msg.get_body(("html",)).get_content()


# --- SBOM -----------------------------------------------------------------------------------
def test_sbom_document(tmp_path):
    syft_cdx = tmp_path / "syft.cdx.json"
    syft_cdx.write_text(json.dumps({"components": [
        {"type": "library", "bom-ref": "pkg:pypi/requests@2.19.1", "name": "requests", "version": "2.19.1",
         "purl": "pkg:pypi/requests@2.19.1",
         "properties": [{"name": "syft:location:0:path", "value": "/files/lib/requests-2.19.1.dist-info/METADATA"}]},
        {"type": "file", "name": "ignored"}]}))
    binaries = [{"path": "bin/libssl.dll", "sha256": "a" * 64, "company": "OpenSSL Project", "party": "third-party",
                 "file_version": "1.1.1.11", "signed": False,
                 "components": [{"vendor": "openssl", "product": "openssl", "version": "1.1.1k",
                                 "rule": "OpenSSL library", "confidence": "high"}]}]
    findings = [
        scanners.finding(vuln_id="CVE-2021-3711", component="openssl", version="1.1.1k", severity="CRITICAL",
                         cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", priority="P1",
                         cwe="CWE-120", published="2021-08-24", sources={"binary-id"}),
        scanners.finding(vuln_id="CVE-2018-18074", component="requests", version="2.19.1", severity="HIGH",
                         purl="pkg:pypi/requests@2.19.1", priority="P3", sources={"grype"}),
    ]
    doc = sbom.build("r1", "42", "https://svn.example.com/r1", syft_cdx, binaries, findings, {"grype": "0.121.0"})
    assert doc["specVersion"] == "1.6" and doc["metadata"]["component"]["version"] == "r42"
    names = {(c["type"], c["name"]) for c in doc["components"]}
    assert ("library", "requests") in names and ("library", "openssl") in names and ("file", "bin/libssl.dll") in names
    assert ("file", "ignored") not in names
    req = next(c for c in doc["components"] if c["name"] == "requests")
    assert {"name": "vulnscan:location", "value": "lib/requests-2.19.1.dist-info/METADATA"} in req["properties"]
    ssl = next(c for c in doc["components"] if c["name"] == "openssl")
    assert ssl["cpe"].startswith("cpe:2.3:a:openssl:openssl:1.1.1k")
    vulns = {v["id"]: v for v in doc["vulnerabilities"]}
    assert vulns["CVE-2021-3711"]["affects"] == [{"ref": ssl["bom-ref"]}]
    assert vulns["CVE-2021-3711"]["ratings"][0]["method"] == "CVSSv31"
    assert vulns["CVE-2021-3711"]["cwes"] == [120]
    assert vulns["CVE-2018-18074"]["affects"] == [{"ref": "pkg:pypi/requests@2.19.1"}]
    refs = {c["bom-ref"] for c in doc["components"]}
    assert len(refs) == len(doc["components"]), "bom-refs must be unique"
    # round-trips as JSON
    sbom.write(tmp_path / "x.cdx.json", doc)
    assert json.loads((tmp_path / "x.cdx.json").read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"


def test_sbom_validates_against_cyclonedx_schema(tmp_path):
    validation = pytest.importorskip("cyclonedx.validation.json")
    from cyclonedx.schema import SchemaVersion
    doc = sbom.build("r1", "1", "https://svn.example.com/r1", None,
                     [{"path": "a.dll", "sha256": "b" * 64, "components": [
                         {"vendor": "zlib", "product": "zlib", "version": "1.2.11", "rule": "sig", "confidence": "high"}]}],
                     [scanners.finding(vuln_id="CVE-2022-37434", component="zlib", version="1.2.11",
                                       severity="CRITICAL", cvss_score=9.8, priority="P2", sources={"binary-id"})],
                     {"grype": "0.121.0"})
    err = validation.JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(doc))
    assert err is None, err
