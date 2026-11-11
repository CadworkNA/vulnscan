"""Excel report, email rendering/sending and CLI argument handling."""
from __future__ import annotations

import smtplib
from email import message_from_bytes
from pathlib import Path

import openpyxl
import pytest

from vulnscan import cli, enrich, notify, report, scanners, svn


def _finding(**kw):
    f = scanners.finding(repo="r1", revision="42", path="bin/libssl.dll", component="openssl", version="1.1.1k",
                         vuln_id="CVE-2021-3711", severity="CRITICAL", cvss_score=9.8, sources={"grype"},
                         description="SM2 decryption overflow", title="")
    f.update(kw)
    f.setdefault("priority", enrich.priority(f))
    f["priority"] = enrich.priority(f)
    return f


FINDINGS = [
    _finding(),
    _finding(path="bin/other.dll"),
    _finding(vuln_id="CVE-2025-0411", component="7-zip", version="19.00", severity="HIGH", cvss_score=7.0,
             kev={"cve": "CVE-2025-0411", "date_added": "2025-02-06", "due_date": "2025-02-27",
                  "known_ransomware_campaign_use": "unknown"}, epss=0.47, path="bin/7z.exe"),
    _finding(vuln_id="GHSA-xxxx", component="=cmd|'/C calc'!A0", version="1", severity="MEDIUM",
             cvss_score=None, description="<script>alert(1)</script>", path="web/@evil.js"),
]
COVERAGE = [{"repo": "r1", "url": "https://svn.example.com/r1", "revision": "42", "files": 10, "binaries": 3,
             "components": 2, "engines": {"grype (packages)": {"status": "ok", "duration": "0:01"},
                                         "osv-scanner": {"status": "FAILED", "error": "boom"}},
             "archive_failures": [("x.zip", "bad")], "archives_failed": 1}]
EOL = [{"repo": "r1", "name": "python", "version": "3.8.10", "path": "python38.dll", "type": "binary",
        "product": "python", "cycle": "3.8", "eol_date": "2024-10-07", "latest": "3.8.20",
        "status": "End of life", "source": "endoflife.date"}]
META = {"run_id": "20260101-000000", "started": "2026-01-01 00:00 UTC", "finished": "2026-01-01 00:01 UTC",
        "duration": "1:00", "command": "vulnscan --r1", "evidence_dir": "./vulnscan-results/x",
        "repos": [{"name": "r1", "revision": "42", "url": "https://svn.example.com/r1"}],
        "tools": {"vulnscan": "1.0.0", "grype": "0.121.0"}, "databases": {"grype DB": "built today"}, "notes": []}
BINARIES = [{"repo": "r1", "path": "bin/unknown.dll", "kind": "pe", "party": "third-party", "company": "Acme",
             "components": [], "review": True, "sha256": "0" * 64, "size": 10}]
COMPONENTS = [{"repo": "r1", "name": "openssl", "version": "1.1.1k", "type": "binary", "source": "PE",
               "path": "bin/libssl.dll", "id": "cpe:2.3:a:openssl:openssl:1.1.1k"}]


@pytest.fixture
def workbook(tmp_path):
    path = tmp_path / "r.xlsx"
    report.Report(path).build(META, [dict(f) for f in FINDINGS], COMPONENTS, EOL, BINARIES, COVERAGE)
    return openpyxl.load_workbook(path)


def test_report_sheets_and_rows(workbook):
    assert workbook.sheetnames == ["Summary", "Findings", "Vulnerabilities", "Upgrades", "Components", "End of Life",
                                   "Binaries", "Coverage"]
    rows = list(workbook["Findings"].iter_rows(values_only=True))
    assert len(rows) == 1 + len(FINDINGS)
    header = rows[0]
    # sorted: the KEV finding is P1 and comes first
    assert rows[1][header.index("KEV")] == "YES"
    assert rows[1][header.index("Priority")] == "P1"
    vulns = list(workbook["Vulnerabilities"].iter_rows(values_only=True))
    files_col = vulns[0].index("Affected files")
    ssl_row = next(r for r in vulns[1:] if "CVE-2021-3711" in str(r[vulns[0].index("Vulnerability")]))
    assert ssl_row[files_col] == 2  # two files, one vulnerability row


def test_report_neutralises_formula_injection(workbook):
    for ws in workbook.worksheets:
        for row in ws.iter_rows():
            for c in row:
                if isinstance(c.value, str) and c.value.startswith("="):
                    assert c.value.startswith("=HYPERLINK(\"https://"), (ws.title, c.coordinate, c.value)


def test_report_flags_incomplete_scan(workbook):
    text = " ".join(str(c.value) for row in workbook["Summary"].iter_rows() for c in row if c.value)
    assert "Incomplete" in text and "osv-scanner" in text


def test_report_handles_empty_scan(tmp_path):
    path = tmp_path / "empty.xlsx"
    report.Report(path).build(META, [], [], [], [], [{"repo": "r1", "engines": {}, "files": 0}])
    wb = openpyxl.load_workbook(path)
    assert wb["Findings"].max_row == 2  # header + placeholder row


# --- email -----------------------------------------------------------------------------
def _summary():
    return cli.summarize([dict(f) for f in FINDINGS], COVERAGE, EOL, ["r1"])


def test_summary_model():
    s = _summary()
    assert s["total"] == 4 and s["kev"] == 1 and s["eol"] == 1
    assert not s["status_ok"] and any("osv-scanner" in p for p in s["problems"])
    assert s["top_components"][0]["name"] == "7-zip"  # KEV first


def test_email_html_escapes_untrusted_text():
    html = notify.render_html(_summary(), META, True, "r.xlsx")
    assert "<script>" not in html
    assert "Scan incomplete" in html and "CVE-2025-0411" in html
    assert notify.render_text(_summary(), META, True, "r.xlsx").startswith("VULNERABILITY SCAN")


def test_subject_lines():
    assert "1 actively exploited" in notify.subject(_summary(), "[vulnscan]")
    assert "INCOMPLETE" in notify.subject(_summary(), "[vulnscan]")
    empty = cli.summarize([], [{"repo": "r1", "engines": {}}], [], ["r1"])
    assert notify.subject(empty, "[x]") == "[x] r1: no known vulnerabilities found"


def test_email_config_validation(monkeypatch):
    with pytest.raises(notify.EmailConfigError):
        notify.config()
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "scanner@example.com")
    monkeypatch.setenv("SMTP_TO", "a@example.com; b@example.com")
    monkeypatch.setenv("SMTP_SECURITY", "bogus")
    with pytest.raises(notify.EmailConfigError):
        notify.config()
    monkeypatch.setenv("SMTP_SECURITY", "starttls")
    assert notify.config()["to"] == ["a@example.com", "b@example.com"]


class FakeSMTP:
    sent: list = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port = host, port
        self.tls = False

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        pass

    def starttls(self, context=None):
        assert context.verify_mode.name == "CERT_REQUIRED"
        self.tls = True

    def login(self, user, pw):
        if pw != "right":
            raise smtplib.SMTPAuthenticationError(535, b"nope")

    def send_message(self, msg):
        assert self.tls
        FakeSMTP.sent.append(msg)


@pytest.mark.parametrize("max_mb, attached", [("15", True), ("0.000001", False)])
def test_send_email(tmp_path, monkeypatch, max_mb, attached):
    FakeSMTP.sent = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    for k, v in {"SMTP_HOST": "smtp.example.com", "SMTP_FROM": "scanner@example.com", "SMTP_TO": "a@example.com",
                 "SMTP_USERNAME": "u", "SMTP_PASSWORD": "right", "SMTP_MAX_ATTACHMENT_MB": max_mb}.items():
        monkeypatch.setenv(k, v)
    rep = tmp_path / "vulnscan_r1.xlsx"
    rep.write_bytes(b"PK fake xlsx")
    notify.send(_summary(), META, rep)
    msg = message_from_bytes(FakeSMTP.sent[0].as_bytes())
    names = [p.get_filename() for p in msg.walk() if p.get_filename()]
    assert (names == ["vulnscan_r1.xlsx"]) is attached
    assert msg["To"] == "a@example.com"


def test_send_email_auth_failure_does_not_retry(tmp_path, monkeypatch):
    FakeSMTP.sent = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(notify.time, "sleep", lambda s: pytest.fail("must not retry on auth failure"))
    for k, v in {"SMTP_HOST": "h", "SMTP_FROM": "f@example.com", "SMTP_TO": "t@example.com",
                 "SMTP_USERNAME": "u", "SMTP_PASSWORD": "wrong"}.items():
        monkeypatch.setenv(k, v)
    rep = tmp_path / "r.xlsx"
    rep.write_bytes(b"x")
    with pytest.raises(RuntimeError, match="could not send"):
        notify.send(_summary(), META, rep)


# --- CLI -------------------------------------------------------------------------------
def _repos():
    return {"app_2026": svn.Repo("app_2026", "https://svn.example.com/a"),
            "tools_2026": svn.Repo("tools_2026", "https://svn.example.com/b")}


def test_cli_repo_flags():
    _, args = cli.parse(["--app_2026"], _repos())
    assert args.selected == ["app_2026"]
    _, args = cli.parse(["--all"], _repos())
    assert args.selected == ["app_2026", "tools_2026"]
    _, args = cli.parse(["--repo", "tools_2026", "--app_2026", "--repo", "tools_2026"], _repos())
    assert args.selected == ["tools_2026", "app_2026"]


@pytest.mark.parametrize("argv", [["--nope"], ["--repo", "nope"], ["--engines", "packages,trivy"],
                                  ["--path", "/definitely/missing"]])
def test_cli_rejects_bad_arguments(argv):
    with pytest.raises(SystemExit) as e:
        cli.parse(argv, _repos())
    assert e.value.code == 2


def test_cli_path_adds_local_repo(tmp_path):
    (tmp_path / "build out").mkdir()
    repos = _repos()
    _, args = cli.parse(["--path", str(tmp_path / "build out")], repos)
    name = args.selected[0]
    assert repos[name].local and name == "build_out"


def test_cli_list_and_help_exit_codes(monkeypatch, capsys):
    monkeypatch.setenv("VULNSCAN_REPOS", "app_2026=https://svn.example.com/a")
    assert cli.main(["--list"]) == 0
    assert "--app_2026" in capsys.readouterr().out
    assert cli.main([]) == 2


def test_cli_schedule_validation(monkeypatch):
    monkeypatch.setenv("VULNSCAN_REPOS", "app_2026=https://svn.example.com/a")
    assert cli.main(["--app_2026", "--schedule", "61 * * * *"]) == 2


def test_cli_email_requires_config(monkeypatch):
    monkeypatch.setenv("VULNSCAN_REPOS", "app_2026=https://svn.example.com/a")
    assert cli.main(["--app_2026", "--email"]) == 2


def test_cli_output_must_be_writable(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNSCAN_REPOS", "app_2026=https://svn.example.com/a")
    assert cli.main(["--app_2026", "--output", str(tmp_path / "missing")]) == 2


def test_host_path():
    assert cli.host_path(cli.WORK / "a" / "b.xlsx") == "./a/b.xlsx"
    assert cli.host_path(Path("/elsewhere/x")) == "/elsewhere/x"
