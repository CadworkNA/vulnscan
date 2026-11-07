"""Detection regression test: the full pipeline on public, known-vulnerable artifacts.

Runs every engine for real (needs network for the artifacts and vulnerability
databases), then asserts that well-known vulnerabilities are still detected,
that the run is reported as complete, and that the SBOM is produced. Catches
regressions in identification rules, scanner upgrades and database changes.

    pytest -m integration
"""
from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path

import openpyxl
import pytest

from vulnscan import cli

pytestmark = pytest.mark.integration

ARTIFACTS = {
    "runtime/python-3.8.10-embed-amd64.zip": (
        "https://www.python.org/ftp/python/3.8.10/python-3.8.10-embed-amd64.zip",
        "abbe314e9b41603dde0a823b76f5bbbe17b3de3e5ac4ef06b759da5466711271"),
    "bin/7z1900-x64.exe": (
        "https://www.7-zip.org/a/7z1900-x64.exe",
        "0f5d4dbbe5e55b7aa31b91e5925ed901fdf46a367491d81381846f05ad54c45e"),
    "web/js/jquery-1.12.4.min.js": (
        "https://code.jquery.com/jquery-1.12.4.min.js",
        "668b046d12db350ccba6728890476b3efee53b2f42dbb84743e5e9f1ae0cc404"),
    "python/wheels/requests-2.19.1-py2.py3-none-any.whl": (
        "https://files.pythonhosted.org/packages/py2.py3/r/requests/requests-2.19.1-py2.py3-none-any.whl",
        "63b52e3c866428a224f97cab011de738c36aec0185aa91cfacd418b5d58911d1"),
    "python/wheels/urllib3-1.23-py2.py3-none-any.whl": (
        "https://files.pythonhosted.org/packages/py2.py3/u/urllib3/urllib3-1.23-py2.py3-none-any.whl",
        "b5725a0bd4ba422ab0e66e89e030c806576753ea3ee08554382c14e685d117b5"),
}

# (vulnerability, component as reported, where) that must be found
EXPECTED = [
    ("CVE-2025-0411", "7-Zip", "bin/7z1900-x64.exe"),                                       # CISA KEV
    ("CVE-2020-11023", "jquery", "web/js/jquery-1.12.4.min.js"),                            # CISA KEV
    ("CVE-2021-3711", "openssl", "runtime/python-3.8.10-embed-amd64.zip!/libcrypto-1_1.dll"),
    ("CVE-2022-37434", "zlib", "runtime/python-3.8.10-embed-amd64.zip!/python38.dll"),     # static zlib
    ("CVE-2018-18074", "requests", None),
    ("CVE-2019-11324", "urllib3", None),
]


@pytest.fixture(scope="module")
def demo(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("acme-cad-2.4")
    for rel, (url, sha) in ARTIFACTS.items():
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "vulnscan-tests"})
        with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 - fixed public URLs
            data = r.read()
        assert hashlib.sha256(data).hexdigest() == sha, f"artifact changed upstream: {url}"
        dest.write_bytes(data)
    return root


@pytest.fixture(scope="module")
def result(demo, tmp_path_factory):
    out = tmp_path_factory.mktemp("out")
    rc = cli.main(["--path", str(demo), "--output", str(out), "--sbom"])
    reports = list(out.glob("vulnscan_*.xlsx"))
    return rc, out, reports[0] if reports else None


def test_run_is_complete(result):
    rc, _, report = result
    assert report is not None, "no report written"
    assert rc == 0, "scan reported as incomplete/failed - see scan.log"


def test_known_vulnerabilities_detected(result):
    _, _, report = result
    rows = list(openpyxl.load_workbook(report, read_only=True, data_only=True)["Findings"].iter_rows(values_only=True))
    h = rows[0]
    found = {(r[h.index("Vulnerability")], r[h.index("Component")].lower(), r[h.index("File path")]) for r in rows[1:]}
    for vid, comp, path in EXPECTED:
        hits = [f for f in found if f[0] == vid and f[1] == comp.lower() and (path is None or f[2] == path)]
        assert hits, f"{vid} in {comp} ({path or 'any file'}) no longer detected"


def test_kev_and_eol_flagged(result):
    _, _, report = result
    wb = openpyxl.load_workbook(report, read_only=True, data_only=True)
    rows = list(wb["Findings"].iter_rows(values_only=True))
    h = rows[0]
    kev = {r[h.index("Vulnerability")] for r in rows[1:] if r[h.index("KEV")] == "YES"}
    assert {"CVE-2025-0411", "CVE-2020-11023"} <= kev
    eol = {(r[0], r[3]) for r in list(wb["End of Life"].iter_rows(values_only=True))[1:]}
    assert ("python", "End of life") in eol and ("openssl", "End of life") in eol


def test_sbom_written(result):
    _, out, _ = result
    sboms = list(out.glob("vulnscan_*.cdx.json"))
    assert len(sboms) == 1
    doc = json.loads(sboms[0].read_text(encoding="utf-8"))
    ids = {v["id"] for v in doc["vulnerabilities"] if v["affects"]}
    assert {"CVE-2025-0411", "CVE-2021-3711", "CVE-2020-11023"} <= ids
