"""Contract tests: recorded real outputs of grype / osv-scanner / retire.js.

When a scanner version bump changes its JSON format, these fail instead of the
report silently losing findings.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from conftest import STAGE_ROOT

from vulnscan import scanners
from vulnscan.pe import Component, PEInfo

MAP = scanners.PathMapper(Path(STAGE_ROOT))


def test_parse_grype_packages(fixtures):
    out = scanners.parse_grype(fixtures / "grype-packages.json", MAP, "grype")
    assert out, "no findings parsed"
    by_id = {f["vuln_id"]: f for f in out}
    # KEV entry carried through with its CISA metadata and EPSS
    kev = by_id["CVE-2025-0411"]
    assert kev["kev"] and kev["kev"]["cve"] == "CVE-2025-0411"
    assert kev["epss"] is not None and 0 <= kev["epss"] <= 1
    assert kev["path"] == "bin/7z1900-x64.exe"
    assert kev["confidence"] == "medium"  # cpe-match
    # GHSA ids are normalised to the CVE they alias
    assert not any(f["vuln_id"].startswith("GHSA-") and any(a.startswith("CVE-") for a in f["aliases"])
                   for f in out)
    for f in out:
        assert f["severity"] in scanners.SEV_ORDER
        assert f["sources"] == {"grype"}
        assert not f["path"].startswith(("/", "files/", "archives/"))
        if f["cvss_score"] is not None:
            assert 0 <= f["cvss_score"] <= 10


def test_parse_grype_binaries_maps_locations(fixtures):
    lookup = {"7-zip/7-zip": {"19.00": [{"path": "bin/7z.dll", "component": "7-zip", "comp_type": "binary",
                                         "evidence": "rule", "confidence": "high"}]}}
    out = scanners.parse_grype(fixtures / "grype-binaries.json", MAP, "binary-id", loc_lookup=lookup)
    sevenzip = [f for f in out if f["component"] == "7-zip"]
    assert sevenzip and all(f["path"] == "bin/7z.dll" and f["confidence"] == "high" for f in sevenzip)
    assert "CVE-2025-0411" in {f["vuln_id"] for f in sevenzip}
    # components without a location lookup still produce findings (path unknown) rather than vanishing
    assert any(f["component"] == "openssl/openssl" or f["component"] == "openssl" for f in out)


def test_parse_osv(fixtures):
    out = scanners.parse_osv(fixtures / "osv-scanner.json", MAP)
    assert out
    names = {f["component"] for f in out}
    assert {"requests", "urllib3"} <= names
    for f in out:
        assert f["sources"] == {"osv-scanner"}
        assert f["path"].endswith("METADATA") and "!/" in f["path"]
        # PYSEC ids with a CVE alias are reported under the CVE
        if any(a.startswith("CVE-") for a in f["aliases"] | {f["vuln_id"]}):
            assert f["vuln_id"].startswith("CVE-")


def test_parse_retire(fixtures):
    out = scanners.parse_retire(fixtures / "retire.json", MAP)
    assert len(out) == 6
    assert {f["component"] for f in out} == {"jquery"}
    assert all(f["path"] == "web/js/jquery-1.12.4.min.js" for f in out)
    assert "CVE-2020-11023" in {f["vuln_id"] for f in out}
    assert all(f["fixed"].startswith(">=") for f in out if f["fixed"])


@pytest.mark.parametrize("content", ["{not json", "", "[]", '{"unexpected": 1}', "null"])
@pytest.mark.parametrize("parser", [lambda p: scanners.parse_grype(p, MAP, "grype"),
                                    lambda p: scanners.parse_osv(p, MAP),
                                    lambda p: scanners.parse_retire(p, MAP)])
def test_parsers_fail_closed_on_bad_output(tmp_path, content, parser):
    """Corrupt, truncated or unexpected output is an engine failure - never 'no findings'."""
    bad = tmp_path / "bad.json"
    bad.write_text(content, encoding="utf-8")
    with pytest.raises(scanners.ScannerError):
        parser(bad)
    with pytest.raises(scanners.ScannerError):
        parser(tmp_path / "missing.json")


def test_empty_but_valid_output_is_zero_findings(tmp_path):
    ok = tmp_path / "ok.json"
    ok.write_text('{"matches": []}', encoding="utf-8")
    assert scanners.parse_grype(ok, MAP, "grype") == []


def test_binary_sbom_is_valid_cyclonedx(tmp_path, monkeypatch):
    """run_grype_binaries writes a CycloneDX SBOM with one CPE per distinct library."""
    info = PEInfo(path="bin/a.dll", size=1, components=[Component("openssl", "openssl", "1.1.1k", "r", "high")])
    info2 = PEInfo(path="bin/b.dll", size=1, components=[Component("openssl", "openssl", "1.1.1k", "r", "high")])
    captured = {}

    def fake_grype(target, raw, tag, extra=()):
        captured["sbom"] = target
        raw.write_text('{"matches": []}', encoding="utf-8")
        return 0

    monkeypatch.setattr(scanners, "_grype", fake_grype)
    out, meta = scanners.run_grype_binaries([info, info2], tmp_path, MAP)
    assert out == [] and meta["components"] == 1
    import json
    bom = json.loads((tmp_path / "sbom.binaries.cyclonedx.json").read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX"
    assert [c["cpe"] for c in bom["components"]] == ["cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"]
