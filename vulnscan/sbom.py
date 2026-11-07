"""CycloneDX 1.6 SBOM per repository (--sbom).

Combines what the scan learned into one document:
  * packages catalogued by Syft (Python, npm, .NET, Java, ...), as Syft described them
  * third-party libraries identified inside binaries (version resource / embedded
    signature), with CPE, identification evidence and every file location
  * vulnerabilities (CycloneDX VDR): id, source, ratings, CISA KEV, EPSS and the
    affected component(s)
"""
from __future__ import annotations

import json
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .scanners import PathMapper
from .util import load_json, log

SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "NEGLIGIBLE": "info",
       "UNKNOWN": "unknown"}


def _props(**kv) -> list[dict]:
    return [{"name": k, "value": str(v)} for k, v in kv.items() if v not in (None, "")]


def build(repo: str, revision: str, url: str, syft_cdx: Path | None, binaries: list[dict],
          findings: list[dict], tools: dict) -> dict:
    mapper = PathMapper(Path("/"))
    components: list[dict] = []
    index: dict[tuple[str, str], list[str]] = defaultdict(list)  # (name, version) -> bom-refs
    by_purl: dict[str, str] = {}

    # 1. Syft packages (kept as-is, locations normalised to repository paths)
    syft = load_json(syft_cdx, {}) if syft_cdx and syft_cdx.exists() else {}
    for c in (syft or {}).get("components", []) or []:
        if c.get("type") == "file":
            continue
        c = dict(c)
        props = []
        for p in c.get("properties", []) or []:
            if p.get("name", "").startswith("syft:location:") and p.get("name", "").endswith(":path"):
                props.append({"name": "vulnscan:location", "value": mapper(p.get("value", ""))})
            else:
                props.append(p)
        c["properties"] = props
        c.setdefault("bom-ref", str(uuid.uuid4()))
        components.append(c)
        index[(c.get("name", "").lower(), c.get("version", ""))].append(c["bom-ref"])
        if c.get("purl"):
            by_purl[c["purl"]] = c["bom-ref"]

    # 2. libraries identified inside binaries
    libs: dict[tuple[str, str, str], dict] = {}
    for b in binaries:
        for comp in b.get("components", []):
            key = (comp["vendor"], comp["product"], comp["version"])
            lib = libs.setdefault(key, {"rules": set(), "confidence": comp["confidence"], "files": []})
            lib["rules"].add(comp["rule"])
            lib["files"].append((b["path"], b.get("sha256", "")))
    for (vendor, product, version), lib in sorted(libs.items()):
        ref = f"binary:{vendor}/{product}@{version}"
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        components.append({
            "type": "library", "bom-ref": ref, "name": product, "version": version, "cpe": cpe,
            "supplier": {"name": vendor},
            "evidence": {
                "identity": [{"field": "cpe", "confidence": 0.9 if lib["confidence"] == "high" else 0.6,
                              "methods": [{"technique": "binary-analysis",
                                           "confidence": 0.9 if lib["confidence"] == "high" else 0.6,
                                           "value": "; ".join(sorted(lib["rules"]))}]}],
                "occurrences": [{"location": p} for p, _ in lib["files"]],
            },
            "properties": _props(**{"vulnscan:identification": "; ".join(sorted(lib["rules"]))})
            + [{"name": "vulnscan:location", "value": p} for p, _ in lib["files"]],
        })
        index[(product.lower(), version)].append(ref)

    # 3. every shipped executable as a file component with its hash
    for b in binaries:
        if len(b.get("sha256", "")) == 64:
            components.append({
                "type": "file", "bom-ref": f"file:{b['path']}", "name": b["path"],
                **({"version": b["file_version"]} if b.get("file_version") else {}),
                "hashes": [{"alg": "SHA-256", "content": b["sha256"]}],
                **({"supplier": {"name": b["company"]}} if b.get("company") else {}),
                "properties": _props(**{"vulnscan:origin": b.get("party"), "vulnscan:product": b.get("product"),
                                        "vulnscan:signed": "yes" if b.get("signed") else "no"}),
            })

    # 4. libraries only a vulnerability engine saw (e.g. standalone JavaScript found by retire.js)
    def refs_for(f: dict) -> list[str]:
        return ([by_purl[f["purl"]]] if f.get("purl") in by_purl else []) or \
            index.get((f["component"].lower(), f["version"])) or \
            index.get((f["component"].split("/")[-1].lower(), f["version"])) or []

    extra: dict[tuple[str, str], dict] = {}
    for f in findings:
        if f["component"] and not refs_for(f):
            key = (f["component"].lower(), f["version"])
            c = extra.get(key)
            if c is None:
                c = extra[key] = {"type": "library", "bom-ref": f"detected:{f['component']}@{f['version']}",
                                  "name": f["component"], "version": f["version"],
                                  **({"purl": f["purl"]} if f.get("purl") else {}),
                                  "properties": _props(**{"vulnscan:detected-by": ", ".join(sorted(f["sources"]))})}
            loc = {"name": "vulnscan:location", "value": f["path"]}
            if f.get("path") and loc not in c["properties"]:
                c["properties"].append(loc)
    for key, c in extra.items():
        components.append(c)
        index[key].append(c["bom-ref"])

    # 5. vulnerabilities (VDR)
    vulns: dict[str, dict] = {}
    for f in findings:
        refs = refs_for(f)
        v = vulns.get(f["vuln_id"])
        if v is None:
            rating = {"severity": SEV.get(f["severity"], "unknown")}
            if f.get("cvss_score") is not None:
                rating["score"] = f["cvss_score"]
                vec = f.get("cvss_vector") or ""
                rating["method"] = ("CVSSv4" if vec.startswith("CVSS:4") else "CVSSv31" if vec.startswith("CVSS:3.1")
                                    else "CVSSv3" if vec.startswith("CVSS:3") else "CVSSv2" if vec else "other")
                if vec:
                    rating["vector"] = vec
            v = vulns[f["vuln_id"]] = {
                "bom-ref": f"vuln:{f['vuln_id']}", "id": f["vuln_id"],
                "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{f['vuln_id']}"}
                if f["vuln_id"].startswith("CVE-") else {"name": "OSV", "url": f"https://osv.dev/vulnerability/{f['vuln_id']}"},
                "ratings": [rating],
                "description": (f.get("description") or f.get("title") or "")[:4000],
                "affects": [],
                "properties": _props(**{
                    "vulnscan:priority": f.get("priority"),
                    "vulnscan:cisa-kev": "yes" if f.get("kev") else "no",
                    "vulnscan:epss": f.get("epss"), "vulnscan:fixed-in": f.get("fixed"),
                    "vulnscan:detected-by": ", ".join(sorted(f.get("sources") or []))}),
            }
            if f.get("cwe"):
                cwes = [int(c.split("-")[1]) for c in f["cwe"].split(", ") if c.startswith("CWE-") and c[4:].isdigit()]
                if cwes:
                    v["cwes"] = cwes
            if f.get("published"):
                v["published"] = f"{f['published']}T00:00:00Z"
        for r in refs:
            if {"ref": r} not in v["affects"]:
                v["affects"].append({"ref": r})

    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "vulnscan", "version": __version__}]
                      + [{"type": "application", "name": k, "version": str(v)} for k, v in tools.items()
                         if k != "vulnscan"]},
            "component": {"type": "application", "bom-ref": f"repo:{repo}", "name": repo,
                          "version": revision if revision in ("local", "") else f"r{revision}",
                          "properties": _props(**{"vulnscan:source": url})},
        },
        "components": components,
        "vulnerabilities": [v for v in vulns.values() if v["affects"]] + [v for v in vulns.values() if not v["affects"]],
    }


def write(path: Path, doc: dict) -> Path:
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=False), encoding="utf-8")
    n_lib = sum(1 for c in doc["components"] if c["type"] != "file")
    log.info("SBOM written: %s (%d components, %d files, %d vulnerabilities)", path.name, n_lib,
             len(doc["components"]) - n_lib, len(doc["vulnerabilities"]), extra={"stage": "sbom"})
    return path
