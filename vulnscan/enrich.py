"""Merge findings from all engines, then enrich them from the same grype DB
snapshot (CISA KEV, EPSS, NVD description/CVSS) and add end-of-life status."""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from .pe import msvc_eol
from .scanners import CVE_RE, GRYPE_DB, SEV_ORDER, sev_from_score
from .util import DB_CACHE, NotFound, cached_download, load_json, log

try:
    from cvss import CVSS2, CVSS3, CVSS4
except ImportError:  # pragma: no cover
    CVSS2 = CVSS3 = CVSS4 = None


# ---------------------------------------------------------------------------
# merge
# ---------------------------------------------------------------------------
def merge(findings: list[dict]) -> list[dict]:
    """One row per (repo, path, vulnerability). Sources are unioned; for
    conflicting severities the highest wins (conservative)."""
    merged: dict[tuple, dict] = {}
    for f in findings:
        if not CVE_RE.match(f["vuln_id"]):
            cve = next((a for a in sorted(f["aliases"]) if CVE_RE.match(a)), None)
            if cve:
                f["aliases"] = (f["aliases"] | {f["vuln_id"]}) - {cve}
                f["vuln_id"] = cve
        key = (f["repo"], f["path"], f["vuln_id"].upper())
        cur = merged.get(key)
        if cur is None:
            merged[key] = f
            continue
        cur["sources"] = cur["sources"] | f["sources"]
        cur["aliases"] = cur["aliases"] | f["aliases"]
        if SEV_ORDER[f["severity"]] > SEV_ORDER[cur["severity"]]:
            cur["severity"] = f["severity"]
        if f["cvss_score"] is not None and (cur["cvss_score"] is None or f["cvss_score"] > cur["cvss_score"]):
            cur["cvss_score"], cur["cvss_vector"], cur["cvss_version"] = f["cvss_score"], f["cvss_vector"], f["cvss_version"]
        for k in ("fixed", "fix_state", "title", "description", "published", "cwe", "purl", "cpe",
                  "kev", "epss", "epss_pct"):
            if not cur.get(k) and f.get(k):
                cur[k] = f[k]
        if len(f["refs"]) > len(cur["refs"]):
            cur["refs"] = f["refs"]
        if f["confidence"] == "high":
            cur["confidence"] = "high"
        if f["evidence"] not in cur["evidence"]:
            cur["evidence"] = f"{cur['evidence']}; {f['evidence']}"
    return list(merged.values())


# ---------------------------------------------------------------------------
# grype DB lookups
# ---------------------------------------------------------------------------
class GrypeDB:
    def __init__(self, path: Path = GRYPE_DB):
        self.con = sqlite3.connect(f"file:{path}?mode=ro", uri=True) if path.exists() else None

    def kev(self, cve: str):
        if not self.con:
            return None
        row = self.con.execute(
            "SELECT b.value FROM known_exploited_vulnerability_handles k JOIN blobs b ON b.id = k.blob_id "
            "WHERE k.cve = ? COLLATE NOCASE LIMIT 1", (cve,)).fetchone()
        return json.loads(row[0]) if row else None

    def epss(self, cve: str):
        if not self.con:
            return None
        return self.con.execute("SELECT epss, percentile FROM epss_handles WHERE cve = ? COLLATE NOCASE LIMIT 1",
                                (cve,)).fetchone()

    def detail(self, cve: str) -> dict:
        """NVD record for a CVE: description, published date, best CVSS vector."""
        if not self.con:
            return {}
        row = self.con.execute(
            "SELECT v.published_date, b.value FROM vulnerability_handles v JOIN blobs b ON b.id = v.blob_id "
            "WHERE v.name = ? COLLATE NOCASE AND v.provider_id = 'nvd' LIMIT 1", (cve,)).fetchone()
        if not row:
            return {}
        blob = json.loads(row[1])
        best = None
        for s in blob.get("severities") or []:
            val = s.get("value") or {}
            if s.get("scheme") == "CVSS" and val.get("vector"):
                if best is None or str(val.get("version", "")) > str(best.get("version", "")):
                    best = val
        return {"published": (row[0] or "")[:10], "description": blob.get("description", ""),
                "vector": (best or {}).get("vector", ""), "version": str((best or {}).get("version", "")),
                "refs": [r.get("url") for r in blob.get("refs") or [] if r.get("url")]}


def cvss_score(vector: str, version: str):
    if not vector or CVSS3 is None:
        return None
    try:
        if vector.startswith("CVSS:4"):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3"):
            return float(CVSS3(vector).base_score)
        return float(CVSS2(vector).base_score)
    except Exception:  # noqa: BLE001
        return None


def priority(f: dict) -> str:
    """Triage priority combining severity, exploitation evidence (KEV) and
    exploitation likelihood (EPSS)."""
    sev, epss = f["severity"], f.get("epss") or 0
    if f.get("kev") or (sev == "CRITICAL" and epss >= 0.1):
        return "P1"
    if sev == "CRITICAL" or (sev == "HIGH" and epss >= 0.05):
        return "P2"
    if sev in ("HIGH", "MEDIUM"):
        return "P3"
    return "P4"


def enrich(findings: list[dict]) -> None:
    db = GrypeDB()
    if not db.con:
        log.warning("grype DB not available - KEV/EPSS enrichment skipped", extra={"stage": "enrich"})
    cache: dict[str, tuple] = {}
    for f in findings:
        cve = f["vuln_id"].upper()
        if CVE_RE.match(cve):
            if cve not in cache:
                cache[cve] = (db.kev(cve), db.epss(cve),
                              db.detail(cve))
            kev, epss, det = cache[cve]
            if kev and not f.get("kev"):
                f["kev"] = kev
            if epss and f.get("epss") is None:
                f["epss"], f["epss_pct"] = epss
            if det:
                f["description"] = f["description"] or det["description"]
                f["published"] = f["published"] or det["published"]
                if not f["refs"]:
                    f["refs"] = det["refs"]
                if not f["cvss_vector"] and det["vector"]:
                    f["cvss_vector"], f["cvss_version"] = det["vector"], det["version"]
        if f["cvss_score"] is None and f["cvss_vector"]:
            f["cvss_score"] = cvss_score(f["cvss_vector"], f["cvss_version"])
        if f["severity"] == "UNKNOWN" and f["cvss_score"] is not None:
            f["severity"] = sev_from_score(f["cvss_score"])
        f["priority"] = priority(f)
    n_kev = sum(1 for f in findings if f.get("kev"))
    log.info("enriched %d findings (%d distinct CVEs): %d on CISA KEV list", len(findings),
             len(cache), n_kev, extra={"stage": "enrich"})


# ---------------------------------------------------------------------------
# End-of-life
# ---------------------------------------------------------------------------
# component name / cpe product -> endoflife.date product slug
EOL_PRODUCTS = {
    "python": "python", "cpython": "python", "openssl": "openssl", "qt": "qt",
    "node.js": "nodejs", "node": "nodejs", "nodejs": "nodejs", "electron": "electron",
    "django": "django", "angularjs": "angularjs", "angular": "angular", "jquery": "jquery",
    "log4j": "log4j", "log4j-core": "log4j", "spring-framework": "spring-framework",
    "sqlite": None, "zlib": None, "dotnet": "dotnet", ".net": "dotnet", "numpy": "numpy",
    "postgresql": "postgresql", "mysql": "mysql", "7-zip": None, "ffmpeg": "ffmpeg",
    "bootstrap": "bootstrap", "vue": "vue", "react": "react", "nginx": "nginx",
"jdk": "oracle-jdk", "openjdk": "openjdk-builds-from-oracle",
}


def _match_cycle(releases: list[dict], version: str):
    best = None
    for r in releases:
        name = str(r.get("name", ""))
        if version == name or (version.startswith(name) and len(version) > len(name)
                               and not version[len(name)].isdigit()):
            if best is None or len(name) > len(str(best.get("name", ""))):
                best = r
    return best


def cycle_status(rel: dict) -> tuple[str, str] | None:
    """(status, date) of an endoflife.date release cycle, None while it is fully supported."""
    eol = rel.get("eolFrom") or ""
    eoes = rel.get("eoesFrom") or ""
    if rel.get("isEol") and (not eoes or rel.get("isEoes")):
        return "End of life", max(eol, eoes)
    if rel.get("isEol"):
        # public support ended, paid/extended (e.g. commercial LTS) still running
        return f"Extended support only (until {eoes})", eol
    if rel.get("isEoas"):
        return "Security fixes only", rel.get("eoasFrom") or ""
    return None


def eol_slug(name: str) -> str | None:
    return EOL_PRODUCTS.get(name.lower().split("/")[-1])


def cached_releases(slug: str) -> list[dict] | None:
    """Release cycles of an endoflife.date product from the cache eol_status() filled; None if not cached."""
    path = DB_CACHE / "eol" / f"{slug}.json"
    if not path.exists():
        return None
    d = load_json(path, {})
    releases = ((d or {}).get("result") or {}).get("releases") if isinstance(d, dict) else None
    return releases if isinstance(releases, list) and releases else None


def eol_status(components: list[dict], offline: bool) -> tuple[list[dict], list[str]]:
    """components: [{repo, name, version, path, type}] -> (EOL rows, problems)."""
    rows, problems = [], []
    needed = {EOL_PRODUCTS.get(c["name"].lower().split("/")[-1]) for c in components} - {None}
    data = {}
    for slug in sorted(needed):
        try:
            p = cached_download(f"https://endoflife.date/api/v1/products/{slug}",
                                DB_CACHE / "eol" / f"{slug}.json", 24, offline)
        except NotFound:
            log.debug("endoflife.date does not track %s", slug, extra={"stage": "eol"})
            continue
        d = load_json(p, {}) if p else None
        releases = ((d or {}).get("result") or {}).get("releases") if isinstance(d, dict) else None
        if releases:
            data[slug] = releases
        else:
            problems.append(f"end-of-life data for '{slug}' unavailable - EOL status of {slug} not checked")
    for c in components:
        name = c["name"].lower().split("/")[-1]
        hit = msvc_eol(name)
        if hit:
            label, date = hit
            rows.append({**c, "product": label, "cycle": "", "eol_date": date, "latest": "",
                         "status": "End of life", "source": "Microsoft lifecycle"})
            continue
        slug = EOL_PRODUCTS.get(name)
        if not slug or slug not in data or not c.get("version"):
            continue
        version = re.sub(r"^v", "", c["version"])
        rel = _match_cycle(data[slug], version)
        st = cycle_status(rel) if rel else None
        if not st:
            continue
        status, date = st
        latest = (rel.get("latest") or {}).get("name", "")
        rows.append({**c, "product": slug, "cycle": rel.get("name"), "eol_date": date,
                     "latest": latest, "status": status, "source": "endoflife.date"})
    distinct = {(r["product"], r["version"]) for r in rows if r["status"] == "End of life"}
    log.info("%d end-of-life component versions in %d files (+%d with extended/security-only support)",
             len(distinct), sum(1 for r in rows if r["status"] == "End of life"),
             sum(1 for r in rows if r["status"] != "End of life"), extra={"stage": "eol"})
    return rows, problems
