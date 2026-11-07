"""Run the scan engines and normalise their output to Finding dicts.

Engines (all run against the staged tree of one repository):
  grype       on the Syft SBOM - Python/npm/.NET/Java/Go/Rust packages, binary classifiers
  grype       on the binary-identification SBOM - native libraries identified from PE
              version resources and embedded version signatures, matched via NVD CPEs
  osv-scanner independent second opinion for packages, against the OSV.dev database
  retire.js   vulnerable standalone JavaScript libraries
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .stage import tidy
from .util import DB_CACHE, cached_download, capture, fmt_dur, log, run_streamed

SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NEGLIGIBLE": 1, "UNKNOWN": 0}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
GRYPE_DB = DB_CACHE / "grype" / "6" / "vulnerability.db"


class ScannerError(RuntimeError):
    pass


def norm_sev(s) -> str:
    s = str(s or "").strip().upper()
    if s == "MODERATE":
        return "MEDIUM"
    if s in ("INFO", "NONE"):
        return "NEGLIGIBLE"
    return s if s in SEV_ORDER else "UNKNOWN"


def sev_from_score(score) -> str:
    try:
        x = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    return ("CRITICAL" if x >= 9 else "HIGH" if x >= 7 else "MEDIUM" if x >= 4
            else "LOW" if x > 0 else "NEGLIGIBLE")


def finding(**kw) -> dict:
    base = dict(path="", component="", version="", comp_type="", vuln_id="", aliases=set(),
                severity="UNKNOWN", cvss_score=None, cvss_vector="", cvss_version="", fixed="",
                fix_state="", title="", description="", published="", cwe="", refs=[], sources=set(),
                evidence="", confidence="high", purl="", cpe="", kev=None, epss=None,
                epss_pct=None)
    base.update(kw)
    return base


class PathMapper:
    """Turn any scanner-reported path into the repo-relative display path."""

    def __init__(self, stage_root: Path):
        self.root = str(stage_root).rstrip("/")

    def __call__(self, p: str) -> str:
        if not p:
            return ""
        if p.startswith(self.root):
            p = p[len(self.root):]
        p = p.lstrip("/")
        for prefix in ("files/", "archives/"):
            if p.startswith(prefix):
                return tidy(p[len(prefix):])
        return tidy(p)


# ---------------------------------------------------------------------------
def tool_versions() -> dict:
    def grab(cmd, keys=("Version",)):
        out = capture(cmd)
        lines = [ln.split(":", 1)[1].strip() for ln in out.splitlines() if ln.split(":", 1)[0].strip() in keys]
        return " ".join(lines) or out.splitlines()[0] if out else "?"
    return {
        "syft": grab(["syft", "version"]),
        "grype": grab(["grype", "version"]),
        "osv-scanner": capture(["osv-scanner", "--version"]).splitlines()[0].replace("osv-scanner version: ", ""),
        "retire.js": capture(["retire", "--version"]).splitlines()[0],
        "subversion": capture(["svn", "--version", "--quiet"]),
        "7-Zip": next((ln.split(":")[0].strip() for ln in capture(["7z", "i"]).splitlines() if "7-Zip" in ln), "?"),
    }


MAX_DB_AGE_DAYS = 3  # older vulnerability data is not a trustworthy all-clear


def update_databases(offline: bool) -> tuple[dict, list[str]]:
    """Refresh vulnerability databases once per run.

    Returns (provenance info, problems). Any problem means the run must not be
    reported as complete: a stale or broken database silently hides findings.
    Raises ScannerError when no usable database exists at all."""
    info: dict[str, str] = {}
    problems: list[str] = []
    if offline:
        log.info("offline mode: using cached vulnerability databases", extra={"stage": "db"})
    else:
        ok = False
        for attempt in range(1, 4):
            if run_streamed(["grype", "db", "update"], "db:grype", heartbeat=20) == 0:
                ok = True
                break
            log.warning("grype DB update failed (attempt %d/3)", attempt, extra={"stage": "db"})
            time.sleep(10 * attempt)
        if not ok:
            problems.append("vulnerability database update FAILED - results are based on an older database")
    status = capture(["grype", "db", "status", "-o", "json"])
    try:
        st = json.loads(status)
    except json.JSONDecodeError:
        st = {}
    if not GRYPE_DB.exists() or not st:
        raise ScannerError(f"no usable grype vulnerability database ({status[:200]})")
    if not st.get("valid", False):
        raise ScannerError(f"grype vulnerability database is invalid: {st.get('error') or status[:200]}")
    built = str(st.get("built", ""))
    info["grype DB"] = f"schema {st.get('schemaVersion')}, built {built}"
    info["grype DB source"] = st.get("from", "")
    try:
        age = datetime.now(UTC) - datetime.fromisoformat(built.replace("Z", "+00:00"))
        info["grype DB"] += f" ({age.days} days old)"
        if age > timedelta(days=MAX_DB_AGE_DAYS):
            problems.append(f"vulnerability database is {age.days} days old (built {built[:10]}; "
                            f"limit {MAX_DB_AGE_DAYS} days)")
    except ValueError:
        problems.append(f"cannot determine vulnerability database age ({built!r})")
    # KEV / EPSS live in the same snapshot; their absence would silently drop P1 prioritisation
    try:
        con = sqlite3.connect(f"file:{GRYPE_DB}?mode=ro", uri=True)
        kev = con.execute("SELECT count(*) FROM known_exploited_vulnerability_handles").fetchone()[0]
        epss = con.execute("SELECT count(*) FROM epss_handles").fetchone()[0]
        con.close()
    except sqlite3.Error as exc:
        kev = epss = 0
        log.warning("cannot read KEV/EPSS tables: %s", exc, extra={"stage": "db"})
    info["CISA KEV / EPSS"] = f"{kev:,} known-exploited CVEs, {epss:,} EPSS scores"
    if kev < 500:
        problems.append(f"CISA KEV data missing or incomplete ({kev} entries)")
    if epss < 100_000:
        problems.append(f"EPSS data missing or incomplete ({epss} entries)")
    log.info("grype DB: %s · %s", info["grype DB"], info["CISA KEV / EPSS"], extra={"stage": "db"})

    try:
        repo = retire_repository(offline)
        age_h = (time.time() - repo.stat().st_mtime) / 3600
        info["retire.js repository"] = f"fetched {age_h:.0f} h ago"
        if age_h > 24 * MAX_DB_AGE_DAYS:
            problems.append(f"retire.js repository is {age_h / 24:.0f} days old")
    except ScannerError as exc:
        problems.append(str(exc))

    osv_dir = DB_CACHE / "osv"
    zips = sorted(osv_dir.rglob("*.zip")) if osv_dir.exists() else []
    info["OSV DB"] = f"offline databases ({len(zips)} ecosystems cached)" + ("" if offline else ", refreshed per scan")
    return info, problems


# ---------------------------------------------------------------------------
# Canary self-test: every engine must detect known-vulnerable samples through the
# exact production code path (same functions, same flags), otherwise its "no
# findings" cannot be trusted (broken DB, cataloger/matcher regression, format drift).
# ---------------------------------------------------------------------------
CANARY_JS = "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n"
CANARY_METADATA = "Metadata-Version: 2.1\nName: requests\nVersion: 2.19.1\nSummary: canary\n"


def selftest(workdir: Path, offline: bool) -> dict[str, str]:
    """Returns {engine: problem} for every engine that failed its canary."""
    from .pe import Component, PEInfo

    root = workdir / "canary"
    files = root / "files"
    dist = files / "site-packages" / "requests-2.19.1.dist-info"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "METADATA").write_text(CANARY_METADATA, encoding="utf-8")
    (dist / "RECORD").write_text("requests/__init__.py,,\n", encoding="utf-8")
    (files / "web").mkdir(exist_ok=True)
    (files / "web" / "jquery-1.12.4.min.js").write_text(CANARY_JS, encoding="utf-8")
    out = workdir / "out"
    out.mkdir(parents=True, exist_ok=True)
    mapper = PathMapper(root)
    canary_bin = PEInfo(path="bin/libssl.dll", size=1,
                        components=[Component("openssl", "openssl", "1.1.1k", "canary", "high")])

    checks = {
        "grype (packages)": (lambda: run_grype_packages(root, out, mapper, 2, "canary", "1")[0],
                             "CVE-2018-18074", "requests 2.19.1 (installed Python package)"),
        "grype (binaries)": (lambda: run_grype_binaries([canary_bin], out, mapper)[0],
                             "CVE-2021-3711", "OpenSSL 1.1.1k (identified library)"),
        "osv-scanner": (lambda: run_osv(root, out, mapper, offline)[0],
                        "CVE-2018-18074", "requests 2.19.1 (installed Python package)"),
        "retire.js": (lambda: run_retire(root, out, mapper, offline)[0],
                      "CVE-2020-11023", "jQuery 1.12.4"),
    }
    failed: dict[str, str] = {}
    for engine, (run, expected, what) in checks.items():
        try:
            found = run()
            ids = {i for f in found for i in {f["vuln_id"], *f["aliases"]}}
            if expected not in ids:
                failed[engine] = f"did not detect {expected} in {what} ({len(found)} matches)"
        except Exception as exc:  # noqa: BLE001 - any self-test error leaves the engine untrusted
            failed[engine] = f"self-test error: {exc}"
    for eng, why in failed.items():
        log.error("self-test FAILED for %s: %s", eng, why, extra={"stage": "selftest"})
    if not failed:
        log.info("self-test passed: every engine detected its known-vulnerable canary", extra={"stage": "selftest"})
    return failed


RETIRE_REPO_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v5.json"
RETIRE_REPO = DB_CACHE / "retire" / "jsrepository-v5.json"


def retire_repository(offline: bool) -> Path:
    """retire.js signature repository, fetched by vulnscan (refreshed daily) so that
    retire.js itself never goes to the network and --offline is honoured."""
    p = cached_download(RETIRE_REPO_URL, RETIRE_REPO, 24, offline)
    if not p:
        raise ScannerError("retire.js repository is unavailable (download failed and nothing cached)")
    return p


def _load(raw: Path, kind: type, key: str | None = None):
    """Strictly load a scanner's JSON output: unreadable or unexpected output is an
    engine failure, never 'no findings'."""
    try:
        with open(raw, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise ScannerError(f"scanner output {raw.name} is missing") from None
    except (OSError, ValueError) as exc:
        raise ScannerError(f"scanner output {raw.name} is unreadable: {exc}") from None
    if not isinstance(data, kind) or (key and key not in data):
        raise ScannerError(f"scanner output {raw.name} has an unexpected format")
    return data


# ---------------------------------------------------------------------------
# grype helpers
# ---------------------------------------------------------------------------
def parse_grype(raw: Path, mapper: PathMapper, source: str, loc_lookup=None) -> list[dict]:
    data = _load(raw, dict, "matches")
    out = []
    for m in data.get("matches") or []:
        v, a = m.get("vulnerability", {}), m.get("artifact", {})
        related = m.get("relatedVulnerabilities", []) or []
        ids = {v.get("id", "")} | {r.get("id", "") for r in related}
        cve = next((i for i in sorted(ids) if CVE_RE.match(i)), v.get("id", ""))
        score, vector, cver = None, "", ""
        for src in [v] + related:
            for c in src.get("cvss") or []:
                bs = (c.get("metrics") or {}).get("baseScore")
                if bs is not None and (score is None or c.get("version", "") > cver):
                    score, vector, cver = bs, c.get("vector", ""), c.get("version", "")
        desc = v.get("description") or next((r.get("description") for r in related if r.get("description")), "")
        urls = list(dict.fromkeys((v.get("urls") or []) + [u for r in related for u in (r.get("urls") or [])]))
        kev = (v.get("knownExploited") or [None])[0]
        epss = next((e for e in v.get("epss") or [] if e.get("cve") == cve), None)
        cwes = sorted({c.get("cwe", "") for c in v.get("cwes") or [] if c.get("cwe")})
        md = (m.get("matchDetails") or [{}])[0]
        if loc_lookup is not None:
            locs = loc_lookup.get(a.get("name", ""), {}).get(a.get("version", ""), [])
        else:
            locs = [loc.get("path", "") for loc in a.get("locations") or [] if isinstance(loc, dict)]
        cpes = a.get("cpes") or []
        for loc in locs or [""]:
            item = loc if isinstance(loc, dict) else {"path": mapper(loc)}
            out.append(finding(
                path=item["path"], component=item.get("component", a.get("name", "")),
                version=a.get("version", ""), comp_type=item.get("comp_type", a.get("type", "")),
                vuln_id=cve, aliases=ids - {cve, ""}, severity=norm_sev(v.get("severity")),
                cvss_score=score, cvss_vector=vector, cvss_version=cver,
                fixed=", ".join((v.get("fix") or {}).get("versions") or []),
                fix_state=(v.get("fix") or {}).get("state", ""), description=desc or "",
                refs=urls, sources={source}, purl=a.get("purl", ""),
                cpe=cpes[0] if cpes and isinstance(cpes[0], str) else "",
                cwe=", ".join(cwes),
                evidence=item.get("evidence", f"{md.get('type', '')} via {md.get('matcher', '')}"),
                confidence=item.get("confidence", "medium" if md.get("type") == "cpe-match" else "high"),
                kev=kev, epss=(epss or {}).get("epss"), epss_pct=(epss or {}).get("percentile")))
    return out


def _grype(target: str, raw: Path, tag: str, extra: list[str] = ()) -> int:
    raw.unlink(missing_ok=True)  # never parse a previous run's output
    rc = run_streamed(["grype", target, "-o", "json", "--file", str(raw), *extra], tag,
                      env={"GRYPE_DB_AUTO_UPDATE": "false"})
    if rc != 0 or not raw.exists():
        raise ScannerError(f"grype failed (exit {rc})")
    return rc


# ---------------------------------------------------------------------------
# Syft + Grype (packages)
# ---------------------------------------------------------------------------
SYFT_DEPRECATED = ("dotnet-deps-cataloger", "dotnet-portable-executable-cataloger",
                   "php-pecl-serialized-cataloger", "nix-store-cataloger")


def run_grype_packages(stage_root: Path, outdir: Path, mapper: PathMapper, jobs: int,
                       name: str = "", version: str = ""):
    sbom = outdir / "sbom.syft.json"
    cdx = outdir / "sbom.cyclonedx.json"
    raw = outdir / "grype-packages.json"
    t0 = time.monotonic()
    env = {"SYFT_PARALLELISM": str(jobs), "SYFT_FILE_METADATA_SELECTION": "none"}
    sbom.unlink(missing_ok=True)
    rc = run_streamed(["syft", "scan", f"dir:{stage_root}", "--override-default-catalogers", "all",
                       "--select-catalogers", ",".join(f"-{c}" for c in SYFT_DEPRECATED),
                       "--source-name", name or stage_root.name, "--source-version", version or "unknown",
                       "-o", f"syft-json={sbom}", "-o", f"cyclonedx-json={cdx}"],
                      "syft", env=env, heartbeat=20)
    if rc != 0 or not sbom.exists():
        raise ScannerError(f"syft failed (exit {rc})")
    pkgs = _load(sbom, dict, "artifacts")["artifacts"] or []
    by_type = defaultdict(int)
    for p in pkgs:
        by_type[p.get("type", "?")] += 1
    log.info("SBOM: %d packages in %s (%s)", len(pkgs), fmt_dur(time.monotonic() - t0),
             ", ".join(f"{k} {v}" for k, v in sorted(by_type.items(), key=lambda kv: -kv[1])) or "none",
             extra={"stage": "syft"})
    rc = _grype(f"sbom:{sbom}", raw, "grype", ["--add-cpes-if-none"])
    out = parse_grype(raw, mapper, "grype")
    log.info("%d package vulnerability matches", len(out), extra={"stage": "grype"})
    return out, pkgs, {"packages": len(pkgs), "exit": rc}


# ---------------------------------------------------------------------------
# Grype on binary-identification SBOM (PE resources + embedded signatures)
# ---------------------------------------------------------------------------
def run_grype_binaries(bin_infos, outdir: Path, mapper: PathMapper):
    tag = "grype:binaries"
    lookup: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    comps = {}
    for info in bin_infos:
        for c in info.components:
            name = f"{c.vendor}/{c.product}"
            comps[(name, c.version)] = c
            lookup[name][c.version].append({
                "path": info.path, "component": c.product, "comp_type": "binary",
                "evidence": f"{c.rule} -> cpe:2.3:a:{c.vendor}:{c.product}:{c.version}",
                "confidence": c.confidence})
    if not comps:
        log.info("no third-party libraries identified in binaries", extra={"stage": tag})
        return [], {"components": 0}
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "serialNumber": f"urn:uuid:{uuid.uuid4()}",
           "metadata": {"component": {"type": "application", "name": "binary-identification"}},
           "components": [{"type": "library", "bom-ref": f"{n}@{v}", "name": n, "version": v,
                           "cpe": f"cpe:2.3:a:{c.vendor}:{c.product}:{v}:*:*:*:*:*:*:*"}
                          for (n, v), c in sorted(comps.items())]}
    sbom = outdir / "sbom.binaries.cyclonedx.json"
    sbom.write_text(json.dumps(bom, indent=1), encoding="utf-8")
    log.info("matching %d distinct libraries found in %d binary locations against NVD CPE data",
             len(comps), sum(len(v) for d in lookup.values() for v in d.values()), extra={"stage": tag})
    raw = outdir / "grype-binaries.json"
    rc = _grype(f"sbom:{sbom}", raw, tag)
    out = parse_grype(raw, mapper, "binary-id", loc_lookup=lookup)
    log.info("%d binary vulnerability matches", len(out), extra={"stage": tag})
    return out, {"components": len(comps), "exit": rc}


# ---------------------------------------------------------------------------
# osv-scanner (independent second opinion on packages)
# ---------------------------------------------------------------------------
def run_osv(stage_root: Path, outdir: Path, mapper: PathMapper, offline: bool):
    """Uses osv-scanner's own extractors (independent of syft) and the OSV.dev
    database, downloaded for offline matching so no package list leaves the host."""
    tag = "osv-scanner"
    raw = outdir / "osv-scanner.json"
    cmd = ["osv-scanner", "scan", "source", "--recursive", "--no-ignore", "--format", "json",
           "--output-file", str(raw), "--offline-vulnerabilities", "--allow-no-lockfiles",
           "--x-plugins", "artifact"]
    if not offline:
        cmd.append("--download-offline-databases")
    cmd.append(str(stage_root))
    raw.unlink(missing_ok=True)
    rc = run_streamed(cmd, tag, heartbeat=20,
                      quiet_patterns=("scanning dir", "scanned ", "filtered "))
    # exit 0 = clean, 1 = vulnerabilities found, 128 = no packages; others are failures
    if not raw.exists() or rc not in (0, 1, 128):
        raise ScannerError(f"osv-scanner failed (exit {rc})")
    out = parse_osv(raw, mapper)
    log.info("%d package vulnerability matches", len(out), extra={"stage": tag})
    return out, {"exit": rc}


def parse_osv(raw: Path, mapper: PathMapper) -> list[dict]:
    data = _load(raw, dict, "results")
    out = []
    for res in data.get("results", []) or []:
        src_path = (res.get("source") or {}).get("path", "")
        for pkg in res.get("packages", []) or []:
            p = pkg.get("package", {})
            groups = {tuple(sorted(g.get("ids", []))): g for g in pkg.get("groups", []) or []}
            for v in pkg.get("vulnerabilities", []) or []:
                ids = {v.get("id", "")} | set(v.get("aliases") or [])
                cve = next((i for i in sorted(ids) if CVE_RE.match(i)), v.get("id", ""))
                g = next((g for k, g in groups.items() if v.get("id") in k), {})
                score = None
                try:
                    score = float(g.get("max_severity")) if g.get("max_severity") else None
                except ValueError:
                    pass
                sev = norm_sev((v.get("database_specific") or {}).get("severity")) if v.get("database_specific") else "UNKNOWN"
                if sev == "UNKNOWN":
                    sev = sev_from_score(score)
                fixed = sorted({e.get("fixed") for a in v.get("affected", []) or []
                                for r in a.get("ranges", []) or [] for e in r.get("events", []) or []
                                if e.get("fixed")})
                locs = [mapper(loc) for loc in _osv_locations(pkg)] or [mapper(src_path)]
                for loc in locs:
                    out.append(finding(
                        path=loc, component=p.get("name", ""), version=p.get("version", ""),
                        comp_type=p.get("ecosystem", ""), vuln_id=cve, aliases=ids - {cve, ""},
                        severity=sev, cvss_score=score, title=v.get("summary", ""),
                        description=v.get("details", "") or v.get("summary", ""),
                        published=(v.get("published") or "")[:10], fixed=", ".join(fixed[:5]),
                        refs=[r.get("url") for r in v.get("references", []) or [] if r.get("url")],
                        sources={"osv-scanner"}, evidence=f"OSV {v.get('id', '')} ({p.get('ecosystem', '')})",
                        purl=p.get("purl", "")))
    return out


def _osv_locations(pkg: dict) -> list[str]:
    """osv-scanner reports SBOM-sourced packages with their original syft locations
    in the purl qualifiers / package locations when available."""
    locs = []
    for loc in (pkg.get("package", {}).get("locations") or []):
        for k in ("block", "name", "version"):
            fn = (loc.get(k) or {}).get("file_name")
            if fn:
                locs.append(fn)
                break
    return locs


# ---------------------------------------------------------------------------
# retire.js
# ---------------------------------------------------------------------------
def run_retire(stage_root: Path, outdir: Path, mapper: PathMapper, offline: bool):
    tag = "retire.js"
    raw = outdir / "retire.json"
    cache = DB_CACHE / "retire"
    cache.mkdir(parents=True, exist_ok=True)
    cmd = ["retire", "--path", str(stage_root), "--outputformat", "json", "--outputpath", str(raw),
           "--exitwith", "0", "--cachedir", str(cache), "--jsrepo", str(retire_repository(offline))]
    raw.unlink(missing_ok=True)
    rc = run_streamed(cmd, tag, heartbeat=20)
    if not raw.exists():
        raise ScannerError(f"retire.js failed (exit {rc}, no output)")
    errors = (_load(raw, dict, "data").get("errors") or [])
    for e in errors:
        log.warning("retire.js: %s", str(e)[:300], extra={"stage": tag})
    if rc != 0 or errors:
        first = mapper(str(errors[0])) if errors else ""
        raise ScannerError(f"retire.js could not scan {len(errors)} file(s)" + (f", e.g. {first[:200]}" if first
                                                                                 else f" (exit {rc})"))
    out = parse_retire(raw, mapper)
    log.info("%d JavaScript library vulnerability matches", len(out), extra={"stage": tag})
    return out, {"exit": rc}


def parse_retire(raw: Path, mapper: PathMapper) -> list[dict]:
    data = _load(raw, dict, "data")
    rows = data["data"]
    out = []
    for entry in rows:
        path = mapper(entry.get("file", ""))
        for res in entry.get("results", []) or []:
            for v in res.get("vulnerabilities", []) or []:
                ids = v.get("identifiers") or {}
                cves = ids.get("CVE") or []
                alt = ids.get("githubID") or (ids.get("issue") and f"{res.get('component')}-issue-{ids['issue']}")
                vid = cves[0] if cves else (alt or f"RETIRE:{res.get('component')}:{ids.get('summary', '')[:50]}")
                below = v.get("below", "")
                out.append(finding(
                    path=path, component=res.get("component", ""), version=res.get("version", ""),
                    comp_type="javascript", vuln_id=vid,
                    aliases=set(cves[1:]) | ({ids["githubID"]} if ids.get("githubID") and cves else set()),
                    severity=norm_sev(v.get("severity")), fixed=f">= {below}" if below else "",
                    title=ids.get("summary", ""), description=ids.get("summary", ""),
                    cwe=", ".join(v.get("cwe") or []), refs=v.get("info") or [],
                    sources={"retire.js"}, evidence=f"retire.js {res.get('detection', 'signature')}"))
    return out
