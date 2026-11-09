"""Upgrade paths: for every vulnerable component, the lowest version that fixes all of its known
vulnerabilities, and how big a step that is.

Deterministic and offline: it works from the fixed versions the engines reported and the end-of-life data
eol_status() already cached. It never claims more than that data supports: a vulnerability without a fixed
version is listed as such, and a version that cannot be compared is an *unknown* step, never a small one."""
from __future__ import annotations

import re
from collections import defaultdict

from . import enrich
from .scanners import SEV_ORDER

PRIO = ["P1", "P2", "P3", "P4"]

# tokens that mark a pre-release when they are a word, or a letter followed by a number (1.0a1, 2.0rc2);
# a lone letter is a post-release suffix (OpenSSL 1.1.1w)
_PRE_WORDS = {"alpha", "beta", "rc", "pre", "preview", "dev", "snapshot", "milestone", "ea", "cr"}
_PRE_LETTERS = {"a", "b", "c", "m"}
_PRE, _END, _POST, _NUM = 0, 1, 2, 3


def vkey(version: str) -> tuple | None:
    """Sort key for a version string across ecosystems (PEP 440, semver, Maven, NuGet, OpenSSL letters).

    None when the string is not a version (empty, a range, a commit hash, a date-less label)."""
    s = (version or "").strip().lower()
    s = re.sub(r"^v(?=\d)", "", s).split("+", 1)[0]
    if not re.match(r"^\d+([._-]|[a-z]|$)", s) or len(s) > 64:
        return None
    if re.fullmatch(r"[0-9a-f]{7,}", s) and re.search(r"[a-f]", s):
        return None  # a commit hash (OSV GIT ranges), not a version
    toks = re.findall(r"\d+|[a-z]+", s)
    lead = 0
    while lead < len(toks) and toks[lead].isdigit():
        lead += 1
    nums = [int(t) for t in toks[:lead]]
    while len(nums) > 1 and nums[-1] == 0:  # 1.0 == 1.0.0
        nums.pop()
    key = [(_NUM, n) for n in nums]
    rest = toks[lead:]
    for i, t in enumerate(rest):
        if t.isdigit():
            key.append((_NUM, int(t)))
        elif t in _PRE_WORDS or (t in _PRE_LETTERS and i + 1 < len(rest) and rest[i + 1].isdigit()):
            key.append((_PRE, t))
        else:
            key.append((_POST, t))
    key.append((_END, ""))
    return tuple(key)


def numbers(version: str) -> list[int]:
    m = re.match(r"^v?(\d+(?:\.\d+)*)", (version or "").strip().lower())
    return [int(x) for x in m.group(1).split(".")] if m else []


def line(version: str) -> tuple[int, ...]:
    """Release line a fix belongs to: (major, minor), or (major, minor, patch) for versions with a letter
    suffix, whose third number is the line (OpenSSL 1.1.0 and 1.1.1 are separate lines, 1.1.1w a release)."""
    n = numbers(version) + [0, 0, 0]
    if re.match(r"^v?\d+(?:\.\d+)*[a-z]+$", (version or "").strip().lower()):
        return n[0], n[1], n[2]
    return n[0], n[1]


def step(installed: str, target: str) -> str:
    """Size of the upgrade: patch, minor, major or unknown. In 0.x, a minor step counts as major (semver)."""
    a, b = numbers(installed), numbers(target)
    if not a or not b or vkey(installed) is None or vkey(target) is None:
        return "unknown"
    a, b = a + [0, 0], b + [0, 0]
    if a[0] != b[0] or (a[0] == 0 and a[1] != b[1]):
        return "major"
    if a[1] != b[1]:
        return "minor"
    return "patch"


def parse_fixed(fixed: str) -> list[str]:
    """Fixed versions as reported by the engines: '1.1.1w, 3.0.12' (grype/OSV) or '>= 3.5.0' (retire.js)."""
    out = []
    for part in (fixed or "").split(","):
        v = re.sub(r"^[<>=~^ ]+", "", part.strip())
        if vkey(v) is not None:
            out.append(v)
    return out


def fixes(target: str, fixed: list[str]) -> bool:
    """Does `target` fix a vulnerability fixed in `fixed`? Either it is at or above every fix, or its own release
    line has fixes and the highest of them is at or below it (1.1.1w fixes the 1.1.1 line, not 3.0.5). Taking the
    highest fix on the line errs on the safe side when a line was fixed, regressed and fixed again."""
    t = vkey(target)
    if t >= max(vkey(f) for f in fixed):
        return True
    same = [vkey(f) for f in fixed if line(f) == line(target)]
    return bool(same) and max(same) <= t


def ecosystem(f: dict) -> str:
    purl = f.get("purl") or ""
    if purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0].lower()
    t = (f.get("comp_type") or "").lower()
    return {"python": "pypi", "pypi": "pypi", "npm": "npm", "javascript": "npm", "dotnet": "nuget",
            "nuget": "nuget", "java-archive": "maven", "maven": "maven", "go-module": "golang", "go": "golang",
            "rust-crate": "cargo", "crates.io": "cargo", "gem": "gem", "rubygems": "gem",
            "binary": "binary"}.get(t, "binary" if f.get("cpe") else t)


def _target_support(name: str, target: str) -> tuple[str, str]:
    """(status of the target's release line, supported alternative) from cached endoflife.date data."""
    slug = enrich.eol_slug(name)
    releases = enrich.cached_releases(slug) if slug else None
    if not releases:
        return "", ""
    rel = enrich._match_cycle(releases, target)
    st = enrich.cycle_status(rel) if rel else None
    if not st:
        return "", ""
    tk = vkey(target)
    best = None
    for r in releases:
        latest = str((r.get("latest") or {}).get("name") or "")
        lk = vkey(latest)
        if r.get("isEol") or lk is None or lk <= tk or vkey(str(r.get("name") or "")) is None:
            continue
        if best is None or vkey(str(r.get("name"))) < vkey(str(best.get("name"))):
            best = r
    alt = f"{best['name']} (latest {best['latest']['name']})" if best else ""
    return st[0], alt


def plan(findings: list[dict], eol: list[dict] = ()) -> list[dict]:
    """One row per vulnerable (component, installed version)."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for f in findings:
        if f.get("component") and f.get("version"):
            groups[(f["component"].lower(), f["version"])].append(f)
    eol_by = {(e["name"].lower(), e["version"]): e["status"] for e in eol if e.get("name")}
    rows = []
    for (_, version), fs in groups.items():
        name = fs[0]["component"]
        inst = vkey(version)
        per_vuln: dict[str, set[str]] = defaultdict(set)
        for f in fs:
            per_vuln[f["vuln_id"]] |= set(parse_fixed(f.get("fixed", "")))
        no_fix, at_fix, needed = [], [], {}
        for vid, fx in sorted(per_vuln.items()):
            above = {v for v in fx if inst is None or vkey(v) > inst}
            if not fx:
                no_fix.append(vid)
            elif not above:
                at_fix.append(vid)  # installed is already at/above every reported fix: verify the match
            else:
                needed[vid] = sorted(above, key=vkey)
        target = ""
        if needed:
            candidates = sorted({v for fx in needed.values() for v in fx}, key=vkey)
            target = next(t for t in candidates if all(fixes(t, fx) for fx in needed.values()))
        target_status, alternative = _target_support(name, target) if target else ("", "")
        sev = max((f["severity"] for f in fs), key=lambda s: SEV_ORDER[s])
        notes = []
        if no_fix:
            notes.append(f"{len(no_fix)} without a fixed version: {', '.join(no_fix[:10])}")
        if at_fix:
            notes.append(f"installed version is already at or above the reported fix for {', '.join(at_fix[:10])}"
                         " - verify the match")
        if target_status:
            notes.append(f"target line: {target_status}" + (f"; supported: {alternative}" if alternative else ""))
        rows.append({
            "component": name, "version": version, "ecosystem": ecosystem(fs[0]),
            "id": next((f.get("purl") or f.get("cpe") for f in fs if f.get("purl") or f.get("cpe")), ""),
            "target": target, "step": step(version, target) if target else "",
            # upgrade: target found; no fix: a vulnerability without any fixed version; verify: every reported
            # fix is at or below the installed version, so the match itself is doubtful
            "state": "upgrade" if target else ("no fix" if no_fix else "verify"),
            "vulns": len(per_vuln), "fixed_by_target": len(needed), "no_fix": no_fix, "at_fix": at_fix,
            "severity": sev, "priority": min((f["priority"] for f in fs), key=PRIO.index),
            "kev": len({f["vuln_id"] for f in fs if f.get("kev")}),
            "repos": sorted({f["repo"] for f in fs}), "files": len({(f["repo"], f["path"]) for f in fs}),
            "installed_eol": eol_by.get((name.lower(), version), ""), "target_eol": target_status,
            "alternative": alternative, "note": "; ".join(notes),
        })
    for r in rows:
        r["target_label"] = r["target"] or ("no fix available" if r["state"] == "no fix"
                                            else "already at the fixed version - verify the match")
    rows.sort(key=lambda r: (PRIO.index(r["priority"]), -r["kev"], -SEV_ORDER[r["severity"]], -r["vulns"],
                             r["component"].lower()))
    return rows
