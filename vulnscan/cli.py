"""vulnscan command line entry point."""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import shutil
import signal
import sys
import threading
import time
import traceback
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__, enrich, notify, report, sbom, scanners, stage, svn
from .schedule import Cron
from .util import (
    add_logfile,
    console,
    drop_privileges,
    fmt_dur,
    fmt_size,
    get_secret,
    log,
    remove_handler,
    setup_logging,
)
from .util import stage as stage_ctx

WORK = Path(os.environ.get("VULNSCAN_WORK", "/work"))
ENGINES = ("packages", "binaries", "osv", "retire")
SEV_STYLE = {"CRITICAL": "sev.critical", "HIGH": "sev.high", "MEDIUM": "sev.medium", "LOW": "sev.low",
             "NEGLIGIBLE": "sev.negligible", "UNKNOWN": "sev.unknown"}


def build_parser(repo_names: list[str]) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnscan",
        description="Check out SVN repositories of shipped files and scan every file for known "
                    "vulnerabilities (CVE/GHSA/OSV), CISA KEV, EPSS and end-of-life components. "
                    "Writes an Excel report to the mounted /work folder.",
        epilog="repositories: " + (", ".join(f"--{n}" for n in repo_names) or
                                   "none configured (set VULNSCAN_REPOS, see README)") +
               "\n\nexample:  podman run --rm -it --env-file .env -v vulnscan-cache:/cache "
               "-v \"$PWD:/work\" ghcr.io/cadworkna/vulnscan --all",
        formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    sel = p.add_argument_group("repository selection (combine freely)")
    sel.add_argument("--all", action="store_true", help="scan every configured repository")
    sel.add_argument("--repo", action="append", default=[], metavar="NAME",
                     help="scan repository NAME (same as --NAME); may be repeated")
    sel.add_argument("--path", action="append", default=[], metavar="DIR", type=Path,
                     help="scan a local folder instead of an SVN repository (relative to /work); "
                          "may be repeated")
    sel.add_argument("--list", action="store_true", help="list configured repositories and exit")
    o = p.add_argument_group("options")
    o.add_argument("--no-update", action="store_true",
                   help="scan the cached checkout without running svn update")
    o.add_argument("--offline", action="store_true",
                   help="no network: use cached checkouts and vulnerability databases as-is")
    o.add_argument("--engines", default=",".join(ENGINES),
                   help=f"comma-separated engines to run (default: all = {','.join(ENGINES)})")
    o.add_argument("--no-extract", action="store_true", help="do not extract archives (zip/msi/cab/7z...)")
    o.add_argument("--no-hash", action="store_true", help="skip SHA-256 hashing of every file")
    o.add_argument("--jobs", type=int, default=os.cpu_count() or 4, help="parallel workers (default: CPU count)")
    o.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "kev", "p1", "p2", "none"],
                   default="none", help="exit with code 1 if findings at/above this level exist (CI gating)")
    o.add_argument("--output", type=Path, default=WORK, help="report folder (default: /work)")
    o.add_argument("--sbom", action="store_true",
                   help="also write a CycloneDX 1.6 SBOM (+ vulnerabilities) per repository next to the report")
    o.add_argument("--email", action="store_true",
                   help="email the summary + report (SMTP_* settings, see README)")
    o.add_argument("--schedule", metavar="CRON", default="",
                   help="keep running and scan on this cron schedule, e.g. '0 2 * * 1' "
                        "(Mondays 02:00, container TZ)")
    o.add_argument("--scheduled", action="store_true",
                   help="keep running and scan on the cron schedule in $VULNSCAN_SCHEDULE (used by compose)")
    o.add_argument("--run-now", action="store_true", help="with --schedule: also scan once immediately")
    o.add_argument("--keep-stage", action="store_true", help="keep the extracted scan tree in the cache")
    o.add_argument("-v", "--verbose", action="store_true", help="show every tool output line live")
    o.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    return p


def parse(argv: list[str], repos: dict[str, svn.Repo]):
    names = sorted(repos)
    parser = build_parser(names)
    args, extra = parser.parse_known_args(argv)
    selected = list(args.repo)
    for e in extra:
        name = e[2:] if e.startswith("--") else None
        if name in repos:
            selected.append(name)
        else:
            parser.error(f"unknown argument {e!r}. Known repositories: {', '.join(names)}")
    unknown = [s for s in selected if s not in repos]
    if unknown:
        parser.error(f"unknown repository {', '.join(unknown)}. Known: {', '.join(names)}")
    if args.all:
        selected = names
    for p in args.path:
        folder = p if p.is_absolute() else WORK / p
        if not folder.is_dir():
            parser.error(f"--path {p}: not a directory inside the container (did you mount it?)")
        name = re.sub(r"[^A-Za-z0-9._-]", "_", folder.resolve().name) or "folder"
        while name in repos:
            name += "_"
        repos[name] = svn.Repo(name=name, url=f"local:{folder}", checkout=folder, local=True)
        selected.append(name)
    args.selected = list(dict.fromkeys(selected))
    args.engines = [e.strip() for e in args.engines.split(",") if e.strip()]
    bad = [e for e in args.engines if e not in ENGINES]
    if bad:
        parser.error(f"unknown engine(s) {bad}; choose from {ENGINES}")
    if not args.engines:
        parser.error(f"--engines: at least one engine is required ({','.join(ENGINES)})")
    if args.scheduled and not args.schedule:
        args.schedule = os.environ.get("VULNSCAN_SCHEDULE", "").strip()
        if not args.schedule:
            parser.error("--scheduled needs VULNSCAN_SCHEDULE (a cron expression)")
    clash = sorted(n for n in repos if f"--{n}" in parser._option_string_actions)
    if clash:
        parser.error(f"repository name(s) {', '.join(clash)} clash with built-in options - rename them")
    return parser, args


# ---------------------------------------------------------------------------
def banner(tools: dict):
    t = Text()
    t.append("vulnscan ", "bold cyan")
    t.append(__version__, "cyan")
    t.append("  ·  shipped-file vulnerability scanner\n", "grey62")
    t.append("  ".join(f"{k} {v}" for k, v in tools.items()), "grey50")
    console.print(Panel(t, border_style="cyan", box=box.ROUNDED, expand=False))


def list_repos(repos, notes):
    tb = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
    tb.add_column("flag")
    tb.add_column("SVN URL", style="grey62")
    tb.add_column("cached checkout")
    for name, r in sorted(repos.items()):
        cached = (r.checkout / ".svn").exists()
        tb.add_row(f"--{name}", r.url, "[ok]yes[/ok]" if cached else "[muted]no[/muted]")
    console.print(tb)
    for n in notes:
        console.print(f"[muted]· {n}[/muted]")


# ---------------------------------------------------------------------------
def load_accepted_gaps(work: Path) -> tuple[list[dict], list[str]]:
    """Known, deliberately accepted coverage gaps (e.g. a password-protected archive).

    From <work>/vulnscan-accepted-gaps.json or $VULNSCAN_ACCEPTED_GAPS:
      [{"repo": "tools_2026" | "*", "path": "glob", "reason": "why", "expires": "YYYY-MM-DD"}]
    A gap is only accepted with a reason; expired entries no longer match, so the
    run becomes incomplete again until someone re-evaluates it."""
    raw, src = os.environ.get("VULNSCAN_ACCEPTED_GAPS", ""), "VULNSCAN_ACCEPTED_GAPS"
    f = work / "vulnscan-accepted-gaps.json"
    if not raw and f.is_file():
        raw, src = f.read_text(encoding="utf-8"), f.name
    if not raw.strip():
        return [], []
    try:
        entries = json.loads(raw)
        entries = entries.get("gaps", entries) if isinstance(entries, dict) else entries
    except ValueError as exc:
        return [], [f"cannot parse {src}: {exc}"]
    gaps, notes, today = [], [], datetime.now().date().isoformat()
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict) or not e.get("path") or not str(e.get("reason", "")).strip():
            notes.append(f"{src}: ignored entry without path and reason: {e!r}")
        elif e.get("expires") and str(e["expires"]) < today:
            notes.append(f"{src}: accepted gap '{e['path']}' expired on {e['expires']} - re-evaluate it")
        else:
            gaps.append(e)
    return gaps, notes


def accepted_gap(repo: str, path: str, gaps: list[dict]) -> dict | None:
    return next((g for g in gaps if g.get("repo", "*") in ("*", repo) and fnmatch.fnmatchcase(path, g["path"])),
                None)


def scan_repo(repo: svn.Repo, args, evidence: Path):
    tag = f"repo:{repo.name}"
    outdir = evidence / repo.name
    outdir.mkdir(parents=True, exist_ok=True)
    cov = {"repo": repo.name, "url": repo.url, "engines": {}}
    t0 = time.monotonic()
    findings, components, binaries = [], [], []

    if repo.local:
        log.info("scanning local folder %s (no SVN)", repo.checkout, extra={"stage": tag})
        repo.revision = "local"
        cov.update(revision="local", last_changed="")
    else:
        with stage_ctx(f"SVN {'checkout/update' if not args.no_update and not args.offline else 'cache'}",
                       f"svn:{repo.name}"):
            svn.sync(repo, update=not (args.no_update or args.offline))
        cov.update(revision=repo.revision, last_changed=f"r{repo.last_changed_rev} {repo.last_changed_date}")

    with stage_ctx("staging, archive extraction & binary analysis", f"stage:{repo.name}"):
        st = stage.build(repo.name, repo.checkout, extract=not args.no_extract, hash_files=not args.no_hash,
                         jobs=args.jobs)
    sha = {f.path: f.sha256 for f in st.files}
    kind = {f.path: f.kind for f in st.files}
    open_gaps, acknowledged = [], []
    gaps = st.archives_failed + [(p, f"only partially extracted: {why}") for p, why in st.archives_partial]
    for path, why in gaps:
        gap = accepted_gap(repo.name, path, args.accepted_gaps)
        if gap:
            acknowledged.append((path, why, gap["reason"]))
            log.info("not extracted, acknowledged in accepted gaps: %s (%s)", path, gap["reason"], extra={"stage": tag})
        else:
            open_gaps.append((path, why))
    cov.update(files=len(st.files), bytes=sum(f.size for f in st.files),
               in_archives=sum(f.in_archive for f in st.files), archives_ok=len(st.archives_ok),
               archives_failed=len(open_gaps), archive_failures=open_gaps,
               archives_acknowledged=acknowledged, symlinks=st.symlinks,
               not_archives=len(st.not_archives), binaries=len(st.pe))
    if not st.files:
        raise RuntimeError("no files found to scan (empty checkout or folder) - nothing was scanned")
    mapper = scanners.PathMapper(st.root)

    jobs_per_engine = max(2, args.jobs // 2)
    tasks = {}
    if "packages" in args.engines:
        tasks["grype (packages)"] = lambda: scanners.run_grype_packages(
            st.root, outdir, mapper, jobs_per_engine, repo.name, f"r{repo.revision}")
    if "binaries" in args.engines:
        tasks["grype (binaries)"] = lambda: scanners.run_grype_binaries(st.pe, outdir, mapper)
    if "osv" in args.engines:
        tasks["osv-scanner"] = lambda: scanners.run_osv(st.root, outdir, mapper, args.offline)
    if "retire" in args.engines:
        tasks["retire.js"] = lambda: scanners.run_retire(st.root, outdir, mapper, args.offline)

    def timed(name, fn):
        t = time.monotonic()
        try:
            return name, fn(), None, fmt_dur(time.monotonic() - t)
        except Exception as exc:  # noqa: BLE001
            log.error("%s failed: %s", name, exc, extra={"stage": tag})
            log.debug(traceback.format_exc(), extra={"stage": tag})
            return name, None, str(exc), fmt_dur(time.monotonic() - t)

    syft_pkgs = []
    with stage_ctx(f"vulnerability engines ({', '.join(tasks)}) in parallel", tag):
        with ThreadPoolExecutor(max_workers=len(tasks) or 1) as ex:
            for name, result, err, dur in ex.map(lambda kv: timed(*kv), tasks.items()):
                cov["engines"][name] = {"status": "ok" if err is None else "FAILED", "duration": dur,
                                        **({"error": err} if err else {})}
                if err is not None:
                    continue
                if name == "grype (packages)":
                    found, syft_pkgs, _ = result
                else:
                    found = result[0]
                findings += found
                log.info("%-17s %6d matches  (%s)", name, len(found), dur, extra={"stage": tag})

    for f in findings:
        f["repo"], f["revision"] = repo.name, repo.revision

    # components: SBOM packages + binary-identified libraries
    for p in syft_pkgs:
        for loc in p.get("locations") or [{}]:
            components.append({"repo": repo.name, "name": p.get("name", ""), "version": p.get("version", ""),
                               "type": p.get("type", ""), "source": "SBOM (syft)",
                               "path": mapper(loc.get("accessPath") or loc.get("path", "")),
                               "id": p.get("purl", "")})
    pkg_paths = {c["path"] for c in components}
    finding_count = Counter(f["path"] for f in findings)
    for b in st.pe:
        for c in b.components:
            components.append({"repo": repo.name, "name": c.product, "version": c.version, "type": "binary",
                               "source": c.rule.split(":")[0], "path": b.path,
                               "id": f"cpe:2.3:a:{c.vendor}:{c.product}:{c.version}"})
        d = b.to_dict()
        managed = any(s in b.path.lower() for s in ("site-packages/", "node_modules/", "dist-packages/"))
        d.update(repo=repo.name, sha256=sha.get(b.path, ""), kind=kind.get(b.path, ""),
                 findings=finding_count.get(b.path, 0),
                 review=(b.party == "third-party" and not b.components and not managed
                         and b.path not in pkg_paths
                         and "python software foundation" not in (b.company or "").lower()))
        binaries.append(d)
    cov["components"] = len({(c["name"], c["version"]) for c in components})

    if not args.keep_stage:
        shutil.rmtree(st.root, ignore_errors=True)
    cov["duration"] = fmt_dur(time.monotonic() - t0)
    return findings, components, binaries, cov


# ---------------------------------------------------------------------------
def snapshot(name: str):
    rec = os.environ.get("VULNSCAN_RECORD")
    if rec:
        Path(rec).mkdir(parents=True, exist_ok=True)
        console.save_svg(str(Path(rec) / f"{name}.svg"), title="vulnscan", clear=True)


def summarize(findings, coverage, eol, repo_names, run_problems=()) -> dict:
    """One summary model shared by the console output and the email.

    status_ok is True only when every repository was scanned by every engine, the
    databases were fresh and healthy and the self-test passed - anything else must
    never read as an all-clear."""
    per = defaultdict(Counter)
    kev_repo = defaultdict(set)
    p1_repo = Counter()
    for f in findings:
        per[f["repo"]][f["severity"]] += 1
        if f.get("kev"):
            kev_repo[f["repo"]].add(f["vuln_id"])
        if f["priority"] == "P1":
            p1_repo[f["repo"]] += 1
    problems, per_repo = list(run_problems), []
    for c in coverage:
        bad = [k for k, v in c.get("engines", {}).items() if v["status"] != "ok"]
        if c.get("error"):
            problems.append(f"{c['repo']}: {c['error']}")
        problems += [f"{c['repo']}: {b} failed" for b in bad]
        if c.get("archives_failed"):
            bad = bad + ["archives"]
            problems.append(f"{c['repo']}: {c['archives_failed']} archive(s) could not be (fully) extracted - "
                            f"their contents were NOT scanned")
        rev = str(c.get("revision") or "?")
        per_repo.append({"name": c["repo"], "revision": rev if rev in ("local", "?") else f"r{rev}",
                         "files": c.get("files", 0), "sev": per[c["repo"]], "kev": len(kev_repo[c["repo"]]),
                         "p1": p1_repo[c["repo"]], "ok": not c.get("error") and not bad,
                         "failed": bool(c.get("error")), "bad": bad})
    comp = defaultdict(lambda: {"ids": set(), "kev": set(), "files": set(), "sev": defaultdict(set),
                                "names": Counter()})
    for f in findings:
        c = comp[(f["component"].lower(), f["version"])]
        c["names"][f["component"]] += 1
        c["ids"].add(f["vuln_id"])
        c["files"].add((f["repo"], f["path"]))
        c["sev"][f["severity"]].add(f["vuln_id"])
        if f.get("kev"):
            c["kev"].add(f["vuln_id"])
    top = sorted(comp.items(), key=lambda kv: (-len(kv[1]["kev"]), -len(kv[1]["sev"]["CRITICAL"]),
                                               -len(kv[1]["sev"]["HIGH"]), -len(kv[1]["ids"])))
    kev_list, seen = [], set()
    for f in sorted((f for f in findings if f.get("kev")), key=lambda f: f["vuln_id"]):
        if f["vuln_id"] not in seen:
            seen.add(f["vuln_id"])
            kev_list.append({"id": f["vuln_id"], "component": f["component"], "version": f["version"],
                             "title": (f["title"] or f["description"] or "").split("\n")[0]})
    hard_eol = [e for e in eol if e["status"] == "End of life"]
    return {
        "repos": repo_names, "files": sum(r["files"] for r in per_repo), "total": len(findings),
        "sev": Counter(f["severity"] for f in findings), "p1": sum(p1_repo.values()),
        "kev": len(seen), "kev_list": kev_list, "eol": len({(e["product"], e["version"]) for e in hard_eol}),
        "eol_list": Counter(f"{e['product']} {e['version']}" for e in hard_eol).most_common(),
        "per_repo": per_repo, "status_ok": not problems, "problems": problems,
        "top_components": [{"name": c["names"].most_common(1)[0][0], "version": v, "vulns": len(c["ids"]),
                            "critical": len(c["sev"]["CRITICAL"]), "high": len(c["sev"]["HIGH"]),
                            "kev": len(c["kev"]), "files": len(c["files"])} for (_, v), c in top[:12]],
    }


def _n(value: int, style: str) -> Text:
    """Count cell: zero is dimmed so real numbers stand out."""
    return Text(f"{value:,}", style="grey42" if not value else style)


def final_summary(s: dict, report_path: str, evidence: str, duration: str):
    snapshot("scan")
    console.rule("[bold cyan]Results")
    tb = Table(box=box.SIMPLE_HEAVY, header_style="bold")
    tb.add_column("Repository", style="bold")
    tb.add_column("Rev", style="grey62")
    tb.add_column("Files", justify="right")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        tb.add_column(sev.title(), justify="right", style="bold red3" if sev == "CRITICAL" else SEV_STYLE[sev])
    tb.add_column("KEV", justify="right", style="bold red")
    tb.add_column("P1", justify="right")
    tb.add_column("Status")
    for r in s["per_repo"]:
        status = ("[bold red]FAILED[/]" if r["failed"] else
                  f"[yellow]incomplete ({', '.join(r['bad'])})[/]" if r["bad"] else "[ok]complete[/ok]")
        tb.add_row(r["name"], r["revision"], f"{r['files']:,}",
                   *(_n(r["sev"][k], "bold red3" if k == "CRITICAL" else SEV_STYLE[k])
                     for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")),
                   _n(r["kev"], "bold red"), _n(r["p1"], "bold"), status)
    console.print(tb)
    if s["top_components"]:
        t2 = Table(title="Highest-risk components", box=box.SIMPLE, header_style="bold", title_justify="left")
        for col, kw in [("Component", {}), ("Version", {"style": "grey62"}), ("Vulns", {"justify": "right"}),
                        ("Critical", {"justify": "right", "style": "bold red3"}),
                        ("High", {"justify": "right", "style": "red1"}),
                        ("KEV", {"justify": "right", "style": "bold red"}), ("Files", {"justify": "right"})]:
            t2.add_column(col, **kw)
        for c in s["top_components"]:
            t2.add_row(c["name"], c["version"], f"{c['vulns']:,}", _n(c["critical"], "bold red3"),
                       _n(c["high"], "red1"), _n(c["kev"], "bold red"), f"{c['files']:,}")
        console.print(t2)
    if s["eol_list"]:
        console.print("[bold]End-of-life:[/] " + ", ".join(f"{k} [muted]({v} files)[/muted]"
                                                            for k, v in s["eol_list"][:10]))
    if s["kev_list"]:
        ids = [k["id"] for k in s["kev_list"]]
        console.print(f"[kev] {len(ids)} actively exploited (CISA KEV) [/kev] " + ", ".join(ids[:15])
                      + (" …" if len(ids) > 15 else ""))
    console.print()
    console.print(Panel(Text.assemble(("Report    ", "bold"), (report_path, "cyan"), "\n",
                                      ("Evidence  ", "bold"), (evidence, "grey62"), "\n",
                                      ("Duration  ", "bold"), duration),
                        border_style="green", box=box.ROUNDED, expand=False))
    snapshot("results")


def host_path(p: Path) -> str:
    """Show paths relative to the mounted work dir (what the user sees on the host)."""
    try:
        return "./" + str(p.relative_to(WORK))
    except ValueError:
        return str(p)


# ---------------------------------------------------------------------------
def run_once(args, repos, notes, argv) -> int:
    started = datetime.now(UTC).astimezone()
    run_id = started.strftime("%Y%m%d-%H%M%S")
    sel_name = "all" if args.all and not args.path else "+".join(args.selected)
    if len(sel_name) > 60:
        sel_name = f"{len(args.selected)}-repos"
    evidence = args.output / "vulnscan-results" / f"{run_id}_{sel_name}"
    evidence.mkdir(parents=True, exist_ok=True)
    fh = add_logfile(evidence / "scan.log")
    args.accepted_gaps, gap_notes = load_accepted_gaps(WORK)  # re-read every run (scheduler)
    try:
        return _run(args, repos, list(notes) + gap_notes, argv, started, run_id, sel_name, evidence)
    except Exception as exc:  # noqa: BLE001 - a crash must be loud, never a silent non-report
        log.error("SCAN FAILED: %s", exc, extra={"stage": "main"})
        log.debug(traceback.format_exc(), extra={"stage": "main"})
        console.print(Panel(Text.assemble(("SCAN FAILED - no results. ", "bold"), str(exc), "\n",
                                          ("Log: ", "bold"), host_path(evidence / "scan.log")),
                            border_style="red", box=box.HEAVY, expand=False))
        if args.email:
            try:
                notify.send_failure(str(exc), {"run_id": run_id, "repos": args.selected,
                                               "started": started.strftime("%Y-%m-%d %H:%M %Z"),
                                               "evidence_dir": host_path(evidence),
                                               "command": "vulnscan " + " ".join(shlex.quote(a) for a in argv)})
            except Exception as mail_exc:  # noqa: BLE001
                log.error("failure email could not be sent either: %s", mail_exc, extra={"stage": "email"})
        return 3
    finally:
        remove_handler(fh)


def _run(args, repos, notes, argv, started, run_id, sel_name, evidence) -> int:
    out = args.output
    tools = scanners.tool_versions()
    banner(tools)
    for n in notes:
        log.info(n)
    log.info("repositories: %s  ·  engines: %s  ·  workers: %d%s", ", ".join(args.selected),
             ", ".join(args.engines), args.jobs, "  ·  OFFLINE" if args.offline else "")
    if not get_secret("SVN_USERNAME") and not args.offline and any(not repos[n].local for n in args.selected):
        log.warning("SVN_USERNAME not set - pass credentials with --env-file .env")

    t0 = time.monotonic()
    with stage_ctx("vulnerability databases", "db"):
        databases, run_problems = scanners.update_databases(args.offline)
    with stage_ctx("engine self-test (known-vulnerable canaries)", "selftest"):
        broken = scanners.selftest(evidence / "selftest", args.offline)
        run_problems += [f"self-test failed for {eng}: {why} - its results cannot be trusted"
                         for eng, why in broken.items()]
    for p in run_problems:
        log.warning(p, extra={"stage": "db"})

    all_findings, all_components, all_binaries, coverage = [], [], [], []
    for i, name in enumerate(args.selected, 1):
        repo = repos[name]
        console.rule(f"[bold cyan]{name}[/]  [grey50]({i}/{len(args.selected)})  {repo.url}[/]")
        try:
            f, c, b, cov = scan_repo(repo, args, evidence)
            all_findings += f
            all_components += c
            all_binaries += b
            coverage.append(cov)
        except Exception as exc:  # noqa: BLE001
            log.error("scan of %s failed: %s", name, exc, extra={"stage": f"repo:{name}"})
            log.debug(traceback.format_exc(), extra={"stage": f"repo:{name}"})
            coverage.append({"repo": name, "url": repo.url, "revision": repo.revision,
                             "engines": {}, "error": str(exc)})

    console.rule("[bold cyan]Report")
    with stage_ctx("merge, enrich & end-of-life analysis", "enrich"):
        raw = len(all_findings)
        merged = enrich.merge(all_findings)
        log.info("%d raw matches merged into %d findings", raw, len(merged), extra={"stage": "enrich"})
        enrich.enrich(merged)
        eol_input = all_components + [
            {"repo": b["repo"], "name": b["path"].rsplit("/", 1)[-1], "version": b.get("file_version", ""),
             "type": "binary", "path": b["path"]} for b in all_binaries
            if re.match(r"^(?:msvc[pr]|mfc|vcomp|atl)\d{2,3}u?d?\.dll$", b["path"].rsplit("/", 1)[-1], re.I)]
        eol, eol_problems = enrich.eol_status(eol_input, args.offline)
        run_problems += eol_problems
        per_file = Counter((f["repo"], f["path"]) for f in merged)
        for b in all_binaries:
            b["findings"] = per_file.get((b["repo"], b["path"]), 0)

    finished = datetime.now(UTC).astimezone()
    duration = fmt_dur(time.monotonic() - t0)
    report_path = out / f"vulnscan_{sel_name}_{run_id}.xlsx"
    meta = {
        "run_id": run_id, "started": started.strftime("%Y-%m-%d %H:%M %Z"),
        "finished": finished.strftime("%Y-%m-%d %H:%M %Z"), "duration": duration,
        "command": "vulnscan " + " ".join(shlex.quote(a) for a in argv),
        "evidence_dir": host_path(evidence),
        "repos": [{"name": n, "revision": repos[n].revision, "url": repos[n].url} for n in args.selected],
        "tools": {"vulnscan": __version__, **tools}, "databases": databases, "notes": list(run_problems),
        "incomplete": False,
    }
    summary = summarize(merged, coverage, eol, args.selected, run_problems)
    meta["incomplete"] = not summary["status_ok"]
    with stage_ctx(f"writing Excel report ({len(merged):,} findings)", "report"):
        report.Report(report_path).build(meta, merged, all_components, eol, all_binaries, coverage)
        log.info("report written: %s (%s)", host_path(report_path), fmt_size(report_path.stat().st_size),
                 extra={"stage": "report"})

    if args.sbom:
        with stage_ctx("CycloneDX SBOM", "sbom"):
            for cov in coverage:
                name = cov["repo"]
                if cov.get("error"):
                    log.warning("no SBOM for %s: scan failed", name, extra={"stage": "sbom"})
                    continue
                try:
                    doc = sbom.build(name, str(cov.get("revision", "")), cov.get("url", ""),
                                     evidence / name / "sbom.cyclonedx.json",
                                     [b for b in all_binaries if b["repo"] == name],
                                     [f for f in merged if f["repo"] == name], meta["tools"])
                    sbom.write(out / f"vulnscan_{name}_{run_id}.cdx.json", doc)
                except Exception as exc:  # noqa: BLE001 - the report exists; flag, do not abort
                    log.error("SBOM for %s failed: %s", name, exc, extra={"stage": "sbom"})
                    summary["problems"].append(f"{name}: SBOM could not be written ({exc})")
                    summary["status_ok"] = False
    try:
        final_summary(summary, host_path(report_path), host_path(evidence), duration)
    except Exception as exc:  # noqa: BLE001 - console rendering must never cost the email
        log.error("console summary failed: %s", exc)

    rc = 0
    if args.email:
        with stage_ctx("email", "email"):
            try:
                notify.send(summary, meta, report_path)
            except Exception as exc:  # noqa: BLE001
                log.error("email failed: %s", exc, extra={"stage": "email"})
                rc = 4
    if not summary["status_ok"]:
        console.print(Panel("\n".join(f"• {p}" for p in summary["problems"]),
                            title="[bold]⚠ SCAN INCOMPLETE - this is NOT an all-clear[/]",
                            border_style="yellow", box=box.HEAVY, expand=False))
        return 3
    gate = args.fail_on
    if gate != "none":
        sevs = ["critical", "high", "medium", "low"]
        hit = (any(f.get("kev") for f in merged) if gate == "kev" else
               any(f["priority"] == "P1" for f in merged) if gate == "p1" else
               any(f["priority"] in ("P1", "P2") for f in merged) if gate == "p2" else
               any(f["severity"].lower() in sevs[: sevs.index(gate) + 1] for f in merged))
        if hit:
            console.print(f"[bold red]✖ findings at or above '{gate}' - failing (--fail-on {gate})[/]")
            return 1
    return rc


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    setup_logging(verbose="-v" in argv or "--verbose" in argv)
    log.debug(drop_privileges(WORK))
    repos, notes = svn.load_repos(WORK)
    parser, args = parse(argv, repos)
    if args.list:
        list_repos(repos, notes)
        return 0
    if not args.selected:
        parser.print_help()
        console.print()
        list_repos(repos, notes)
        return 2
    out = args.output
    if not out.is_dir() or not os.access(out, os.W_OK):
        log.error("output folder %s is not a writable directory - mount one with -v \"$PWD:/work\"", out)
        return 2
    if args.email:
        try:
            notify.config()
        except notify.EmailConfigError as exc:
            log.error("--email: %s", exc)
            return 2
    if not args.schedule:
        return run_once(args, repos, notes, argv)

    # ---- scheduled mode: stay alive and scan on a cron schedule ------------
    try:
        cron = Cron(args.schedule)
    except ValueError as exc:
        log.error("--schedule: %s", exc)
        return 2
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    tz = time.strftime("%Z")
    if args.run_now:
        log.info("--run-now: starting an immediate scan", extra={"stage": "schedule"})
        _scheduled(args, repos, notes, argv)
    while not stop.is_set():
        nxt = cron.next_after(datetime.now())
        log.info("next scan %s %s (schedule '%s')", nxt.strftime("%a %Y-%m-%d %H:%M"), tz, args.schedule,
                 extra={"stage": "schedule"})
        while not stop.is_set() and datetime.now() < nxt:
            stop.wait(min(60.0, max(1.0, (nxt - datetime.now()).total_seconds())))
        if stop.is_set():
            break
        # pick up configuration changes between runs; --path folders live only in the arguments
        fresh, notes = svn.load_repos(WORK)
        fresh.update({n: r for n, r in repos.items() if r.local})
        repos = fresh
        if args.all:
            args.selected = sorted(n for n, r in repos.items() if not r.local) +                 [n for n in args.selected if repos.get(n) and repos[n].local]
        _scheduled(args, repos, notes, argv)
    log.info("scheduler stopped", extra={"stage": "schedule"})
    return 0


def _scheduled(args, repos, notes, argv):
    missing = [n for n in args.selected if n not in repos]
    if missing or not args.selected:
        why = (f"configured repositories disappeared: {', '.join(missing)}" if missing
               else "no repositories configured")
        log.error("%s - scheduled run NOT performed", why, extra={"stage": "schedule"})
        if args.email:
            try:
                notify.send_failure(f"{why} - check VULNSCAN_REPOS / vulnscan-repos.json", {
                    "run_id": datetime.now().strftime("%Y%m%d-%H%M%S"), "repos": args.selected or ["(none)"],
                    "started": datetime.now().strftime("%Y-%m-%d %H:%M"), "evidence_dir": "(none)",
                    "command": "vulnscan " + " ".join(shlex.quote(a) for a in argv)})
            except Exception as exc:  # noqa: BLE001
                log.error("failure email could not be sent: %s", exc, extra={"stage": "email"})
        return
    try:
        rc = run_once(args, repos, notes, argv)
        log.info("scheduled run finished (exit code %d)", rc, extra={"stage": "schedule"})
    except Exception as exc:  # noqa: BLE001 - never let one bad run kill the scheduler
        log.error("scheduled run crashed: %s", exc, extra={"stage": "schedule"})
        log.debug(traceback.format_exc(), extra={"stage": "schedule"})
