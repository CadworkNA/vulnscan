"""SVN repository discovery and cached checkout/update."""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

from .util import CACHE, fmt_dur, fmt_size, get_secret, log, progress_text, run_streamed

SVN_CACHE = CACHE / "svn"


@dataclass
class Repo:
    name: str
    url: str
    checkout: Path = None  # type: ignore[assignment]
    revision: str = ""
    last_changed_rev: str = ""
    last_changed_date: str = ""
    local: bool = False  # a plain local folder (--path), no SVN

    def __post_init__(self):
        if self.checkout is None:
            self.checkout = SVN_CACHE / self.name


def _wc_url(wc: Path) -> str | None:
    """Read the repository URL of a working copy straight from wc.db (read-only,
    never touches the user's working copy)."""
    db = wc / ".svn" / "wc.db"
    if not db.exists():
        return None
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
        row = con.execute(
            "SELECT r.root, n.repos_path FROM NODES n JOIN REPOSITORY r ON n.repos_id = r.id "
            "WHERE n.local_relpath = '' ORDER BY n.op_depth LIMIT 1").fetchone()
        con.close()
    except sqlite3.Error as exc:
        log.warning("cannot read %s: %s", db, exc)
        return None
    if not row:
        return None
    root, path = row
    return f"{root.rstrip('/')}/{path}".rstrip("/")


NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def parse_repo_spec(spec: str) -> dict[str, str]:
    """'name=url, name2=url2' (commas, semicolons or whitespace) or a JSON object."""
    spec = spec.strip()
    if not spec:
        return {}
    if spec.startswith("{"):
        return {str(k): str(v) for k, v in json.loads(spec).items()}
    out = {}
    for item in re.split(r"[,;\s]+", spec):
        if item:
            name, sep, url = item.partition("=")
            if not sep:
                raise ValueError(f"expected name=url, got {item!r}")
            out[name.strip()] = url.strip()
    return out


def load_repos(work: Path) -> tuple[dict[str, Repo], list[str]]:
    """Repository list - kept outside the image (URLs are internal), in increasing priority:
       1. SVN working copies found directly inside the mounted work folder
       2. VULNSCAN_REPOS environment variable (e.g. from --env-file .env)
       3. <work>/vulnscan-repos.json  ({"name": "https://svn/url", ...})
    Returns (repos, provenance notes)."""
    repos: dict[str, Repo] = {}
    notes = []

    def add(name: str, url: str, origin: str):
        if not NAME_RE.match(name):
            notes.append(f"ignored repo with invalid name {name!r} ({origin})")
            return
        if not re.match(r"^(https?|svn|svn\+ssh)://[^\s]+$", url):
            notes.append(f"ignored repo {name}: unsupported URL ({origin})")
            return
        repos[name] = Repo(name=name, url=url.rstrip("/"))

    if work.is_dir():
        for d in sorted(p for p in work.iterdir() if p.is_dir()):
            url = _wc_url(d)
            if url:
                add(d.name, url, f"working copy {d.name}")
    env_spec = get_secret("VULNSCAN_REPOS")
    if env_spec.strip():
        try:
            for name, url in parse_repo_spec(env_spec).items():
                add(name, url, "VULNSCAN_REPOS")
        except ValueError as exc:
            notes.append(f"could not parse VULNSCAN_REPOS: {exc}")
    override = work / "vulnscan-repos.json"
    if override.is_file():
        try:
            for name, url in json.loads(override.read_text(encoding="utf-8")).items():
                add(name, str(url), str(override))
            notes.append(f"loaded repository overrides from {override.name}")
        except (ValueError, AttributeError) as exc:
            notes.append(f"could not parse {override.name}: {exc}")
    return repos, notes


def _auth_args() -> tuple[list[str], str | None]:
    args = ["--non-interactive", "--no-auth-cache"]
    user = get_secret("SVN_USERNAME").strip()
    pwd = get_secret("SVN_PASSWORD")
    stdin = None
    if user:
        args += ["--username", user]
    if pwd:
        args += ["--password-from-stdin"]
        stdin = pwd
    if os.environ.get("SVN_TRUST_SERVER_CERT", "0").strip() in ("1", "true", "yes"):
        args += ["--trust-server-cert-failures", "unknown-ca,cn-mismatch,expired,not-yet-valid,other"]
    return args, stdin


def _info(path_or_url: str, item: str) -> str:
    args, stdin = _auth_args()
    res = subprocess.run(["svn", "info", "--show-item", item, *args, path_or_url],
                         input=stdin, capture_output=True, text=True)
    return res.stdout.strip()


def parse_listing(xml_text: str) -> dict[str, int]:
    """{relative path: size} of every file in `svn list -R --xml` output (directories skipped)."""
    # The XML is produced by the local svn client, which escapes every name it prints.
    root = ElementTree.fromstring(xml_text)  # noqa: S314
    sizes = {}
    for entry in root.iter("entry"):
        name, size = entry.findtext("name"), entry.findtext("size")
        if entry.get("kind") == "file" and name and size and size.isdigit():
            sizes[name] = int(size)
    return sizes


def _remote_listing(repo: Repo, args: list[str], stdin: str | None) -> dict[str, int] | None:
    """Size of every file in the repository, for checkout progress. Display only: any
    failure just means progress is reported without a total."""
    try:
        res = subprocess.run(["svn", "list", "-R", "--xml", *args, repo.url], input=stdin,
                             capture_output=True, text=True, errors="replace", timeout=1800)
        return parse_listing(res.stdout) if res.returncode == 0 else None
    except (subprocess.TimeoutExpired, ElementTree.ParseError, OSError) as exc:
        log.debug("repository listing for progress failed: %s", exc, extra={"stage": f"svn:{repo.name}"})
        return None


class CheckoutProgress:
    """Checkout progress from svn's 'A <path>' lines.

    svn announces a file before it is written to the working copy, so sizes cannot be read
    from disk; they come from the repository listing, which runs in parallel with the
    checkout. Directories are not files: only listed paths count towards the totals."""

    def __init__(self, wc: Path, tag: str, every: float = 10.0):
        self.wc, self.tag, self.every = str(wc), tag, every
        self.sizes: dict[str, int] | None = None  # set by the listing thread
        self.pending: list[str] = []  # files announced before the listing arrived
        self.files = self.bytes = 0
        self.t0 = self.last = time.monotonic()

    def _count(self, rel: str) -> None:
        size = self.sizes.get(rel) if self.sizes is not None else None
        if size is not None:
            self.files += 1
            self.bytes += size

    def added(self, path: str) -> None:
        rel = os.path.relpath(path, self.wc).replace(os.sep, "/")
        if self.sizes is None:
            self.pending.append(rel)
            return
        if self.pending:
            for p in self.pending:
                self._count(p)
            self.pending = []
        self._count(rel)

    def text(self) -> str:
        elapsed = time.monotonic() - self.t0
        if self.sizes is None:
            return (f"{len(self.pending):,} entries received  ·  {fmt_dur(elapsed)} elapsed  "
                    f"(measuring repository size…)")
        total_bytes, total_files = sum(self.sizes.values()), len(self.sizes)
        return (f"{progress_text(self.bytes, total_bytes, elapsed, size=True, rate=True)}  ·  "
                f"{min(self.files, total_files):,} / {total_files:,} files")

    def tick(self) -> None:
        now = time.monotonic()
        if now - self.last >= self.every:
            self.last = now
            log.info(self.text(), extra={"stage": self.tag})


def sync(repo: Repo, update: bool = True) -> None:
    """Checkout (first run) or update (later runs) the repo into the cache volume."""
    wc = repo.checkout
    args, stdin = _auth_args()
    tag = {"stage": f"svn:{repo.name}"}
    existing_url = ""
    if (wc / ".svn").exists():
        existing_url = _info(str(wc), "url")
        if not existing_url:
            # e.g. the container was killed mid checkout/update: the working copy is locked
            log.warning("cached checkout is not usable - running svn cleanup", extra=tag)
            run_streamed(["svn", "cleanup", *args, str(wc)], f"svn:{repo.name}", stdin_data=stdin)
            existing_url = _info(str(wc), "url")
        if not existing_url and update:
            log.warning("cached checkout is broken beyond cleanup - discarding it and checking out again", extra=tag)
            shutil.rmtree(wc)
    elif wc.exists() and any(wc.iterdir()) and update:
        log.warning("cache folder %s holds no working copy - discarding it", wc, extra=tag)
        shutil.rmtree(wc)

    if not existing_url and not update:
        raise RuntimeError("no usable cached checkout, and --offline/--no-update forbids checking out")

    if existing_url and existing_url.rstrip("/") != repo.url.rstrip("/"):
        if not update:
            raise RuntimeError(f"cached checkout points to {existing_url}, not {repo.url}, "
                               f"and --offline/--no-update forbids checking out again")
        log.warning("cached checkout %s points to %s, expected %s - re-checking out",
                    wc, existing_url, repo.url, extra=tag)
        shutil.rmtree(wc)
        existing_url = ""

    counts = {"A": 0, "U": 0, "D": 0, "G": 0, "C": 0, "E": 0, "R": 0}
    t0 = time.monotonic()
    last_report = [t0]
    line_re = re.compile(r"^([AUDGCER ])([AUDGCER ]?)\s+(\S.*)$")
    progress: CheckoutProgress | None = None  # fresh checkouts only

    def on_line(line: str) -> bool:
        m = line_re.match(line)
        if not m:
            return False
        key = m.group(1) if m.group(1) != " " else "U"
        counts[key] = counts.get(key, 0) + 1
        log.debug(line, extra=tag)
        if progress is not None:
            if key == "A":
                progress.added(m.group(3))
            progress.tick()
        elif time.monotonic() - last_report[0] >= 10:
            last_report[0] = time.monotonic()
            log.info("%s added, %s updated, %s deleted so far  ·  %s elapsed", f"{counts['A']:,}",
                     f"{counts['U'] + counts['G']:,}", f"{counts['D']:,}",
                     fmt_dur(last_report[0] - t0), extra=tag)
        return True

    if existing_url:
        if update:
            log.info("updating cached checkout %s", wc, extra={"stage": f"svn:{repo.name}"})
            run_streamed(["svn", "cleanup", *args, str(wc)], f"svn:{repo.name}", stdin_data=stdin)
            rc = run_streamed(["svn", "update", "--set-depth", "infinity", "--force", "--accept",
                               "theirs-full", *args, str(wc)],
                              f"svn:{repo.name}", stdin_data=stdin, line_callback=on_line)
            if rc != 0:
                raise RuntimeError(f"svn update failed for {repo.name} (exit {rc})")
            # Make sure the cache is pristine: revert local mods, drop unversioned files.
            run_streamed(["svn", "revert", "-R", *args, str(wc)], f"svn:{repo.name}", stdin_data=stdin)
            run_streamed(["svn", "cleanup", "--remove-unversioned", "--remove-ignored", *args, str(wc)],
                         f"svn:{repo.name}", stdin_data=stdin)
        else:
            log.info("--no-update: scanning cached checkout as-is", extra={"stage": f"svn:{repo.name}"})
    else:
        log.info("fresh checkout of %s -> %s (first run can take a long time)",
                 repo.url, wc, extra={"stage": f"svn:{repo.name}"})
        wc.parent.mkdir(parents=True, exist_ok=True)
        progress = CheckoutProgress(wc, f"svn:{repo.name}")

        def measure():
            sizes = _remote_listing(repo, args, stdin)
            if sizes is not None:
                log.info("repository holds %s files, %s", f"{len(sizes):,}", fmt_size(sum(sizes.values())),
                         extra=tag)
                progress.sizes = sizes
            else:
                log.info("repository size unknown - progress is shown without a total", extra=tag)

        measurer = threading.Thread(target=measure, daemon=True)
        measurer.start()
        rc = run_streamed(["svn", "checkout", *args, repo.url, str(wc)], f"svn:{repo.name}",
                          stdin_data=stdin, line_callback=on_line)
        if rc != 0:
            raise RuntimeError(f"svn checkout failed for {repo.name} (exit {rc})")
        measurer.join(timeout=5)

    repo.revision = _info(str(wc), "revision")
    repo.last_changed_rev = _info(str(wc), "last-changed-revision")
    repo.last_changed_date = _info(str(wc), "last-changed-date")
    log.info("at revision r%s (last changed r%s on %s) - %d added, %d updated, %d deleted",
             repo.revision, repo.last_changed_rev, repo.last_changed_date,
             counts["A"], counts["U"] + counts["G"], counts["D"], extra={"stage": f"svn:{repo.name}"})
