"""Logging, subprocess streaming and small helpers shared by all stages."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from rich.console import Console
from rich.text import Text
from rich.theme import Theme

log = logging.getLogger("vulnscan")

CACHE = Path(os.environ.get("VULNSCAN_CACHE", "/cache"))
DB_CACHE = CACHE / "db"
USER_AGENT = "vulnscan/1.0 (vulnerability scanner)"

THEME = Theme({
    "sev.critical": "bold white on red3", "sev.high": "bold red1", "sev.medium": "dark_orange",
    "sev.low": "yellow3", "sev.negligible": "grey50", "sev.unknown": "grey50",
    "kev": "bold white on dark_red", "ok": "green3", "muted": "grey50", "accent": "cyan",
})
# soft_wrap: never hard-wrap log lines, so CI logs stay grep-able.
_width = int(os.environ.get("COLUMNS") or 0) or (None if os.isatty(1) else 160)
# VULNSCAN_RECORD=<dir>: also capture the console as SVG screenshots (used for the README)
console = Console(theme=THEME, soft_wrap=True, highlight=False, width=_width,
                  record=bool(os.environ.get("VULNSCAN_RECORD")),
                  force_terminal=True if os.environ.get("FORCE_COLOR") else None)

_STAGE_COLORS = ["cyan", "magenta", "green3", "dodger_blue1", "orchid", "turquoise2",
                 "gold3", "spring_green2", "medium_purple1", "deep_sky_blue1"]
_LEVEL_STYLE = {"DEBUG": "grey50", "INFO": "", "WARNING": "bold yellow", "ERROR": "bold red",
                "CRITICAL": "bold white on red"}
# Glyphs without an emoji presentation (no U+26A0, U+2714, U+2716, U+25B6): terminals render
# emoji-capable symbols two cells wide, which eats the following space and shifts the line.
MARK_WARN, MARK_ERROR, MARK_START, MARK_DONE = "▲", "✗", "▸", "✓"
_LEVEL_MARK = {"WARNING": MARK_WARN, "ERROR": MARK_ERROR, "CRITICAL": MARK_ERROR, "DEBUG": "·"}
_T0 = time.monotonic()
_STAGE_MIN, _STAGE_MAX = 16, 30
_stage_width = _STAGE_MIN


def set_stage_width(repo_names) -> None:
    """Size the stage column once for the whole run, from the longest tag it will show
    ('stage:<repo>'), so the message column does not jump between repository sections."""
    global _stage_width
    longest = max((len(f"stage:{n}") for n in repo_names), default=0)
    _stage_width = max(_STAGE_MIN, min(_STAGE_MAX, longest))


def _fit(text: str, width: int) -> str:
    return f"{text:<{width}}" if len(text) <= width else text[: width - 1] + "…"


def fmt_dur(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


def fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def progress_text(done: float, total: float, elapsed: float, *, size: bool = False, rate: bool = False) -> str:
    """'42.0% · 1,234 / 2,938 · 12.3 MB/s · ETA 1:20' - done and total are counts or bytes."""
    fmt = fmt_size if size else (lambda v: f"{int(v):,}")
    if total <= 0:
        return f"{fmt(done)} so far"
    done = min(done, total)  # never report past the end
    parts = [f"{100.0 * done / total:5.1f}%", f"{fmt(done)} / {fmt(total)}"]
    if rate and elapsed > 0:
        parts.append(f"{fmt_size(done / elapsed)}/s" if size else f"{done / elapsed:,.0f}/s")
    if 0 < done < total and elapsed > 1:
        parts.append(f"ETA {fmt_dur(elapsed * (total - done) / done)}")
    return "  ·  ".join(parts)


def _stage_of(record: logging.LogRecord) -> str:
    return getattr(record, "stage", "") or "main"


class RichLineHandler(logging.Handler):
    """One coloured line per record: time, elapsed, level mark, stage, message."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            stage = _stage_of(record)
            color = _STAGE_COLORS[sum(map(ord, stage.split(":")[0])) % len(_STAGE_COLORS)]
            lvl = record.levelname
            t = Text()
            t.append(time.strftime("%H:%M:%S", time.localtime(record.created)), "grey50")
            t.append(f" {fmt_dur(time.monotonic() - _T0):>7}  ", "grey42")
            t.append(f"{_LEVEL_MARK.get(lvl, ' ')} ", _LEVEL_STYLE.get(lvl, ""))
            t.append(_fit(stage, _stage_width), color)
            t.append("  " + record.getMessage(), _LEVEL_STYLE.get(lvl, ""))
            if record.exc_info:
                t.append("\n" + logging.Formatter().formatException(record.exc_info), "red")
            console.print(t)
        except Exception:  # noqa: BLE001
            self.handleError(record)


class _FileFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.created))
        line = (f"{ts} +{fmt_dur(time.monotonic() - _T0):>8} {record.levelname:<7} "
                f"[{_stage_of(record)}] {record.getMessage()}")
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def setup_logging(verbose: bool) -> None:
    root = logging.getLogger("vulnscan")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()
    root.propagate = False
    h = RichLineHandler()
    h.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.addHandler(h)


def add_logfile(logfile: Path) -> logging.Handler:
    logfile.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(logfile, encoding="utf-8")
    fh.setLevel(logging.DEBUG)  # the log file always gets everything
    fh.setFormatter(_FileFormatter())
    logging.getLogger("vulnscan").addHandler(fh)
    return fh


def remove_handler(h: logging.Handler) -> None:
    logging.getLogger("vulnscan").removeHandler(h)
    h.close()


@contextmanager
def stage(name: str, tag: str = ""):
    """Log start/end + duration of a pipeline stage."""
    extra = {"stage": tag} if tag else None
    log.info("%s %s", MARK_START, name, extra=extra)
    t0 = time.monotonic()
    try:
        yield
    except Exception:
        log.error("%s failed after %s", name, fmt_dur(time.monotonic() - t0), extra=extra)
        raise
    log.info("%s %s done in %s", MARK_DONE, name, fmt_dur(time.monotonic() - t0), extra=extra)


def run_streamed(cmd: list[str], tag: str, *, cwd: str | Path | None = None,
                 env: dict | None = None, stdin_data: str | None = None,
                 line_callback=None, quiet_patterns: tuple[str, ...] = (),
                 heartbeat: float = 30.0) -> int:
    """Run a command, streaming its combined output line by line into the log.

    Every line goes to the log file (DEBUG); lines that look like warnings or
    errors are also shown live. A heartbeat line is printed when the tool stays
    silent for a while, so a long-running scan visibly stays alive.
    """
    log.debug("$ %s", " ".join(cmd), extra={"stage": tag})
    full_env = subprocess_env()
    if env:
        full_env.update(env)
    proc = subprocess.Popen(cmd, cwd=cwd, env=full_env, text=True, errors="replace",
                            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
    if stdin_data is not None:
        proc.stdin.write(stdin_data)
        proc.stdin.close()

    t0 = time.monotonic()
    last = [t0]
    done = threading.Event()

    def beat():
        while not done.wait(5):
            if time.monotonic() - last[0] >= heartbeat:
                log.info("… still running (%s elapsed)", fmt_dur(time.monotonic() - t0),
                         extra={"stage": tag})
                last[0] = time.monotonic()

    threading.Thread(target=beat, daemon=True).start()
    try:
        for raw in proc.stdout:
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            if line_callback and line_callback(line):
                last[0] = time.monotonic()
                continue
            low = line.lower()
            if any(p in low for p in quiet_patterns):
                log.debug(line, extra={"stage": tag})
            elif any(w in low for w in ("error", "fatal", "panic", "traceback")):
                log.warning(line, extra={"stage": tag})
                last[0] = time.monotonic()
            elif "warn" in low:
                log.info(line, extra={"stage": tag})
                last[0] = time.monotonic()
            else:
                log.debug(line, extra={"stage": tag})
        rc = proc.wait()
    finally:
        done.set()
    log.debug("exit code %s after %s", rc, fmt_dur(time.monotonic() - t0), extra={"stage": tag})
    return rc


SERVICE_UID = 10001  # the image's unprivileged 'vulnscan' user


def drop_privileges(work: Path) -> str:
    """Never scan untrusted content as root. Started as root (the image default), take
    ownership of the cache, then permanently switch to the owner of the mounted work
    folder (so reports belong to the host user), or to the unprivileged service user.
    Returns a short description for the log."""
    if os.geteuid() != 0:
        return f"running as uid {os.geteuid()}"
    if os.environ.get("VULNSCAN_RUN_AS_ROOT") == "1":
        return "running as root (VULNSCAN_RUN_AS_ROOT=1)"
    try:
        st = work.stat()
        uid, gid = (st.st_uid, st.st_gid) if st.st_uid != 0 else (SERVICE_UID, SERVICE_UID)
        if st.st_uid == 0 and not st.st_mode & 0o002:
            # e.g. ./reports created by Docker as root on a Linux host: hand that folder
            # (not its contents) to the service user so reports can be written
            os.chown(work, uid, gid)
    except OSError:
        uid, gid = SERVICE_UID, SERVICE_UID
    CACHE.mkdir(parents=True, exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(CACHE):
        for name in [dirpath, *(os.path.join(dirpath, n) for n in dirnames + filenames)]:
            try:
                s = os.lstat(name)
                if s.st_uid != uid or s.st_gid != gid:
                    os.lchown(name, uid, gid)
            except OSError:
                pass
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if os.access(work, os.W_OK):
        return f"running as uid {uid}"
    return f"running as uid {uid} - WARNING: {work} is not writable for it"


def get_secret(name: str, default: str = "") -> str:
    """Value of env var NAME, or the contents of the file named by NAME_FILE
    (Docker/Compose secrets convention: NAME_FILE=/run/secrets/name)."""
    val = os.environ.get(name)
    if val:
        return val
    path = os.environ.get(f"{name}_FILE")
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            log.warning("cannot read %s_FILE (%s): %s", name, path, exc.strerror)
    return default


def subprocess_env() -> dict:
    """Environment for external tools: without model provider keys or the GitHub token, which only the upgrade
    advice uses and which must only reach their own service (see SECURITY.md)."""
    return {k: v for k, v in os.environ.items()
            if not (k.endswith(("_API_KEY", "_API_KEY_FILE")) or k in ("GITHUB_TOKEN", "GITHUB_TOKEN_FILE"))}


def capture(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=subprocess_env()).stdout.strip()
    except Exception as exc:  # noqa: BLE001
        return f"unavailable ({exc})"


def http_get(url: str, timeout: int = 120) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-HTTPS URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310 - https enforced above
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read()


class NotFound(Exception):
    """The server answered 404: the resource does not exist (as opposed to being unreachable)."""


def cached_download(url: str, dest: Path, max_age_h: float, offline: bool) -> Path | None:
    """Download url to dest unless a fresh-enough copy exists. Returns None if unavailable."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fresh = dest.exists() and (time.time() - dest.stat().st_mtime) < max_age_h * 3600
    if fresh or (offline and dest.exists()):
        log.debug("using cached %s", dest.name)
        return dest
    if offline:
        log.warning("offline mode and no cached copy of %s", url)
        return None
    for attempt in range(1, 4):
        try:
            data = http_get(url)
            tmp = dest.with_suffix(dest.suffix + ".tmp")
            tmp.write_bytes(data)
            tmp.replace(dest)
            log.debug("downloaded %s (%s)", url, fmt_size(len(data)))
            return dest
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise NotFound(url) from None
            log.debug("download attempt %d of %s failed: %s", attempt, url, exc)
            time.sleep(2 * attempt)
        except Exception as exc:  # noqa: BLE001
            log.debug("download attempt %d of %s failed: %s", attempt, url, exc)
            time.sleep(2 * attempt)
    if dest.exists():
        log.warning("download of %s failed - using stale cached copy", url)
        return dest
    log.warning("download of %s failed", url)
    return None


def load_json(path: Path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:  # noqa: BLE001
        log.warning("could not read %s: %s", path, exc)
        return default
