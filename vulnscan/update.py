"""Check on start whether a newer vulnscan release exists, and say so.

Advisory only: the check never fails or slows a scan. Any problem (offline, rate limit,
unexpected answer) is logged to the log file and otherwise ignored. The answer is cached
for a day in the cache volume, so scheduled runs do not ask GitHub every time."""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

from .util import DB_CACHE, http_get, log

REPO = "CadworkNA/vulnscan"
LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"  # stable releases only, no drafts/prereleases
IMAGE = "ghcr.io/cadworkna/vulnscan"
CACHE_FILE = DB_CACHE / "vulnscan-latest-release.json"
MAX_AGE_H = 24
TIMEOUT_S = 5
_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def parse(version: str) -> tuple[int, int, int] | None:
    """(major, minor, patch) of a plain release version; None for anything else (prereleases too)."""
    m = _VERSION.match((version or "").strip())
    return tuple(int(g) for g in m.groups()) if m else None  # type: ignore[return-value]


def enabled(offline: bool) -> bool:
    flag = os.environ.get("VULNSCAN_UPDATE_CHECK", "1").strip().lower()
    return not offline and flag not in ("0", "false", "no", "off")


def latest_release(cache: Path | None = None) -> str | None:
    """Tag of the latest release, e.g. 'v1.2.0', from a fresh cache or from GitHub."""
    cache = cache or CACHE_FILE
    try:
        if time.time() - cache.stat().st_mtime < MAX_AGE_H * 3600:
            return json.loads(cache.read_text(encoding="utf-8"))["tag"]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    tag = json.loads(http_get(LATEST_URL, timeout=TIMEOUT_S))["tag_name"]
    if not parse(tag):
        raise ValueError(f"unexpected release tag {tag!r}")
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"tag": tag}), encoding="utf-8")
    except OSError:
        pass  # caching is an optimisation
    return tag


def message(current: str, latest: str) -> str | None:
    """Warning text when `latest` is newer than `current`, else None."""
    cur, new = parse(current), parse(latest)
    if not cur or not new or new <= cur:
        return None
    tag = latest if latest.startswith("v") else f"v{latest}"
    return (f"vulnscan {tag[1:]} is available (this is {current})  ·  update: podman pull {IMAGE}:{new[0]}  ·  "
            f"release notes: https://github.com/{REPO}/releases/tag/{tag}")


class UpdateCheck:
    """Runs the check in the background; report() logs the result, waiting at most `wait` s."""

    def __init__(self, current: str, offline: bool):
        self.current, self.result = current, None
        self.thread = None
        if enabled(offline):
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()
        else:
            log.debug("update check skipped (offline or VULNSCAN_UPDATE_CHECK=0)", extra={"stage": "update"})

    def _run(self) -> None:
        try:
            self.result = message(self.current, latest_release())
        except Exception as exc:  # noqa: BLE001 - advisory: never let it affect the scan
            log.debug("update check failed: %s", exc, extra={"stage": "update"})

    def report(self, wait: float = TIMEOUT_S) -> None:
        if self.thread is None:
            return
        self.thread.join(timeout=wait)
        if self.result:
            log.warning(self.result, extra={"stage": "update"})
