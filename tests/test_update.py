"""Start-up check for a newer release: advisory only, never fails or blocks a run."""
from __future__ import annotations

import json
import logging
import os
import time

import pytest

from vulnscan import update


def _github(monkeypatch, tag="v1.2.0", calls=None):
    def fake_get(url, timeout=120):
        assert url == update.LATEST_URL and timeout == update.TIMEOUT_S
        if calls is not None:
            calls.append(url)
        if isinstance(tag, Exception):
            raise tag
        return json.dumps({"tag_name": tag}).encode()
    monkeypatch.setattr(update, "http_get", fake_get)


@pytest.mark.parametrize(("current", "latest", "newer"), [
    ("1.1.0", "v1.2.0", True), ("1.1.0", "v1.1.1", True), ("1.9.0", "v2.0.0", True), ("1.1.0", "v1.10.0", True),
    ("1.1.0", "v1.1.0", False), ("1.2.0", "v1.1.9", False), ("1.1.0", "v2.0.0-rc1", False), ("dev", "v9.0.0", False),
])
def test_message_only_for_a_newer_release(current, latest, newer):
    assert (update.message(current, latest) is not None) is newer


def test_message_says_how_to_update():
    msg = update.message("1.1.0", "v2.0.1")
    assert "2.0.1 is available (this is 1.1.0)" in msg
    assert "podman pull ghcr.io/cadworkna/vulnscan:2" in msg
    assert msg.endswith("/releases/tag/v2.0.1")


def test_latest_release_is_cached_for_a_day(tmp_path, monkeypatch):
    calls = []
    _github(monkeypatch, "v1.2.0", calls)
    cache = tmp_path / "latest.json"
    assert update.latest_release(cache) == "v1.2.0"
    assert update.latest_release(cache) == "v1.2.0" and len(calls) == 1
    old = time.time() - 25 * 3600
    os.utime(cache, (old, old))
    _github(monkeypatch, "v1.3.0", calls)
    assert update.latest_release(cache) == "v1.3.0" and len(calls) == 2


def test_unexpected_tag_is_rejected_and_not_cached(tmp_path, monkeypatch):
    _github(monkeypatch, "<script>")
    with pytest.raises(ValueError):
        update.latest_release(tmp_path / "latest.json")
    assert not (tmp_path / "latest.json").exists()


@pytest.mark.parametrize("flag", ["0", "false", "off"])
def test_disabled_by_offline_or_env(monkeypatch, flag):
    monkeypatch.setenv("VULNSCAN_UPDATE_CHECK", "1")
    assert update.enabled(offline=False) and not update.enabled(offline=True)
    monkeypatch.setenv("VULNSCAN_UPDATE_CHECK", flag)
    assert not update.enabled(offline=False)


class _Records(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def caplog():
    """vulnscan's logger does not propagate, so collect its records directly."""
    logger, handler = logging.getLogger("vulnscan"), _Records()
    level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    yield handler
    logger.removeHandler(handler)
    logger.setLevel(level)


def _check(monkeypatch, tmp_path, caplog, tag, current="1.1.0"):
    monkeypatch.setenv("VULNSCAN_UPDATE_CHECK", "1")
    monkeypatch.setattr(update, "CACHE_FILE", tmp_path / "latest.json")
    _github(monkeypatch, tag)
    update.UpdateCheck(current, offline=False).report()
    return [r for r in caplog.records if getattr(r, "stage", None) == "update"]


def test_newer_release_logs_a_warning(monkeypatch, tmp_path, caplog):
    recs = _check(monkeypatch, tmp_path, caplog, "v1.2.0")
    assert [r.levelno for r in recs] == [logging.WARNING] and "1.2.0 is available" in recs[0].getMessage()


def test_current_release_is_silent(monkeypatch, tmp_path, caplog):
    assert _check(monkeypatch, tmp_path, caplog, "v1.1.0") == []


def test_network_failure_is_only_a_debug_line(monkeypatch, tmp_path, caplog):
    recs = _check(monkeypatch, tmp_path, caplog, OSError("rate limited"))
    assert [r.levelno for r in recs] == [logging.DEBUG] and "rate limited" in recs[0].getMessage()


def test_offline_does_not_touch_the_network(monkeypatch, caplog):
    monkeypatch.setattr(update, "http_get", lambda *a, **k: pytest.fail("network used"))
    update.UpdateCheck("1.1.0", offline=True).report()
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)
