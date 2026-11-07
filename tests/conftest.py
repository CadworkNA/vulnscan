"""Shared test setup: isolate caches/work dirs and keep tests off the network."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Must be set before vulnscan modules are imported (paths are resolved at import).
_TMP = Path(tempfile.mkdtemp(prefix="vulnscan-tests-"))
os.environ.setdefault("VULNSCAN_CACHE", str(_TMP / "cache"))
os.environ.setdefault("VULNSCAN_WORK", str(_TMP / "work"))
os.environ.setdefault("VULNSCAN_RUN_AS_ROOT", "1")  # tests manage their own files; no privilege drop
(_TMP / "work").mkdir(parents=True, exist_ok=True)

import pytest  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
STAGE_ROOT = "/cache/stage/acme-cad-2.4"  # stage root recorded in the scanner fixtures


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith(("SMTP_", "SVN_", "VULNSCAN_REPOS", "VULNSCAN_SCHEDULE", "VULNSCAN_RECORD")):
            monkeypatch.delenv(k, raising=False)
