"""Fuzz target: analysis of a hostile binary (PE version resource, identification rules, embedded signatures).

The first input byte picks the file name (identification rules match on it), the rest is the file content. The
analysis must never raise, hang or crash on any input, and must always return a well-formed result: a parse
failure is recorded in PEInfo.error, never an exception that would abort the scan.
"""
from __future__ import annotations

import os
import sys
import tempfile

import atheris

with atheris.instrument_imports(include=["vulnscan", "pefile"]):
    from vulnscan import pe, stage

from seeds import NAMES

TMP = tempfile.mkdtemp(prefix="fuzz-binary-", dir="/dev/shm" if os.path.isdir("/dev/shm") else None)
TARGET = os.path.join(TMP, "target")


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    name, content = NAMES[data[0] % len(NAMES)], data[1:]
    with open(TARGET, "wb") as fh:
        fh.write(content)
    info = stage._analyze_job((TARGET, name, len(content), "pe"))
    assert isinstance(info, pe.PEInfo)
    assert isinstance(info.error, str) and len(info.error) <= 300, info.error
    for c in info.components:
        assert c.vendor and c.product and c.version and c.rule, c
        assert all(isinstance(x, str) for x in (c.vendor, c.product, c.version, c.rule)), c
        assert c.confidence in ("high", "medium"), c
    assert info.to_dict()["party"] in ("first-party", "microsoft", "third-party", "unknown")


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
