"""Fuzz target: extraction paths built from hostile archive member names.

Every archive is extracted into a folder derived from its path in the stage. Whatever names an archive carries
(`..`, msiextract's `.:` prefixes, absolute paths, odd Unicode), extraction_dir() must either refuse (None) or
return a folder that resolves inside <stage>/archives. Display paths must always be computable.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports(include=["vulnscan"]):
    from vulnscan import scanners, stage

STAGE = Path(tempfile.mkdtemp(prefix="fuzz-paths-", dir="/dev/shm" if os.path.isdir("/dev/shm") else None))
(STAGE / "files").mkdir()
(STAGE / "archives").mkdir()
ARCHIVES = (STAGE / "archives").resolve()
MAPPER = scanners.PathMapper(STAGE)


def TestOneInput(data: bytes) -> None:
    # A path as os.walk would produce it from extracted names: decoded leniently, never containing NUL.
    rel = data.decode("utf-8", "replace").replace("\0", "")
    abs_path = os.path.join(STAGE, rel)
    out = stage.extraction_dir(STAGE, abs_path)
    if out is not None:
        assert out.resolve().is_relative_to(ARCHIVES), (rel, out)
    assert isinstance(stage.display_path(STAGE, abs_path), str)
    assert isinstance(MAPPER(abs_path), str)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
