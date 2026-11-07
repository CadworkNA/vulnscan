# vulnscan

Vulnerability scanner for shipped files; everything runs in one container. The [README](README.md) is the reference
for usage, architecture (Development section) and releases; this file lists what is easy to get wrong.

## Principles

- **Fail closed.** A run is only *complete* if every repository was scanned by every engine with current data and
  passing self-tests. Any error, missing/truncated/malformed scanner output or skipped content must surface as
  *incomplete* (exit code 3), never as an all-clear. Do not swallow exceptions or default to empty results.
- **Untrusted input.** Scanned files are hostile: extraction stays inside the scan folder, symlinks are recorded,
  never followed, and nothing is processed as root (see `util.drop_privileges`).
- **Reproducible toolchain.** Every scanner in the `Containerfile` is pinned to a version and SHA-256; Python
  packages resolve as of `PY_DEPS_DATE`.

## Commands

Python is only available through uv (`uv run ...`); tests run inside the image, against the working tree:

```sh
podman build -t vulnscan .
podman run --rm -v "$PWD:/src:ro" -e PYTHONPATH=/src --entrypoint sh vulnscan -c \
  'uv pip install -q --python /opt/venv/bin/python pytest pytest-cov openpyxl "cyclonedx-python-lib[json-validation]" \
   && cd /src && python -m pytest --cov=vulnscan'
# detection test (network): ... python -m pytest -m integration
```

Lint: `uv run --with ruff ruff check .` (line length 120, rules in `pyproject.toml`).

## Conventions

- **GitHub Actions** are pinned by full commit SHA with the version as a comment (`@<sha> # v1.2.3`); pick a
  release at least 14 days old. Base images in the `Containerfile` are pinned as `tag@sha256:<index digest>`.
  Both are updated by hand: Dependabot only raises security alerts (no update pull requests, no auto-merge).
- **Scanner upgrade:** version and SHA-256 in the `Containerfile` (from the release's checksum file), run the tests,
  refresh `tests/fixtures` if the output format changed. Contract tests must keep parsing real scanner output.
- **Identification rules** go in `pe.py` (version resources) or `binsig.py` (embedded strings), each with a test.
- **Commits** use conventional prefixes (`feat:`, `fix:`, `ci:`, `build(deps):`, `docs:`, `chore:`). `main` only
  accepts squash-merged pull requests with a passing `image` check.
- **Versions** follow semver (README, *Versions and releases*): the version lives in both `pyproject.toml` and
  `vulnscan/__init__.py` (a unit test keeps them equal); a release is a `vX.Y.Z` tag on `main`, and CI publishes the
  image and the GitHub release. Scanner upgrades are minor releases.
- **README images** come from demo scans of public artifacts, never from real scan data. Never commit `.env`,
  scan reports or anything from a real repository.
