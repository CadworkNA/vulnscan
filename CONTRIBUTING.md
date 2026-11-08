# Contributing

Bug reports, feature requests and pull requests are welcome.

- **Bugs and feature requests:** open a [GitHub issue](https://github.com/CadworkNA/vulnscan/issues). For a bug,
  include `vulnscan --version` (or the image tag/digest), what you ran, and the relevant part of `scan.log`.
  **Never attach real scan reports, SBOMs or logs from a private repository**: reduce the problem to public files.
- **Security problems:** do not open an issue; follow [SECURITY.md](SECURITY.md).
- **Changes:** open a pull request against `main`. For anything larger than a fix, open an issue first so the
  approach can be agreed before you invest time.

## Requirements for a pull request

A pull request is merged when it meets all of the following:

1. **It keeps the scanner fail-closed.** A run is *complete* only if every repository was scanned by every engine
   with current data and passing self-tests. Errors, missing or malformed scanner output and skipped content must
   surface as *incomplete* (exit code 3): do not swallow exceptions or default to empty results.
2. **It treats scanned files as hostile.** Extraction stays inside the scan folder, symbolic links are recorded and
   never followed, and nothing processes scanned content as root.
3. **It comes with tests** (see the test policy below), and the `image` check passes: it builds the image and runs
   the unit, contract and detection tests, the CLI smoke test and the self-scan.
4. **It passes the linter:** `uv run --with ruff ruff check .` (rules and line length 120 in
   [`pyproject.toml`](pyproject.toml)). CI runs the same check.
5. **Its title uses a conventional prefix** (`feat:`, `fix:`, `docs:`, `ci:`, `build(deps):`, `chore:`). Pull requests
   are squash-merged, so the title becomes the commit message and the release notes entry.
6. **It keeps the toolchain reproducible:** scanners in the `Containerfile` are pinned to a version and SHA-256 (from
   the release's checksum file), base images to a digest, GitHub Actions to a full commit SHA.
7. **It contains no secrets or real data:** no `.env`, credentials, scan reports or files from a private repository.
   README images come from demo scans of public artifacts.

Every pull request is reviewed by a maintainer ([CODEOWNERS](.github/CODEOWNERS)).

## Test policy

New functionality and bug fixes come with automated tests in [`tests/`](tests):

- a **new feature or option**: unit tests for its behaviour, including its failure paths (what makes the run
  incomplete);
- a **bug fix**: a test that fails without the fix;
- a **new identification rule** in `pe.py` (version resources) or `binsig.py` (embedded strings): a test case for
  the rule;
- a **scanner upgrade** or output-format change: refreshed recorded output in [`tests/fixtures`](tests/fixtures), so
  the contract tests keep parsing real scanner output.

- **new code that parses scanned content** (file formats, archive member names): extend a fuzz target in
  [`fuzz/`](fuzz) or add one, so hostile input is fuzzed on every change.

Coverage must not fall below the threshold CI enforces. See the [Development](README.md#development) section of the
README for how to run the tests.
