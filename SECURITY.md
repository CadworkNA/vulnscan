# Security policy

## Reporting a vulnerability

Report vulnerabilities **privately** through GitHub:
[Security → Report a vulnerability](https://github.com/CadworkNA/vulnscan/security/advisories/new).
Please do not open a public issue, pull request or discussion for a security problem.

Include what you can: the affected version (`vulnscan --version` or the image tag/digest), the steps or a file
that reproduces it, and the impact you expect.

What to expect:

- acknowledgement within **5 business days**;
- an assessment, and a fix or mitigation plan, once the report is confirmed;
- the fix ships as a patch release with a GitHub security advisory, crediting you unless you prefer otherwise.

## Supported versions

Fixes are made to the latest minor release of the current major version and published as a new patch release
(see [Versions and releases](README.md#versions-and-releases)). Older releases are not patched; upgrade to the
latest `:1` image.

## Scope

In scope: vulnerabilities in vulnscan itself and in the published image, for example

- a crafted archive, installer or binary that leads to code execution, writes outside the scan folder or escapes
  the unprivileged user the scanner switches to;
- leaking credentials from `.env` (SVN, SMTP) into reports, logs, SBOMs or emails;
- a crafted input that makes a run report **complete** although content was not scanned, defeating the fail-closed
  guarantee;
- a vulnerable component in the image that is actually reachable through vulnscan;
- with `--ai` (upgrade advice): sending anything beyond what the README documents (repository names, paths, file
  names, the functions our binaries import) to a registry, GitHub/GitLab or the model provider; a request to a
  host outside the allowlist; a model API key or `GITHUB_TOKEN` sent anywhere but its own service;
- crafted release notes or package metadata that make the advice report a change that is not in the notes, or
  an *unlikely* verdict without the evidence for it (e.g. by getting around the quote verification).

Out of scope (open a regular issue instead):

- a known vulnerability that vulnscan misses or misreports in the files *you* scanned, when the run was correctly
  reported as complete or incomplete: that is a detection bug, not a vulnerability in vulnscan;
- vulnerabilities in the bundled scanners (Grype, Syft, osv-scanner, retire.js) that vulnscan does not expose:
  report those upstream;
- findings from scanning the image that are not reachable in vulnscan's use; the image is scanned by CI on every
  change and weekly, and actively exploited (KEV) vulnerabilities fail the build.
