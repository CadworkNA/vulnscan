"""Evidence for the upgrade advice: what changes between the installed and the target version of a component.

Three kinds, all collected without any AI:
  * release notes, changelogs and migration guides, from public sources only (package registries, GitHub,
    GitLab and a few project sites), cut down to the versions between installed and target;
  * runtime requirements of both versions (Python, Node.js, .NET, Rust, Go, Ruby) from the registries, checked
    against the runtimes shipped in the same repository;
  * our own use of the component: the functions our binaries import from its DLLs (PE import tables).

Network access is limited to an allowlist of hosts, also across redirects; credentials (GITHUB_TOKEN) are only
sent to api.github.com. Responses are size-capped and cached in the cache volume, so offline runs reuse them.
Only public identifiers are sent: component names, versions and the project's own URLs, never a repository
name, path or file name of ours. Everything fetched is untrusted text: it is only ever passed on as data."""
from __future__ import annotations

import hashlib
import html
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .upgrade import numbers, step, vkey
from .util import DB_CACHE, USER_AGENT, get_secret, log

ALLOWED_HOSTS = {
    "pypi.org", "registry.npmjs.org", "api.nuget.org", "repo1.maven.org", "crates.io", "proxy.golang.org",
    "rubygems.org", "api.github.com", "raw.githubusercontent.com", "gitlab.com", "www.sqlite.org", "curl.se",
}
CACHE = DB_CACHE / "advisor" / "http"
CACHE_MAX_AGE_H = 24 * 7
MAX_BYTES = 8 << 20          # per response
TIMEOUT_S = 30
MAX_RELEASE_PAGES = 5        # GitHub releases, 100 per page
MAX_RELEASE_BODY = 20_000
MAX_PER_VERSION_FILES = 40   # Qt / Python per-release notes
MAX_SOURCE_CHARS = 400_000   # per source after slicing; longer ones are cut and marked partial
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_GITLAB_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}(/[A-Za-z0-9_.-]{1,100}){1,3}$")
_NAME_RE = re.compile(r"^[@A-Za-z0-9_.+/:-]{1,214}$")


class FetchError(RuntimeError):
    pass


class NotFound(FetchError):
    pass


class RateLimited(FetchError):
    pass


# ---------------------------------------------------------------------------
# HTTP: allowlisted, size-capped, cached
# ---------------------------------------------------------------------------
def _check_url(url: str) -> urllib.parse.SplitResult:
    try:
        u = urllib.parse.urlsplit(url)
        ok = u.scheme == "https" and u.hostname in ALLOWED_HOSTS and u.port in (None, 443) and not u.username
    except ValueError:  # malformed port or IPv6 literal
        ok = False
    if not ok:
        raise FetchError(f"refusing URL outside the allowlist: {url[:200]}")
    return u


class _Redirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to allowlisted HTTPS hosts, and never carry credentials to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = _check_url(urllib.parse.urljoin(req.full_url, newurl))
        out = super().redirect_request(req, fp, code, msg, headers, newurl)
        if out is not None and new.hostname != urllib.parse.urlsplit(req.full_url).hostname:
            out.remove_header("Authorization")
        return out


_OPENER = urllib.request.build_opener(_Redirects())


class Fetcher:
    def __init__(self, offline: bool):
        self.offline = offline
        self.token = get_secret("GITHUB_TOKEN")
        self.github_limited = False
        self.requests = 0
        self._lock = threading.Lock()
        CACHE.mkdir(parents=True, exist_ok=True)

    def get(self, url: str, accept: str = "") -> bytes:
        """Body of url (raises NotFound / RateLimited / FetchError), from a fresh cache entry when possible."""
        u = _check_url(url)
        key = hashlib.sha256(f"{url}\n{accept}".encode()).hexdigest()
        body, meta = CACHE / f"{key}.body", CACHE / f"{key}.json"
        try:
            m = json.loads(meta.read_text(encoding="utf-8"))
            fresh = time.time() - meta.stat().st_mtime < CACHE_MAX_AGE_H * 3600
            if fresh or self.offline:
                if m.get("status") == 404:
                    raise NotFound(url)
                return body.read_bytes()
        except (OSError, ValueError):
            pass
        if self.offline:
            raise FetchError(f"offline and not cached: {url[:200]}")
        github = u.hostname == "api.github.com"
        with self._lock:
            if github and self.github_limited:
                raise RateLimited("GitHub API rate limit reached")
            self.requests += 1
        headers = {"User-Agent": USER_AGENT}
        if accept:
            headers["Accept"] = accept
        if github:
            headers["X-GitHub-Api-Version"] = "2022-11-28"
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, headers=headers)  # noqa: S310 - scheme and host checked above
        try:
            with _OPENER.open(req, timeout=TIMEOUT_S) as resp:
                data = resp.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                self._store(meta, body, 404, b"")
                raise NotFound(url) from None
            limited = exc.code == 429 or (exc.code == 403 and (
                (exc.headers or {}).get("X-RateLimit-Remaining") == "0" or (exc.headers or {}).get("Retry-After")))
            if github and limited:
                with self._lock:
                    if not self.github_limited:
                        log.warning("GitHub API rate limit reached - release notes from GitHub are incomplete "
                                    "for the rest of this run%s", "" if self.token else
                                    " (set GITHUB_TOKEN for 5,000 requests an hour instead of 60)",
                                    extra={"stage": "advice"})
                    self.github_limited = True
                raise RateLimited("GitHub API rate limit reached") from None
            raise FetchError(f"HTTP {exc.code} for {url[:200]}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise FetchError(f"{url[:200]}: {exc}") from None
        if len(data) > MAX_BYTES:
            raise FetchError(f"response larger than {MAX_BYTES >> 20} MB: {url[:200]}")
        self._store(meta, body, 200, data)
        return data

    @staticmethod
    def _store(meta, body, status: int, data: bytes) -> None:
        try:
            tmp = body.with_suffix(f".{threading.get_ident()}.tmp")  # same URL may be fetched by two threads
            tmp.write_bytes(data)
            tmp.replace(body)
            meta.write_text(json.dumps({"status": status}), encoding="utf-8")
        except OSError:
            pass  # caching is an optimisation

    def json(self, url: str, accept: str = ""):
        try:
            return json.loads(self.get(url, accept))
        except (ValueError, UnicodeDecodeError) as exc:
            raise FetchError(f"invalid JSON from {url[:200]}: {exc}") from None

    def text(self, url: str) -> str:
        return self.get(url).decode("utf-8", "replace")


def q(s: str) -> str:
    """Path segment (component names are untrusted: never let them add path segments or a query)."""
    return urllib.parse.quote(s, safe="")


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
@dataclass
class Source:
    title: str
    url: str
    text: str
    complete: bool  # covers every version between installed and target


@dataclass
class Evidence:
    sources: list[Source] = field(default_factory=list)
    requirements: list[dict] = field(default_factory=list)  # {kind, text, violated: bool|None}
    repo: str = ""            # where the notes came from (github owner/name), for the report
    problems: list[str] = field(default_factory=list)
    _seen: dict = field(default_factory=dict, repr=False)  # text hash -> source

    def add(self, source: Source) -> None:
        """Add a source unless the same text is already there (a registry's changelog link and the same file
        found in the repository): it would only be read, and paid for, twice."""
        key = hashlib.sha256(" ".join(source.text.split()).encode()).hexdigest()
        if key in self._seen:
            self._seen[key].complete = self._seen[key].complete or source.complete
            return
        self._seen[key] = source
        self.sources.append(source)

    @property
    def coverage(self) -> str:
        if not self.sources:
            return "none"
        return "complete" if any(s.complete for s in self.sources) else "partial"


_VER_IN_LINE = re.compile(r"(?<![\w.])v?(\d+(?:\.\d+){1,3}(?:[a-z](?![a-z]))?)(?![\w])")
_UNDERLINE = re.compile(r"^\s*[=\-~^*#]{3,}\s*$")
_BULLET = re.compile(r"^\s*([-*+•]|\d+[.)])\s")


_PLAIN_HEAD = re.compile(r"^(?:[-=]{3,}\s|v\d|\d|(?:version|release|changes|what'?s new|noteworthy changes|"
                         r"major changes)\b)", re.I)
_DATE_START = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _line_version(s: str) -> str | None:
    keyed = [m.group(1) for m in _VER_IN_LINE.finditer(s[:100]) if vkey(m.group(1)) is not None]
    return max(keyed, key=vkey) if keyed else None


def headings(lines: list[str]) -> list[tuple[int, str]]:
    """(line index, version) of every heading that introduces a version.

    Only structural headings count, never prose that happens to mention a version ('TLS 1.3 ...'): markdown
    headings, underlined (setext) lines, and short unindented lines that start with a version or a keyword
    ('Version 1.6.38', 'Changes in 1.2.13', 'v2.9.10: ...', '---- FFmpeg 6.1 was cut here ----')."""
    out = []
    for i, ln in enumerate(lines):
        s = ln.strip()
        if not s or len(s) > 120 or ln[:1].isspace():
            continue
        v = _line_version(s)
        if not v:
            continue
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if re.match(r"^#{1,6}\s", ln):
            out.append((i, v))
        elif len(s.split()) <= 12 and not _BULLET.match(ln) and (
                _UNDERLINE.match(nxt) or (_PLAIN_HEAD.match(s) and not _DATE_START.match(s))):
            out.append((i, v))
    return out


def slice_changelog(text: str, installed: str, target: str, need_target: bool = True) -> tuple[str, bool] | None:
    """Sections of a changelog for versions in (installed, target]; (text, complete) or None if none found.

    Complete when the file also has a heading at or below the installed version, so nothing in between can
    be missing. A heading at (or above) the target is required unless need_target is False (files that cover
    one release line each, e.g. Node.js CHANGELOG_V18.md)."""
    lo, hi = vkey(installed), vkey(target)
    if lo is None or hi is None:
        return None
    lines = text.splitlines()
    heads = headings(lines)
    keep, seen_low, seen_target = [], False, False
    for n, (i, v) in enumerate(heads):
        k = vkey(v)
        end = heads[n + 1][0] if n + 1 < len(heads) else len(lines)
        if k <= lo:
            seen_low = True
        if k >= hi:
            seen_target = True
        if lo < k <= hi:
            keep.append("\n".join(lines[i:end]).strip())
    if not keep or (need_target and not seen_target):
        return None
    return "\n\n".join(keep), seen_low


def tag_version(tag: str) -> str | None:
    """'v1.2.3', 'openssl-3.0.12', 'OpenSSL_1_1_1w', 'curl-8_4_0', 'release-2.0' -> version, or None."""
    m = re.search(r"\d+(?:[._]\d+)+[a-z]?(?:-?(?:rc|beta|alpha|pre)[.-]?\d*)?", tag or "", re.I)
    if not m:
        return None
    v = m.group(0)
    if "." not in v:
        v = v.replace("_", ".")
    return v if vkey(v) is not None else None


class _HTMLText(HTMLParser):
    BLOCK = {"p", "div", "li", "br", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "ul", "ol", "table"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        elif tag in self.BLOCK:
            self.out.append("\n")
        if tag in ("h1", "h2", "h3", "h4"):
            self.out.append("## ")

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip = max(0, self.skip - 1)
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def html_text(page: str) -> str:
    p = _HTMLText()
    p.feed(page)
    return re.sub(r"\n\s*\n+", "\n\n", html.unescape("".join(p.out)))


# ---------------------------------------------------------------------------
# Native libraries (identified in binaries): curated sources, keyed by the NVD product name
# ---------------------------------------------------------------------------
# changelogs: files on the default branch, sliced to the version range; guides: (path, ref, when) included
# whole when the upgrade crosses a major version ('major') or always ('always'); releases: GitHub release notes
NATIVE: dict[str, dict] = {
    "openssl": {"repo": "openssl/openssl", "changelogs": ["CHANGES.md", "NEWS.md"],
                "guides": [("doc/man7/ossl-guide-migration.pod", "HEAD", "major")]},
    "curl": {"repo": "curl/curl", "html": ["https://curl.se/changes.html"], "releases": True},
    "zlib": {"repo": "madler/zlib", "changelogs": ["ChangeLog"]},
    "libpng": {"repo": "pnggroup/libpng", "changelogs": ["CHANGES"]},
    "libjpeg-turbo": {"repo": "libjpeg-turbo/libjpeg-turbo", "changelogs": ["ChangeLog.md"]},
    "libexpat": {"repo": "libexpat/libexpat", "changelogs": ["expat/Changes"]},
    "ffmpeg": {"repo": "FFmpeg/FFmpeg", "changelogs": ["Changelog", "doc/APIchanges"]},
    "7-zip": {"repo": "ip7z/7zip", "releases": True},
    "libxml2": {"repo": "GNOME/libxml2", "changelogs": ["NEWS"]},
    "libxslt": {"repo": "GNOME/libxslt", "changelogs": ["NEWS"]},
    "freetype": {"repo": "freetype/freetype", "changelogs": ["docs/CHANGES"]},
    "libwebp": {"repo": "webmproject/libwebp", "changelogs": ["NEWS"]},
    "libssh2": {"repo": "libssh2/libssh2", "changelogs": ["RELEASE-NOTES"], "releases": True},
    "libssh": {"repo": "libssh/libssh-mirror", "changelogs": ["CHANGELOG"]},
    "libarchive": {"repo": "libarchive/libarchive", "changelogs": ["NEWS"]},
    "nghttp2": {"repo": "nghttp2/nghttp2", "releases": True},
    "electron": {"repo": "electron/electron", "changelogs": ["docs/breaking-changes.md"], "releases": True},
    "lz4": {"repo": "lz4/lz4", "changelogs": ["NEWS"]},
    "xz": {"repo": "tukaani-project/xz", "changelogs": ["NEWS"]},
    "pcre2": {"repo": "PCRE2Project/pcre2", "changelogs": ["ChangeLog"]},
    "gdal": {"repo": "OSGeo/gdal", "changelogs": ["NEWS.md", "MIGRATION_GUIDE.TXT"]},
    "proj": {"repo": "OSGeo/PROJ", "changelogs": ["NEWS.md"]},
    "hdf5": {"repo": "HDFGroup/hdf5", "changelogs": ["release_docs/CHANGELOG.md"], "releases": True},
    "harfbuzz": {"repo": "harfbuzz/harfbuzz", "changelogs": ["NEWS"]},
    "libzip": {"repo": "nih-at/libzip", "changelogs": ["NEWS.md"]},
    "openexr": {"repo": "AcademySoftwareFoundation/openexr", "changelogs": ["CHANGES.md"]},
    "openvdb": {"repo": "AcademySoftwareFoundation/openvdb", "changelogs": ["CHANGES"]},
    "mbed_tls": {"repo": "Mbed-TLS/mbedtls", "changelogs": ["ChangeLog"],
                 "guides": [("docs/3.0-migration-guide.md", "mbedtls-3.6", "major"),
                            ("docs/4.0-migration-guide.md", "HEAD", "major")]},
    "opencv": {"repo": "opencv/opencv", "releases": True},
    "international_components_for_unicode": {"repo": "unicode-org/icu", "releases": True},
    "assimp": {"repo": "assimp/assimp", "releases": True},
    "bzip2": {"gitlab": "bzip2/bzip2", "changelogs": ["CHANGES"]},
    "sqlite": {"html": ["https://www.sqlite.org/changes.html"]},
    "node.js": {"special": "node"}, "node": {"special": "node"}, "nodejs": {"special": "node"},
    "python": {"special": "python"}, "cpython": {"special": "python"},
    "qt": {"special": "qt"},
}


def raw_github(repo: str, path: str, ref: str = "HEAD") -> str:
    return f"https://raw.githubusercontent.com/{repo}/{q(ref)}/{'/'.join(q(p) for p in path.split('/'))}"


def raw_gitlab(project: str, path: str, ref: str = "HEAD") -> str:
    return f"https://gitlab.com/{project}/-/raw/{q(ref)}/{'/'.join(q(p) for p in path.split('/'))}"


def crosses_major(installed: str, target: str) -> bool:
    return step(installed, target) == "major"


# ---------------------------------------------------------------------------
class Collector:
    """Collects the evidence for one upgrade at a time (thread-safe: one Fetcher shared by all)."""

    def __init__(self, fetcher: Fetcher):
        self.f = fetcher

    # -- generic pieces -------------------------------------------------
    def _add_changelog(self, ev: Evidence, url: str, title: str, installed: str, target: str) -> bool:
        try:
            text = self.f.text(url)
        except NotFound:
            return False
        except FetchError as exc:
            ev.problems.append(f"{title}: {exc}")
            return False
        if url.endswith((".html", ".htm")) or "<html" in text[:2000].lower():
            text = html_text(text)
        sliced = slice_changelog(text, installed, target)
        if sliced is None:
            return False
        body, complete = sliced
        if len(body) > MAX_SOURCE_CHARS:
            body, complete = body[:MAX_SOURCE_CHARS], False
        ev.add(Source(title, url, body, complete))
        return True

    def _add_whole(self, ev: Evidence, url: str, title: str) -> bool:
        try:
            text = self.f.text(url)
        except NotFound:
            return False
        except FetchError as exc:
            ev.problems.append(f"{title}: {exc}")
            return False
        complete = len(text) <= MAX_SOURCE_CHARS
        ev.add(Source(title, url, text[:MAX_SOURCE_CHARS], complete))
        return True

    def _github_releases(self, ev: Evidence, repo: str, installed: str, target: str) -> bool:
        lo, hi = vkey(installed), vkey(target)
        picked, seen_low, seen_target = [], False, False
        ended, cut = False, False  # complete only if the listing ended normally and nothing was cut
        for page in range(1, MAX_RELEASE_PAGES + 1):
            try:
                rels = self.f.json(f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}",
                                   "application/vnd.github+json")
            except NotFound:
                return False
            except FetchError as exc:  # includes the rate limit: what was read so far is partial
                ev.problems.append(f"GitHub releases of {repo}: {exc}")
                break
            if not isinstance(rels, list):
                ev.problems.append(f"GitHub releases of {repo}: unexpected answer")
                break
            if not rels:
                ended = True
                break
            below = True  # every release on this page is at or below the installed version
            for r in rels:
                if not isinstance(r, dict) or r.get("draft") or r.get("prerelease"):
                    continue
                v = tag_version(str(r.get("tag_name") or "")) or tag_version(str(r.get("name") or ""))
                k = vkey(v) if v else None
                if k is None:
                    continue
                if k <= lo:
                    seen_low = True
                else:
                    below = False
                if k >= hi:
                    seen_target = True
                if lo < k <= hi:
                    body = str(r.get("body") or "").strip()
                    if len(body) > MAX_RELEASE_BODY:
                        body, cut = body[:MAX_RELEASE_BODY], True
                    if body:
                        picked.append((k, v, body))
            # releases come newest first, but several release lines interleave: stop at the last page, or once
            # a whole page is below the range; running into MAX_RELEASE_PAGES leaves the notes partial
            if len(rels) < 100 or (seen_low and below):
                ended = True
                break
        if not picked or not seen_target:
            return False
        picked.sort(key=lambda p: p[0], reverse=True)
        text = "\n\n".join(f"## {v}\n{body}" for _, v, body in picked)
        ev.add(Source(f"GitHub releases of {repo}", f"https://github.com/{repo}/releases", text[:MAX_SOURCE_CHARS],
                      ended and seen_low and not cut and len(text) <= MAX_SOURCE_CHARS))
        return True

    def _repo_files(self, ev: Evidence, repo: str, installed: str, target: str) -> None:
        """Changelog and migration/upgrade guides found in the repository root and docs folder."""
        names = []
        for folder in ("", "docs", "doc"):
            try:
                items = self.f.json(f"https://api.github.com/repos/{repo}/contents/{folder}",
                                    "application/vnd.github+json")
            except FetchError:
                continue
            for it in items if isinstance(items, list) else []:
                name = str((it or {}).get("name") or "")
                if (it or {}).get("type") == "file" and re.match(
                        r"^(change|changes|changelog|history|news|release|releases|release[-_]notes|whatsnew|"
                        r"migrat|upgrad|breaking)[\w.-]*$", name, re.I) and not re.search(r"\.(png|jpg|svg)$", name):
                    names.append(f"{folder}/{name}".lstrip("/"))
        for path in names[:8]:
            url = raw_github(repo, path)
            if re.search(r"migrat|upgrad|breaking", path, re.I):
                if not self._add_changelog(ev, url, f"{repo}: {path}", installed, target) \
                        and crosses_major(installed, target):
                    self._add_whole(ev, url, f"{repo}: {path}")
            else:
                self._add_changelog(ev, url, f"{repo}: {path}", installed, target)

    # -- native libraries -----------------------------------------------
    def native(self, name: str, installed: str, target: str) -> Evidence:
        ev = Evidence()
        if vkey(installed) is None or vkey(target) is None:
            ev.problems.append("version cannot be compared")
            return ev
        spec = NATIVE.get(name.lower())
        if not spec:
            ev.problems.append(f"no known release-note source for {name}")
            return ev
        special = spec.get("special")
        if special == "python":
            self._python(ev, installed, target)
            return ev
        if special == "node":
            self._node(ev, installed, target)
            return ev
        if special == "qt":
            self._qt(ev, installed, target)
            return ev
        repo, project = spec.get("repo", ""), spec.get("gitlab", "")
        ev.repo = repo or project
        for path in spec.get("changelogs", []):
            url = raw_github(repo, path) if repo else raw_gitlab(project, path)
            self._add_changelog(ev, url, f"{ev.repo}: {path}", installed, target)
        for url in spec.get("html", []):
            self._add_changelog(ev, url, url, installed, target)
        for path, ref, when in spec.get("guides", []):
            if when == "always" or crosses_major(installed, target):
                self._add_whole(ev, raw_github(repo, path, ref), f"{repo}: {path} (migration guide)")
        if spec.get("releases") and repo:
            self._github_releases(ev, repo, installed, target)
        return ev

    def _python(self, ev: Evidence, installed: str, target: str) -> None:
        """What's New of every minor version crossed (with its 'Porting to' section) + per-release NEWS."""
        ev.repo = "python/cpython"
        a, b = numbers(installed) + [0, 0, 0], numbers(target) + [0, 0, 0]
        if a[0] != 3 or b[0] != 3:
            ev.problems.append("only Python 3 release notes are supported")
            return
        complete = True
        for minor in range(a[1] + 1, b[1] + 1):
            if not self._add_whole(ev, raw_github("python/cpython", f"Doc/whatsnew/3.{minor}.rst"),
                                   f"What's New in Python 3.{minor}"):
                complete = False
        first = a[2] + 1 if a[1] == b[1] else 1
        patches = list(range(first, b[2] + 1))
        if len(patches) > MAX_PER_VERSION_FILES:
            patches, complete = patches[-MAX_PER_VERSION_FILES:], False
        for p in patches:
            v = f"3.{b[1]}.{p}"
            if not self._add_whole(ev, raw_github("python/cpython", f"Misc/NEWS.d/{v}.rst", f"v{v}"),
                                   f"Python {v} changelog"):
                complete = False
        # across minor versions, the patch releases of the installed line and of the minors in between are not
        # read: only What's New and the target line's NEWS are
        complete = complete and a[1] == b[1]
        for s in ev.sources:
            s.complete = s.complete and complete

    def _node(self, ev: Evidence, installed: str, target: str) -> None:
        ev.repo = "nodejs/node"
        a, b = numbers(installed), numbers(target)
        if not a or not b:
            return
        # one changelog per major version: complete when every one is found and the first reaches the installed
        complete = True
        for major in range(a[0], b[0] + 1):
            url = raw_github("nodejs/node", f"doc/changelogs/CHANGELOG_V{major}.md")
            try:
                sliced = slice_changelog(self.f.text(url), installed, target, need_target=major == b[0])
            except FetchError as exc:
                if not isinstance(exc, NotFound):
                    ev.problems.append(f"Node.js {major} changelog: {exc}")
                sliced = None
            if sliced is None:
                complete = False
                continue
            text, reaches_installed = sliced
            if major == a[0] and not reaches_installed:
                complete = False
            ev.add(Source(f"Node.js {major} changelog", url, text[:MAX_SOURCE_CHARS],
                                     len(text) <= MAX_SOURCE_CHARS))
        for s in ev.sources:
            s.complete = s.complete and complete

    def _qt(self, ev: Evidence, installed: str, target: str) -> None:
        """Per-release notes: qt/qtreleasenotes (5.12.11 and later), else qtbase dist/changes-<version>."""
        ev.repo = "qt/qtreleasenotes"
        lo, hi = vkey(installed), vkey(target)
        try:
            items = self.f.json("https://api.github.com/repos/qt/qtreleasenotes/contents/qt",
                                "application/vnd.github+json")
        except FetchError as exc:
            ev.problems.append(f"Qt release notes: {exc}")
            items = []
        listed = sorted({str(i.get("name")) for i in items if isinstance(i, dict) and vkey(str(i.get("name")))},
                        key=vkey)
        wanted = [v for v in listed if lo < vkey(v) <= hi]
        texts, complete = [], bool(listed) and vkey(listed[0]) <= lo
        for v in wanted[-MAX_PER_VERSION_FILES:]:
            try:
                texts.append((vkey(v), f"## Qt {v}\n" +
                              self.f.text(raw_github("qt/qtreleasenotes", f"qt/{v}/release-note.md"))))
            except FetchError:
                complete = False
        if len(wanted) > MAX_PER_VERSION_FILES:
            complete = False
        a = numbers(installed)
        if a and a[0] == 5 and not complete:
            # older Qt 5 releases: qtbase dist/changes-<version> on the minor branch
            try:
                old = self.f.json(f"https://api.github.com/repos/qt/qtbase/contents/dist?ref=5.{a[1]}",
                                  "application/vnd.github+json")
                for it in old if isinstance(old, list) else []:
                    m = re.match(r"^changes-(\d+\.\d+\.\d+)$", str((it or {}).get("name") or ""))
                    if m and lo < vkey(m.group(1)) <= hi and m.group(1) not in wanted \
                            and len(texts) < MAX_PER_VERSION_FILES:
                        texts.append((vkey(m.group(1)), f"## Qt {m.group(1)}\n" + self.f.text(
                            raw_github("qt/qtbase", f"dist/changes-{m.group(1)}", f"5.{a[1]}"))))
            except FetchError as exc:
                ev.problems.append(f"Qt 5 changes files: {exc}")
        if texts:
            text = "\n\n".join(t for _, t in sorted(texts, key=lambda x: x[0], reverse=True))
            ev.add(Source("Qt release notes", "https://github.com/qt/qtreleasenotes",
                                     text[:MAX_SOURCE_CHARS], complete and len(text) <= MAX_SOURCE_CHARS))

    # -- packages ---------------------------------------------------------
    def package(self, ecosystem: str, name: str, installed: str, target: str, runtimes: dict) -> Evidence:
        """Registry metadata (repository, changelog links, requirements) of both versions, then release notes."""
        ev = Evidence()
        if not _NAME_RE.match(name or "") or any(p in ("", ".", "..") for p in name.split("/")):
            ev.problems.append("component name is not a plain package name")
            return ev
        if vkey(installed) is None or vkey(target) is None:
            ev.problems.append("version cannot be compared")
            return ev
        meta = getattr(self, f"_meta_{ecosystem}", None)
        if meta is None:
            ev.problems.append(f"no registry support for {ecosystem or 'this ecosystem'}")
            return ev
        try:
            old, new = meta(name, installed), meta(name, target)
        except NotFound:
            ev.problems.append(f"{ecosystem} registry has no record of {name} {installed}/{target}")
            return ev
        except FetchError as exc:
            ev.problems.append(f"{ecosystem} registry: {exc}")
            return ev
        ev.requirements = requirement_changes(ecosystem, old, new, runtimes)
        links = new.get("links", []) + old.get("links", [])
        repo = next((r for r in (github_repo(u) for u in links) if r), "")
        gitlab = next((r for r in (gitlab_project(u) for u in links) if r), "")
        ev.repo = repo or gitlab
        for url in new.get("changelog_urls", []):
            raw = raw_url(url)
            if raw:
                self._add_changelog(ev, raw, f"{name}: {url}", installed, target)
        if repo:
            self._github_releases(ev, repo, installed, target)
            if ev.coverage != "complete" or crosses_major(installed, target):
                self._repo_files(ev, repo, installed, target)  # changelog files, migration guides
        elif gitlab:
            for path in ("CHANGELOG.md", "CHANGES.md", "NEWS.md", "HISTORY.md", "CHANGELOG", "NEWS"):
                if self._add_changelog(ev, raw_gitlab(gitlab, path), f"{gitlab}: {path}", installed, target):
                    break
        if not ev.sources and not ev.repo:
            ev.problems.append("the registry does not name a GitHub/GitLab repository")
        return ev

    def _meta_pypi(self, name, version) -> dict:
        d = self.f.json(f"https://pypi.org/pypi/{q(name)}/{q(version)}/json")
        info = d.get("info") or {}
        urls = {str(k).lower(): str(v) for k, v in (info.get("project_urls") or {}).items()}
        return {"requires_python": info.get("requires_python") or "",
                "wheels": [u.get("filename", "") for u in d.get("urls") or [] if str(u.get("filename", "")).endswith(".whl")],
                "links": [v for v in urls.values()] + [info.get("home_page") or ""],
                "changelog_urls": [v for k, v in urls.items() if re.search(r"change|history|release|news", k)]}

    def _meta_npm(self, name, version) -> dict:
        d = self.f.json(f"https://registry.npmjs.org/{q(name)}/{q(version)}")
        repo = d.get("repository")
        repo = repo.get("url", "") if isinstance(repo, dict) else str(repo or "")
        return {"engines": (d.get("engines") or {}) if isinstance(d.get("engines"), dict) else {},
                "links": [repo, str(d.get("homepage") or "")], "changelog_urls": []}

    def _meta_nuget(self, name, version) -> dict:
        reg = self.f.json(f"https://api.nuget.org/v3/registration5-semver1/{q(name.lower())}/{q(version.lower())}.json")
        entry = reg.get("catalogEntry")
        if isinstance(entry, str):
            entry = self.f.json(entry)
        entry = entry if isinstance(entry, dict) else {}
        repo = entry.get("repository")
        links = [str(entry.get("projectUrl") or ""), repo.get("url", "") if isinstance(repo, dict) else ""]
        if not any(github_repo(u) or gitlab_project(u) for u in links):
            # the catalog often leaves the repository out; the package's own .nuspec names it
            try:
                nuspec = self.f.text(f"https://api.nuget.org/v3-flatcontainer/{q(name.lower())}/"
                                     f"{q(version.lower())}/{q(name.lower())}.nuspec")
                links += re.findall(r"<repository\b[^>]*\burl=\"([^\"]{1,300})\"", nuspec)
            except FetchError:
                pass
        return {"frameworks": sorted({str(g.get("targetFramework") or "") for g in entry.get("dependencyGroups") or []
                                      if isinstance(g, dict)} - {""}),
                "links": links, "changelog_urls": []}

    def _meta_maven(self, name, version) -> dict:
        group, _, artifact = name.replace(":", "/").rpartition("/")
        if not group or not artifact:
            raise NotFound(name)
        links = []
        for depth in range(3):  # <scm> is often inherited from a parent POM
            pom = self.f.text(f"https://repo1.maven.org/maven2/{'/'.join(q(g) for g in group.split('.'))}/"
                              f"{q(artifact)}/{q(version)}/{q(artifact)}-{q(version)}.pom")
            pom = re.sub(r"<!--.*?-->", "", pom, flags=re.S)
            scm = re.search(r"<scm>(.*?)</scm>", pom, re.S)
            if scm:
                links += [maven_scm(u) for u in re.findall(r">\s*([^<\s]+)\s*<", scm.group(1))]
            url = re.search(r"<url>\s*([^<\s]+)\s*</url>", pom)
            links.append(url.group(1) if url else "")
            parent = re.search(r"<parent>\s*(.*?)</parent>", pom, re.S)
            if any(github_repo(u) for u in links) or not parent or depth == 2:
                break
            fields = {k: re.search(rf"<{k}>\s*([^<\s]+)\s*</{k}>", parent.group(1))
                      for k in ("groupId", "artifactId", "version")}
            if not all(fields.values()):
                break
            group, artifact, version = (fields[k].group(1) for k in ("groupId", "artifactId", "version"))
            if not all(_NAME_RE.match(x) for x in (group, artifact, version)):
                break
        return {"links": links, "changelog_urls": []}

    def _meta_cargo(self, name, version) -> dict:
        d = (self.f.json(f"https://crates.io/api/v1/crates/{q(name)}/{q(version)}") or {}).get("version") or {}
        crate = self.f.json(f"https://crates.io/api/v1/crates/{q(name)}").get("crate") or {}
        return {"rust_version": d.get("rust_version") or "",
                "links": [str(crate.get("repository") or ""), str(crate.get("homepage") or "")], "changelog_urls": []}

    def _meta_golang(self, name, version) -> dict:
        # module proxy case encoding: upper-case letters become '!' + lower case
        def esc(s: str) -> str:
            return urllib.parse.quote(re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), s), safe="!")

        path = "/".join(esc(seg) for seg in name.split("/"))
        mod = self.f.text(f"https://proxy.golang.org/{path}/@v/{esc('v' + version.lstrip('v'))}.mod")
        go = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)", mod, re.M)
        return {"go": go.group(1) if go else "", "links": [f"https://{name}"], "changelog_urls": []}

    def _meta_gem(self, name, version) -> dict:
        d = self.f.json(f"https://rubygems.org/api/v2/rubygems/{q(name)}/versions/{q(version)}.json")
        return {"ruby": d.get("ruby_version") or "",
                "links": [str(d.get("source_code_uri") or ""), str(d.get("homepage_uri") or "")],
                "changelog_urls": [str(d.get("changelog_uri") or "")]}


def github_repo(url: str) -> str:
    m = re.match(r"^(?:git\+)?(?:https?|git|ssh)://(?:git@)?(?:www\.)?github\.com[/:]([^/#?\s]+)/([^/#?\s]+)",
                 (url or "").strip(), re.I) or re.match(r"^(?:github:|git@github\.com:)([^/\s]+)/([^/#?\s]+)$",
                                                        (url or "").strip(), re.I)
    if not m:
        return ""
    repo = f"{m.group(1)}/{re.sub(r'\.git$', '', m.group(2))}"
    return repo if _REPO_RE.match(repo) else ""


def maven_scm(url: str) -> str:
    """POM SCM URL -> plain URL: drops the 'scm:git:' prefix and maps Apache gitbox to its GitHub mirror."""
    u = re.sub(r"^scm:\w+:", "", (url or "").strip())
    m = re.match(r"^https?://(?:gitbox|git-wip-us)\.apache\.org/repos/asf(?:\?p=|/)([A-Za-z0-9_.-]+?)(?:\.git)?(?:[;/].*)?$",
                 u)
    return f"https://github.com/apache/{m.group(1)}" if m else u


def gitlab_project(url: str) -> str:
    m = re.match(r"^(?:git\+)?https://gitlab\.com/([^#?\s]+?)(?:\.git)?/?(?:/-/.*)?$", (url or "").strip(), re.I)
    return m.group(1) if m and _GITLAB_RE.match(m.group(1)) else ""


def raw_url(url: str) -> str:
    """Raw URL of a changelog file linked from a registry (GitHub blob links), if on an allowlisted host."""
    m = re.match(r"^https://github\.com/([^/]+/[^/]+)/(?:blob|tree)/([^/]+)/(.+?)(?:#.*)?$", (url or "").strip())
    if m and _REPO_RE.match(m.group(1)) and not m.group(3).endswith("/"):
        return raw_github(m.group(1), urllib.parse.unquote(m.group(3)), urllib.parse.unquote(m.group(2)))
    try:
        _check_url(url)
    except FetchError:
        return ""
    return url if re.search(r"change|history|news|release", url, re.I) else ""


# ---------------------------------------------------------------------------
# Requirements
# ---------------------------------------------------------------------------
def _py_tags(wheels: list[str]) -> set[str]:
    tags = set()
    for w in wheels:
        parts = w[:-4].split("-")
        if len(parts) >= 5:
            for py in parts[-3].split("."):
                for abi in parts[-2].split("."):
                    for plat in parts[-1].split("."):
                        tags.add(f"{py}-{abi}-{plat}")
    return tags


def _wheel_ok(tags: set[str], py: str) -> bool:
    """Is there a wheel usable on Windows CPython `py` (e.g. '3.8')?"""
    major, minor = (numbers(py) + [0, 0])[:2]
    cp = f"cp{major}{minor}"
    for t in tags:
        pyt, abi, plat = t.split("-")
        win_or_any = plat == "any" or plat.startswith("win")
        if not win_or_any:
            continue
        if pyt == cp or pyt in (f"py{major}", f"py{major}{minor}"):
            return True
        if abi == "abi3" and pyt.startswith(f"cp{major}") and vkey(pyt[2:3] + "." + pyt[3:]) <= vkey(f"{major}.{minor}"):
            return True
    return False


def _py_spec_ok(spec: str, version: str) -> bool | None:
    try:
        return Version(version) in SpecifierSet(spec) if spec else True
    except (InvalidSpecifier, InvalidVersion):
        return None


def npm_satisfies(version: str, rng: str) -> bool | None:
    """Minimal npm semver range check (>=, >, <, <=, =, ^, ~, x-ranges, hyphen ranges, ||); None if unparsable."""
    v = (numbers(version) + [0, 0, 0])[:3]
    if not numbers(version):
        return None

    def cmp_ok(op, ver):
        n = numbers(ver)
        if not n:
            return None
        n3 = (n + [0, 0, 0])[:3]
        if op in ("", "="):
            return v[:len(n)] == n[:3]
        if op == ">=":
            return v >= n3
        if op == ">":
            return v > n3 if len(n) >= 3 else v[:len(n)] > n
        if op == "<":
            return v < n3
        if op == "<=":
            return v <= n3 if len(n) >= 3 else v[:len(n)] <= n
        if op == "^":
            nz = next((i for i, x in enumerate(n3) if x), 2)
            upper = n3[:nz] + [n3[nz] + 1] + [0] * (2 - nz)
            return n3 <= v < upper
        if op == "~":
            upper = [n3[0] + 1, 0, 0] if len(n) == 1 else [n3[0], n3[1] + 1, 0]
            return n3 <= v < upper
        return None

    for alt in (rng or "*").split("||"):
        alt = re.sub(r"\s*-\s+", " - ", alt.strip())
        if alt in ("", "*", "x", "latest"):
            return True
        if " - " in alt:
            lo, hi = alt.split(" - ", 1)
            res = [cmp_ok(">=", lo.strip()), cmp_ok("<=", hi.strip())]
        else:
            res = []
            for c in re.findall(r"(>=|<=|>|<|=|\^|~)?\s*v?([\dxX*][\w.*]*)", alt):
                op, ver = c
                ver = re.sub(r"\.[xX*].*$", "", ver)
                if ver in ("x", "X", "*"):
                    res.append(True)
                    continue
                res.append(cmp_ok(op, ver))
        if None in res or not res:
            return None
        if all(res):
            return True
    return False


def requirement_changes(eco: str, old: dict, new: dict, runtimes: dict) -> list[dict]:
    """Runtime/platform requirements that changed between the two versions, checked against what we ship.

    runtimes: {'python': ['3.8.10'], 'node': ['18.17.0']} - versions shipped in the same repositories."""
    out = []
    if eco == "pypi":
        a, b = old.get("requires_python", ""), new.get("requires_python", "")
        if a != b and b:
            bad = [p for p in runtimes.get("python", []) if _py_spec_ok(b, p) is False]
            out.append({"kind": "Python", "text": f"requires Python {b}" + (f" (was {a})" if a else ""),
                        "violated": f"shipped Python {', '.join(bad)} not supported" if bad else None})
        ta, tb = _py_tags(old.get("wheels", [])), _py_tags(new.get("wheels", []))
        for py in runtimes.get("python", []):
            if ta and _wheel_ok(ta, py) and not _wheel_ok(tb, py):
                out.append({"kind": "wheels", "text": f"no prebuilt Windows wheel for Python {'.'.join(map(str, numbers(py)[:2]))} "
                            "in the target version (the installed version has one)",
                            "violated": f"shipped Python {py} needs a wheel"})
    elif eco == "npm":
        a, b = str(old.get("engines", {}).get("node", "")), str(new.get("engines", {}).get("node", ""))
        if a != b and b:
            bad = [n for n in runtimes.get("node", []) if npm_satisfies(n, b) is False]
            out.append({"kind": "Node.js", "text": f"engines.node {b}" + (f" (was {a})" if a else ""),
                        "violated": f"shipped Node.js {', '.join(bad)} not supported" if bad else None})
    elif eco == "nuget":
        dropped = sorted(set(old.get("frameworks", [])) - set(new.get("frameworks", [])))
        if dropped and new.get("frameworks"):
            out.append({"kind": ".NET", "text": f"no longer targets {', '.join(dropped)} "
                        f"(targets: {', '.join(new['frameworks'])})", "violated": None})
    else:
        key, label = {"cargo": ("rust_version", "Rust (MSRV)"), "golang": ("go", "Go"),
                      "gem": ("ruby", "Ruby")}.get(eco, ("", ""))
        if key and old.get(key) != new.get(key) and new.get(key):
            out.append({"kind": label, "text": f"requires {label} {new[key]}" +
                        (f" (was {old[key]})" if old.get(key) else ""), "violated": None})
    return out


# ---------------------------------------------------------------------------
# Our usage: functions our binaries import from the component's DLLs
# ---------------------------------------------------------------------------
# libraries shipped as several DLLs, only one of which is identified as the component
DLL_FAMILY = {
    "qt": r"^qt[456]?[a-z0-9]+d?\.dll$",
    "openssl": r"^(libssl|libcrypto|ssleay32|libeay32)[\w-]*\.dll$",
    "ffmpeg": r"^(avcodec|avformat|avutil|avfilter|avdevice|swscale|swresample|postproc)[\w-]*\.dll$",
    "international_components_for_unicode": r"^icu(uc|in|dt|io)\d*\.dll$",
}


def usage(binaries: list[dict], component: str, version: str, repos: list[str] | None = None) -> dict:
    """{'dlls': [...], 'functions': {name, ...}, 'importers': n} for one component version.

    The DLLs are the binaries that *are* this library: identified from their version resource or file name (not
    a copy found statically linked inside another binary, whose callers would be calling that binary's own API),
    plus the other modules of the same library (Qt5Gui.dll next to Qt5Core.dll) with the same version.
    Importers are the other binaries of the same repository that import from those DLLs (a same-named DLL of
    another version shipped elsewhere is not this one). Statically linked copies have no DLL, so their use cannot
    be seen here."""
    name = component.lower()
    family = DLL_FAMILY.get(name)
    binaries = [b for b in binaries if repos is None or b.get("repo", "") in repos]
    dlls = set()  # (repository, file name)
    for b in binaries:
        fname = (b.get("repo", ""), b["path"].rsplit("/", 1)[-1].lower())
        if any(c.get("product", "").lower() == name and c.get("version") == version
               and not str(c.get("rule", "")).startswith("embedded signature") for c in b.get("components", [])):
            dlls.add(fname)
        elif family and re.match(family, fname[1]) and numbers(str(b.get("file_version") or "")
                                                           )[:len(numbers(version))] == numbers(version):
            dlls.add(fname)
    funcs, importers = set(), 0
    for b in binaries:
        if (b.get("repo", ""), b["path"].rsplit("/", 1)[-1].lower()) in dlls:
            continue
        hit = False
        for dll, names in (b.get("imports") or {}).items():
            if (b.get("repo", ""), dll) in dlls:
                funcs.update(f for f in map(callable_name, names) if f)
                hit = True
        importers += hit
    return {"dlls": sorted({f for _, f in dlls}), "functions": funcs, "importers": importers}


_IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b")
_QUALIFIED = re.compile(r"\b([A-Za-z_]\w*)::([A-Za-z_]\w*)")
_MSVC_METHOD = re.compile(r"^\?([A-Za-z_]\w*)@([A-Za-z_]\w*)@")


def callable_name(imported: str) -> str:
    """How release notes name an imported function: C names as they are, MSVC-mangled C++ methods as
    'Class::method' (constructors, operators and ordinals cannot be named reliably and are skipped)."""
    if imported.startswith("#"):
        return ""
    if imported.startswith("?"):
        m = _MSVC_METHOD.match(imported)
        return f"{m.group(2)}::{m.group(1)}" if m else ""
    return imported if _IDENT.fullmatch(imported) else ""


def mentioned(text: str, functions: set[str]) -> list[str]:
    """Imported functions named in text: exact C identifiers, or qualified 'Class::method' for C++."""
    text = text or ""
    hits = set(_IDENT.findall(text)) & functions
    hits |= {f"{a}::{b}" for a, b in _QUALIFIED.findall(text)} & functions
    return sorted(hits)
