# vulnscan - vulnerability scanner for shipped SVN deliverables
#
# Every third-party scanner is pinned to an exact version and checksum-verified,
# base images are pinned by digest, and Python
# dependencies are resolved as of a fixed date, so a report can always be traced
# back to an exact, rebuildable toolchain.
#
#   docker build -t vulnscan .        (or: podman build -t vulnscan .)

FROM ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 AS uv

FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

ARG SYFT_VERSION=1.55.0
ARG SYFT_SHA256=bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d
ARG GRYPE_VERSION=0.121.0
ARG GRYPE_SHA256=64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519
ARG OSV_SCANNER_VERSION=2.7.0
ARG OSV_SCANNER_SHA256=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
ARG NODE_VERSION=24.22.2
ARG NODE_SHA256=48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75
ARG RETIRE_VERSION=6.1.0
# Python packages are resolved as they existed on this date (reproducible builds).
ARG PY_DEPS_DATE=2026-10-20T00:00:00Z

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    UV_NO_CACHE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl tzdata subversion 7zip msitools xz-utils bzip2 sqlite3 \
      python3 \
 && rm -rf /var/lib/apt/lists/*

# --- Go-based scanners (checksum-verified release artifacts) ------------------
RUN set -eux; cd /tmp; \
    curl -fsSLo syft.tgz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz"; \
    echo "${SYFT_SHA256}  syft.tgz" | sha256sum -c -; \
    tar -xzf syft.tgz -C /usr/local/bin syft; \
    curl -fsSLo grype.tgz "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz"; \
    echo "${GRYPE_SHA256}  grype.tgz" | sha256sum -c -; \
    tar -xzf grype.tgz -C /usr/local/bin grype; \
    curl -fsSLo /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"; \
    echo "${OSV_SCANNER_SHA256}  /usr/local/bin/osv-scanner" | sha256sum -c -; \
    chmod +x /usr/local/bin/osv-scanner; \
    rm -f /tmp/*.tgz; \
    syft version; grype version; osv-scanner --version

# --- retire.js on the official Node.js LTS runtime ------------------------------
# npm is only needed to install retire.js; it is removed afterwards so its large
# bundled dependency tree is not shipped in the image.
RUN set -eux; cd /tmp; \
    curl -fsSLo node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"; \
    echo "${NODE_SHA256}  node.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/node; tar -xJf node.tar.xz -C /opt/node --strip-components=1; rm node.tar.xz; \
    ln -s /opt/node/bin/node /usr/local/bin/node; \
    /opt/node/bin/node /opt/node/lib/node_modules/npm/bin/npm-cli.js install -g --prefix /opt/retire \
        --no-fund --no-audit --no-update-notifier "retire@${RETIRE_VERSION}"; \
    ln -s /opt/retire/bin/retire /usr/local/bin/retire; \
    rm -rf /opt/node/lib/node_modules/npm /opt/node/lib/node_modules/corepack /opt/node/bin/npm \
           /opt/node/bin/npx /opt/node/bin/corepack /opt/node/include /root/.npm; \
    node --version; retire --version

# --- Python orchestrator ------------------------------------------------------
COPY --from=uv /uv /usr/local/bin/uv
RUN uv venv --python /usr/bin/python3 /opt/venv \
 && VIRTUAL_ENV=/opt/venv uv pip install --exclude-newer "${PY_DEPS_DATE}" pefile xlsxwriter rich cvss
ENV PATH="/opt/venv/bin:${PATH}"

# Unprivileged user the scanner switches to at start-up (see util.drop_privileges):
# untrusted content is never processed as root.
RUN useradd --system --uid 10001 --user-group --home-dir /cache/home --no-create-home \
      --shell /usr/sbin/nologin vulnscan

COPY vulnscan /opt/vulnscan/vulnscan
ENV PYTHONPATH=/opt/vulnscan

# Caches live in a named volume (/cache) so checkouts and vulnerability databases
# persist between runs; reports are written to /work (bind-mount your folder there).
ENV VULNSCAN_CACHE=/cache \
    GRYPE_DB_CACHE_DIR=/cache/db/grype \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/cache/db/osv \
    HOME=/cache/home \
    TERM=xterm-256color

VOLUME ["/cache"]
WORKDIR /work
ENTRYPOINT ["python", "-m", "vulnscan"]
CMD ["--help"]
