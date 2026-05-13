# =============================================================================
# usulnet recon-spiderfoot
#
# SpiderFoot at a pinned upstream tag, behind the usulnet sandbox.  The
# image is multi-arch (linux/amd64, linux/arm64), runs as UID 65534, and
# binds the HTTP API on 0.0.0.0:5001 (only ever reachable from the
# dedicated usulnet-recon Docker network — never published to the host).
# =============================================================================
# NOTE: SpiderFoot v4.0 pins ancient deps (lxml<5, pyyaml<6, pyOpenSSL<22).
# PyYAML 5.4.1 — the only version satisfying SpiderFoot's `pyyaml<6,>=5.4.1`
# range — has no wheels past cp39 and fails to build from source under
# Cython>=3 with "AttributeError: 'build_ext' object has no attribute
# 'cython_sources'".  Wheels exist for every other SpiderFoot dep on
# cp39, so we pin Python 3.9.  Bump back to a newer slim image when
# upstream loosens these bounds.
FROM python:3.9-slim

# Pin the SpiderFoot tag.  Overridable via --build-arg in CI but the
# default matches docs/v26.5/references.md.
ARG SF_VERSION=v4.0

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Build deps (git for fetch, build-essential for any wheels lacking
# prebuilt binaries) are installed, used, then purged so they do not
# bloat the final image.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        build-essential && \
    git clone --depth 1 --branch "${SF_VERSION}" \
        https://github.com/smicallef/spiderfoot.git /opt/spiderfoot && \
    pip install --no-cache-dir -r /opt/spiderfoot/requirements.txt && \
    apt-get purge -y --auto-remove git build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /opt/spiderfoot/.git

# Entrypoint writes a minimal config on first start and execs sf.py.
COPY entrypoint.sh /usr/local/bin/recon-spiderfoot
RUN chmod 0755 /usr/local/bin/recon-spiderfoot

# Non-root user (matches sandbox spec).  /opt/spiderfoot stays root-owned
# (read-only for the runtime user); SpiderFoot writes its sqlite db and
# config to $HOME=/tmp, which the sandbox launcher mounts as tmpfs.
RUN groupadd --system --gid 65534 usulnet 2>/dev/null || true && \
    useradd --system --uid 65534 --gid 65534 --home-dir /tmp --shell /usr/sbin/nologin usulnet 2>/dev/null || true

USER 65534:65534
WORKDIR /tmp

ENV HOME=/tmp
ENV SPIDERFOOT_HOME=/tmp

EXPOSE 5001

LABEL org.opencontainers.image.title="usulnet-recon-spiderfoot" \
      org.opencontainers.image.description="SpiderFoot OSINT engine packaged for the usulnet recon sandbox" \
      org.opencontainers.image.source="https://github.com/fr4nsys/usulnet" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENTRYPOINT ["/usr/local/bin/recon-spiderfoot"]
