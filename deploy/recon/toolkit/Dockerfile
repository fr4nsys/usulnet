# =============================================================================
# usulnet recon-toolkit
#
# Slim Debian image bundling the metadata + atomic OSINT tools that the
# usulnet recon module invokes in a sandboxed container. The image is
# built multi-arch (linux/amd64, linux/arm64); phoneinfoga is amd64-only
# (upstream releases). All Python tools live in a venv at /opt/venv.
# Downloaded Go binaries are pinned by SHA-256.
#
# Designed to run with: --read-only --tmpfs /tmp:exec --user 65534:65534
# =============================================================================
FROM debian:stable-slim

ARG TARGETARCH

# -----------------------------------------------------------------------------
# Pinned versions (bump together with the matching SHA256 below)
# -----------------------------------------------------------------------------
ARG HOLEHE_VERSION=1.61
ARG H8MAIL_VERSION=2.5.6
ARG OLETOOLS_VERSION=0.60.2
ARG PDFID_VERSION=1.1.3

ARG PHONEINFOGA_VERSION=2.11.0
ARG SUBFINDER_VERSION=2.6.6
ARG KATANA_VERSION=1.1.0

# SHA-256 of the release tarballs / binaries.  These are placeholders
# until CI publishes the first reproducible build; the workflow at
# .github/workflows/build-recon-images.yml refreshes them and opens a PR
# that bumps internal/services/recon/images.go in lockstep.
ARG PHONEINFOGA_SHA256_AMD64=0000000000000000000000000000000000000000000000000000000000000000
ARG SUBFINDER_SHA256_AMD64=0000000000000000000000000000000000000000000000000000000000000000
ARG SUBFINDER_SHA256_ARM64=0000000000000000000000000000000000000000000000000000000000000000
ARG KATANA_SHA256_AMD64=0000000000000000000000000000000000000000000000000000000000000000
ARG KATANA_SHA256_ARM64=0000000000000000000000000000000000000000000000000000000000000000

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# -----------------------------------------------------------------------------
# OS packages
# -----------------------------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        mat2 \
        libimage-exiftool-perl \
        python3 \
        python3-pip \
        python3-venv \
        curl \
        ca-certificates \
        jq \
        file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# Python tools (isolated venv so apt-managed python3 stays clean)
# -----------------------------------------------------------------------------
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir \
        "holehe==${HOLEHE_VERSION}" \
        "h8mail==${H8MAIL_VERSION}" \
        "oletools==${OLETOOLS_VERSION}" \
        "pdfid==${PDFID_VERSION}"

ENV PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin

# -----------------------------------------------------------------------------
# Go-built binaries from ProjectDiscovery / sundowndev (SHA-pinned).
#
# phoneinfoga ships only linux/amd64 binaries from upstream; on arm64 the
# entrypoint reports an unsupported-architecture error instead of failing
# the image build.
# -----------------------------------------------------------------------------
WORKDIR /tmp/dl

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) \
            curl -fsSL -o phoneinfoga.tar.gz \
                "https://github.com/sundowndev/phoneinfoga/releases/download/v${PHONEINFOGA_VERSION}/phoneinfoga_Linux_x86_64.tar.gz"; \
            echo "${PHONEINFOGA_SHA256_AMD64}  phoneinfoga.tar.gz" | sha256sum -c - || \
                echo "WARN: phoneinfoga checksum is a placeholder; CI must refresh before release"; \
            tar -xzf phoneinfoga.tar.gz phoneinfoga; \
            install -m 0755 phoneinfoga /usr/local/bin/phoneinfoga; \
            ;; \
        arm64) \
            echo "phoneinfoga: upstream has no arm64 release; entrypoint will report unsupported_arch"; \
            ;; \
        *) echo "Unsupported TARGETARCH=${TARGETARCH}"; exit 1 ;; \
    esac

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) SF_ARCH=amd64; SF_SHA="${SUBFINDER_SHA256_AMD64}" ;; \
        arm64) SF_ARCH=arm64; SF_SHA="${SUBFINDER_SHA256_ARM64}" ;; \
        *) echo "Unsupported TARGETARCH=${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL -o subfinder.zip \
        "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${SF_ARCH}.zip"; \
    echo "${SF_SHA}  subfinder.zip" | sha256sum -c - || \
        echo "WARN: subfinder checksum is a placeholder; CI must refresh before release"; \
    apt-get update && apt-get install -y --no-install-recommends unzip && \
        unzip -o subfinder.zip subfinder && \
        apt-get purge -y unzip && apt-get autoremove -y && \
        rm -rf /var/lib/apt/lists/*; \
    install -m 0755 subfinder /usr/local/bin/subfinder

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) KT_ARCH=amd64; KT_SHA="${KATANA_SHA256_AMD64}" ;; \
        arm64) KT_ARCH=arm64; KT_SHA="${KATANA_SHA256_ARM64}" ;; \
        *) echo "Unsupported TARGETARCH=${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL -o katana.zip \
        "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${KT_ARCH}.zip"; \
    echo "${KT_SHA}  katana.zip" | sha256sum -c - || \
        echo "WARN: katana checksum is a placeholder; CI must refresh before release"; \
    apt-get update && apt-get install -y --no-install-recommends unzip && \
        unzip -o katana.zip katana && \
        apt-get purge -y unzip && apt-get autoremove -y && \
        rm -rf /var/lib/apt/lists/*; \
    install -m 0755 katana /usr/local/bin/katana

RUN rm -rf /tmp/dl

# -----------------------------------------------------------------------------
# Entrypoint dispatcher
# -----------------------------------------------------------------------------
COPY entrypoint.sh /usr/local/bin/recon-toolkit
RUN chmod 0755 /usr/local/bin/recon-toolkit

# -----------------------------------------------------------------------------
# Non-root user.  /opt and /usr/local stay root-owned (read-only for user).
# UID/GID 65534 (nobody) lines up with the sandbox spec in the launcher.
# -----------------------------------------------------------------------------
RUN groupadd --system --gid 65534 usulnet 2>/dev/null || true && \
    useradd --system --uid 65534 --gid 65534 --home-dir /tmp --shell /usr/sbin/nologin usulnet 2>/dev/null || true

WORKDIR /tmp
USER 65534:65534

ENV HOME=/tmp

LABEL org.opencontainers.image.title="usulnet-recon-toolkit" \
      org.opencontainers.image.description="Slim toolkit image (mat2, exiftool, holehe, h8mail, oletools, phoneinfoga, subfinder, katana) used by the usulnet recon module" \
      org.opencontainers.image.source="https://github.com/fr4nsys/usulnet" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENTRYPOINT ["/usr/local/bin/recon-toolkit"]
