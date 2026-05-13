# =============================================================================
# usulnet Docker Management Platform
# Optimized multi-stage production build
# =============================================================================

# Default BUILDPLATFORM for non-buildx environments (legacy Docker build)
ARG BUILDPLATFORM=linux/amd64

# Stage 1: Build Go binary with Templ compilation
# --platform=$BUILDPLATFORM: run Go compiler natively (fast), cross-compile via GOARCH
FROM --platform=$BUILDPLATFORM golang:1.25.7-alpine AS builder

ARG TARGETARCH
ARG TARGETOS=linux

RUN apk add --no-cache git ca-certificates tzdata

# Install templ CLI (must match go.mod version)
RUN go install github.com/a-h/templ/cmd/templ@v0.3.977

WORKDIR /build

# Copy dependency files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Generate Go code from .templ files
RUN templ generate

# Tidy modules after templ generate (adds templ runtime dependency)
RUN go mod tidy

# Build the binary with optimizations
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-w -s \
        -X github.com/fr4nsys/usulnet/internal/app.Version=${VERSION} \
        -X github.com/fr4nsys/usulnet/internal/app.Commit=${COMMIT} \
        -X github.com/fr4nsys/usulnet/internal/app.BuildTime=${BUILD_TIME}" \
    -o usulnet \
    ./cmd/usulnet

# =============================================================================
# Stage 2: Compile Tailwind CSS (standalone binary, no Node.js/npm)
# =============================================================================
# --platform=$BUILDPLATFORM: Tailwind runs at build time only, use host arch.
# CSS output is architecture-independent so we only need Tailwind to run, not
# match the target. Using BUILDARCH avoids QEMU and is much faster.
FROM --platform=$BUILDPLATFORM alpine:3.21 AS frontend

ARG BUILDARCH

RUN apk add --no-cache curl

WORKDIR /frontend

# Download Tailwind CSS standalone CLI (no Node.js dependency)
# Map Docker BUILDARCH (amd64/arm64) → Tailwind release name (x64/arm64)
ARG TAILWIND_VERSION=3.4.17
RUN if [ "${BUILDARCH}" = "arm64" ]; then TAILWIND_ARCH="arm64"; else TAILWIND_ARCH="x64"; fi && \
    curl -fsSL -o /usr/local/bin/tailwindcss \
    "https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VERSION}/tailwindcss-linux-${TAILWIND_ARCH}" && \
    chmod +x /usr/local/bin/tailwindcss

# Copy Tailwind source, config, and templates for class scanning
COPY web/static/src/input.css ./src/input.css
COPY web/static/tailwind.docker.config.js ./tailwind.config.js
COPY internal/web/templates ./templates

# Compile CSS (config scans .templ files for classes)
RUN mkdir -p css && \
    tailwindcss --config ./tailwind.config.js -i src/input.css -o css/style.css --minify

# =============================================================================
# Stage 3: Runtime image (production-optimized)
# =============================================================================
FROM alpine:3.21

ARG TARGETARCH

# OCI image metadata labels
LABEL org.opencontainers.image.title="usulnet" \
      org.opencontainers.image.description="Docker Management Platform" \
      org.opencontainers.image.url="https://github.com/fr4nsys/usulnet" \
      org.opencontainers.image.source="https://github.com/fr4nsys/usulnet" \
      org.opencontainers.image.vendor="usulnet" \
      org.opencontainers.image.licenses="AGPL-3.0"

# All runtime packages in a single layer (includes nvim editor deps)
# Minimized apk cache by combining all installs
RUN apk add --no-cache \
    ca-certificates tzdata curl su-exec util-linux \
    docker-cli docker-cli-compose \
    neovim git ripgrep fd \
    musl-locales musl-locales-lang && \
    # Install Trivy vulnerability scanner
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    # Clean up curl caches
    rm -rf /tmp/* /var/cache/apk/*

# Overwrite Alpine's docker-cli (27.x, API 1.47) with Docker 29.2.0 (API 1.53)
# to match host daemon. Compose plugin stays from Alpine package.
# Map Docker TARGETARCH (amd64/arm64) → Docker release dir (x86_64/aarch64)
RUN if [ "${TARGETARCH}" = "arm64" ]; then DOCKER_ARCH="aarch64"; else DOCKER_ARCH="x86_64"; fi && \
    rm -f /usr/bin/docker && \
    curl -fsSL "https://download.docker.com/linux/static/stable/${DOCKER_ARCH}/docker-29.2.0.tgz" | \
    tar xz --strip-components=1 -C /usr/bin docker/docker && \
    chmod +x /usr/bin/docker && \
    rm -rf /tmp/*

# Locale for nvim unicode support (musl-based)
ENV LANG=en_US.UTF-8
ENV MUSL_LOCPATH=/usr/share/i18n/locales/musl

# Create non-root user
RUN addgroup -g 1000 usulnet && \
    adduser -u 1000 -G usulnet -s /bin/sh -D usulnet

# Create required directories with proper ownership in a single layer
RUN mkdir -p /app/data /app/config /app/web/static/css /var/lib/usulnet/trivy && \
    chown -R usulnet:usulnet /app /var/lib/usulnet

WORKDIR /app

# Copy binary (Templ templates compiled into it)
COPY --from=builder --chown=usulnet:usulnet /build/usulnet /app/usulnet

# Copy compiled CSS
COPY --from=frontend --chown=usulnet:usulnet /frontend/css/style.css /app/web/static/css/style.css

# Copy favicon if exists
COPY --from=builder --chown=usulnet:usulnet /build/web/static/favicon.ico /app/web/static/favicon.ico

# Copy JS assets (guacamole-common-js, etc.)
COPY --from=builder --chown=usulnet:usulnet /build/web/static/js/ /app/web/static/js/

# Copy self-hosted vendor assets (HTMX, Alpine.js, Font Awesome, fonts)
COPY --from=builder --chown=usulnet:usulnet /build/web/static/vendor/ /app/web/static/vendor/

# --- Neovim editor support (Phase 7) ---
COPY --chown=usulnet:usulnet nvim/ /opt/usulnet/nvim-config/

# Pre-install lazy.nvim + plugins so first session is instant.
# Runs as root during build, data copied to shared location.
RUN set -e && \
    mkdir -p /tmp/nvim-setup/.config/nvim && \
    cp -a /opt/usulnet/nvim-config/. /tmp/nvim-setup/.config/nvim/ && \
    HOME=/tmp/nvim-setup \
      XDG_CONFIG_HOME=/tmp/nvim-setup/.config \
      XDG_DATA_HOME=/tmp/nvim-setup/.local/share \
      XDG_STATE_HOME=/tmp/nvim-setup/.local/state \
      XDG_CACHE_HOME=/tmp/nvim-setup/.cache \
      nvim --headless "+Lazy! install" +qa 2>&1 && \
    mkdir -p /opt/usulnet/nvim-data && \
    cp -a /tmp/nvim-setup/.local/share/nvim/. /opt/usulnet/nvim-data/ && \
    rm -rf /tmp/nvim-setup

# Fix ownership: /app for the binary, /opt/usulnet for nvim config+plugins
RUN chown -R usulnet:usulnet /app /opt/usulnet

# Entrypoint auto-detects Docker socket GID and drops to usulnet
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 8080 7443

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/app/usulnet", "serve", "--config", "/app/config/config.yaml"]
