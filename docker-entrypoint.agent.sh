#!/bin/sh
set -e

# =============================================================================
# usulnet Agent Docker Entrypoint
# Auto-detects Docker socket GID and drops privileges to usulnet user
# =============================================================================

USULNET_USER="usulnet"

# ---------------------------------------------------------------------------
# Auto-detect Docker socket path (unless DOCKER_SOCKET is already set)
# ---------------------------------------------------------------------------
detect_docker_socket() {
    # 1. Standard path
    if [ -S "/var/run/docker.sock" ]; then
        echo "/var/run/docker.sock"; return
    fi

    # 2. XDG_RUNTIME_DIR (rootless Docker)
    if [ -n "$XDG_RUNTIME_DIR" ] && [ -S "$XDG_RUNTIME_DIR/docker.sock" ]; then
        echo "$XDG_RUNTIME_DIR/docker.sock"; return
    fi

    # 3. /run/user/<UID>/docker.sock (rootless Docker)
    _uid=$(id -u)
    if [ -S "/run/user/${_uid}/docker.sock" ]; then
        echo "/run/user/${_uid}/docker.sock"; return
    fi

    # 4. docker context inspect (if docker CLI is available)
    if command -v docker >/dev/null 2>&1; then
        _ctx_host=$(docker context inspect 2>/dev/null \
            | sed -n 's/.*"Host"[[:space:]]*:[[:space:]]*"unix:\/\/\(.*\)".*/\1/p' \
            | head -n1)
        if [ -n "$_ctx_host" ] && [ -S "$_ctx_host" ]; then
            echo "$_ctx_host"; return
        fi
    fi

    # 5. Fallback
    echo "/var/run/docker.sock"
}

if [ -n "$DOCKER_SOCKET" ]; then
    # Explicitly set by user — use as-is
    :
elif [ -n "$DOCKER_HOST" ] && echo "$DOCKER_HOST" | grep -q '^unix://'; then
    # Derive from standard DOCKER_HOST env var
    DOCKER_SOCKET=$(echo "$DOCKER_HOST" | sed 's|^unix://||')
else
    DOCKER_SOCKET=$(detect_docker_socket)
fi

export DOCKER_SOCKET

# If running as root, configure Docker socket access and drop to usulnet
if [ "$(id -u)" = "0" ]; then
    # Auto-detect Docker socket GID and grant access
    if [ -S "$DOCKER_SOCKET" ]; then
        SOCK_GID=$(stat -c '%g' "$DOCKER_SOCKET")

        EXISTING_GROUP=$(getent group "$SOCK_GID" | cut -d: -f1 || true)

        if [ -z "$EXISTING_GROUP" ]; then
            addgroup -g "$SOCK_GID" docker 2>/dev/null || true
            EXISTING_GROUP="docker"
        fi

        addgroup "$USULNET_USER" "$EXISTING_GROUP" 2>/dev/null || true

        echo "Docker socket GID=$SOCK_GID, added $USULNET_USER to group $EXISTING_GROUP"
    else
        echo "WARNING: Docker socket not found at $DOCKER_SOCKET"
        echo "  Searched: /var/run/docker.sock, \$XDG_RUNTIME_DIR/docker.sock, /run/user/<UID>/docker.sock, docker context"
        echo "  Set DOCKER_SOCKET or DOCKER_HOST to specify the path manually."
    fi

    # Ensure data directories are owned by usulnet
    chown -R "$USULNET_USER:$USULNET_USER" /app/data 2>/dev/null || true
    chown -R "$USULNET_USER:$USULNET_USER" /app/certs 2>/dev/null || true

    # Write PID file for healthcheck
    echo $$ > /app/data/agent.pid

    # Drop privileges and exec the command
    exec su-exec "$USULNET_USER" "$@"
fi

# Already running as non-root
echo $$ > /app/data/agent.pid
exec "$@"
