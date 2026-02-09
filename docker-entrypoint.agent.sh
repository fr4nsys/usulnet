#!/bin/sh
set -e

# =============================================================================
# usulnet Agent Docker Entrypoint
# Auto-detects Docker socket GID and drops privileges to usulnet user
# =============================================================================

USULNET_USER="usulnet"
DOCKER_SOCKET="/var/run/docker.sock"

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
