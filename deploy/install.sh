#!/bin/bash
# =============================================================================
# usulnet - Quick Install Script
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/fr4nsys/usulnet/main/deploy/install.sh | bash
#
# Or download and run manually:
#   chmod +x install.sh && ./install.sh
#
# =============================================================================
set -euo pipefail

INSTALL_DIR="${USULNET_DIR:-/opt/usulnet}"
REPO_BASE="https://raw.githubusercontent.com/fr4nsys/usulnet/main/deploy"

echo "============================================"
echo " usulnet Docker Management Platform"
echo " Installation Script"
echo "============================================"
echo ""

# --- Prerequisites ---

if ! command -v docker &>/dev/null; then
    echo "ERROR: Docker is not installed."
    echo "Install Docker: https://docs.docker.com/engine/install/"
    exit 1
fi

if ! docker compose version &>/dev/null 2>&1; then
    echo "ERROR: Docker Compose v2 is not available."
    echo "Install: https://docs.docker.com/compose/install/"
    exit 1
fi

if ! command -v openssl &>/dev/null; then
    echo "WARNING: openssl not found. Secrets will use /dev/urandom fallback."
fi

if ! command -v curl &>/dev/null; then
    echo "ERROR: curl is required."
    exit 1
fi

# --- Create directory ---

echo "Install directory: ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
cd "${INSTALL_DIR}"

# --- Download files ---

echo "Downloading configuration files..."
curl -fsSL "${REPO_BASE}/docker-compose.prod.yml" -o docker-compose.yml
curl -fsSL "${REPO_BASE}/.env.example" -o .env

# --- Generate secrets ---

echo "Generating secure secrets..."

generate_hex() {
    if command -v openssl &>/dev/null; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | xxd -p -c 64
    fi
}

generate_password() {
    if command -v openssl &>/dev/null; then
        openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32
    else
        head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32
    fi
}

DB_PASSWORD=$(generate_password)
JWT_SECRET=$(generate_hex)
ENCRYPTION_KEY=$(generate_hex)

# Replace placeholders in .env
sed -i "s|CHANGE_ME_GENERATE_RANDOM_PASSWORD|${DB_PASSWORD}|" .env
sed -i "s|CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32|${JWT_SECRET}|" .env
# Second replacement for ENCRYPTION_KEY (sed replaces first match only without g flag,
# but since the first was already replaced, this hits the second)
sed -i "s|CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32|${ENCRYPTION_KEY}|" .env

# --- Start ---

echo ""
echo "Starting usulnet..."
docker compose up -d

echo ""
echo "============================================"
echo " usulnet installed successfully!"
echo "============================================"
echo ""
echo " Access usulnet:"
echo "   HTTPS: https://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):7443"
echo "   HTTP:  http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):8080"
echo ""
echo " Files: ${INSTALL_DIR}/"
echo ""
echo " Useful commands:"
echo "   cd ${INSTALL_DIR}"
echo "   docker compose logs -f          # View logs"
echo "   docker compose restart          # Restart"
echo "   docker compose down             # Stop"
echo "   docker compose pull && docker compose up -d  # Update"
echo ""
