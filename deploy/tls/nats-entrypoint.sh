#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2024-2026 usulnet contributors
# https://github.com/fr4nsys/usulnet
#
# nats-entrypoint.sh — opt-in TLS bootstrap for the in-cluster NATS
# container.
#
# Wired as the container entrypoint in docker-compose.yml. The script
# is a dispatcher: when USULNET_TLS_LOCAL_SERVICES is unset or false,
# it execs nats-server with the stock config file. When the flag is
# true it generates a self-signed ECDSA P-256 server certificate
# (3650 days) on first boot, appends a tls{} block to the mounted
# nats-server.conf, and execs nats-server against the effective copy.
#
# Defaults stay plain TCP — this script is opt-in via env var only.

set -eu

BASE_CONF="${USULNET_NATS_BASE_CONF:-/etc/nats/nats-server.conf}"

if [ "${USULNET_TLS_LOCAL_SERVICES:-false}" != "true" ]; then
    exec nats-server -c "$BASE_CONF" "$@"
fi

CERT_DIR="${USULNET_NATS_TLS_DIR:-/tls}"
CERT_FILE="$CERT_DIR/nats.crt"
KEY_FILE="$CERT_DIR/nats.key"
SUBJECT="${USULNET_NATS_TLS_SUBJECT:-/CN=usulnet-nats}"
SAN="${USULNET_NATS_TLS_SAN:-DNS:nats,DNS:localhost,IP:127.0.0.1}"
EFFECTIVE_CONF="${USULNET_NATS_EFFECTIVE_CONF:-/tmp/nats-server.tls.conf}"

mkdir -p "$CERT_DIR"

# nats:alpine is built minimal — install openssl on first run so the
# self-signed cert can be generated. postgres / redis alpine images
# already ship with openssl, so they skip this step.
if ! command -v openssl >/dev/null 2>&1; then
    apk add --no-cache openssl >/dev/null 2>&1 || true
fi

if [ ! -s "$CERT_FILE" ] || [ ! -s "$KEY_FILE" ]; then
    echo "usulnet-nats: generating self-signed ECDSA P-256 TLS cert"
    openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_FILE"
    openssl req -new -x509 \
        -key "$KEY_FILE" \
        -out "$CERT_FILE" \
        -days 3650 \
        -subj "$SUBJECT" \
        -addext "subjectAltName=$SAN"
fi

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

cp "$BASE_CONF" "$EFFECTIVE_CONF"
cat >> "$EFFECTIVE_CONF" <<EOF

tls {
  cert_file: "$CERT_FILE"
  key_file:  "$KEY_FILE"
  verify:    false
}
EOF

exec nats-server -c "$EFFECTIVE_CONF" "$@"
