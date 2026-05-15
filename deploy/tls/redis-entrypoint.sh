#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2024-2026 usulnet contributors
# https://github.com/fr4nsys/usulnet
#
# redis-entrypoint.sh — opt-in TLS bootstrap for the in-cluster Redis
# container.
#
# Wired as the container entrypoint in docker-compose.yml. The script
# is a dispatcher: when USULNET_TLS_LOCAL_SERVICES is unset or false,
# it execs the stock redis-entrypoint and Redis behaves exactly like
# before (plain TCP on 6379). When the flag is true it generates a
# self-signed ECDSA P-256 server certificate (3650 days) on first
# boot and starts redis-server with TLS bound on the standard 6379
# port — plain TCP is disabled. The same certificate doubles as the
# CA so a client mounting it can verify-full.
#
# Defaults stay plain TCP — this script is opt-in via env var only.

set -eu

if [ "${USULNET_TLS_LOCAL_SERVICES:-false}" != "true" ]; then
    exec docker-entrypoint.sh "$@"
fi

CERT_DIR="${USULNET_REDIS_TLS_DIR:-/tls}"
CERT_FILE="$CERT_DIR/redis.crt"
KEY_FILE="$CERT_DIR/redis.key"
CA_FILE="$CERT_DIR/ca.crt"
SUBJECT="${USULNET_REDIS_TLS_SUBJECT:-/CN=usulnet-redis}"
SAN="${USULNET_REDIS_TLS_SAN:-DNS:redis,DNS:localhost,IP:127.0.0.1}"

mkdir -p "$CERT_DIR"

if [ ! -s "$CERT_FILE" ] || [ ! -s "$KEY_FILE" ]; then
    echo "usulnet-redis: generating self-signed ECDSA P-256 TLS cert"
    openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_FILE"
    openssl req -new -x509 \
        -key "$KEY_FILE" \
        -out "$CERT_FILE" \
        -days 3650 \
        -subj "$SUBJECT" \
        -addext "subjectAltName=$SAN"
    cp "$CERT_FILE" "$CA_FILE"
fi

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE" "$CA_FILE"

exec redis-server \
    --port 0 \
    --tls-port 6379 \
    --tls-cert-file "$CERT_FILE" \
    --tls-key-file "$KEY_FILE" \
    --tls-ca-cert-file "$CA_FILE" \
    --tls-auth-clients no \
    --appendonly yes \
    --maxmemory 256mb \
    --maxmemory-policy allkeys-lru \
    --save 60 1000 \
    --tcp-backlog 511
