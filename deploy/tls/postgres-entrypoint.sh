#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2024-2026 usulnet contributors
# https://github.com/fr4nsys/usulnet
#
# postgres-entrypoint.sh — opt-in TLS bootstrap for the in-cluster
# PostgreSQL container.
#
# Wired as the container entrypoint in docker-compose.yml. The script
# is a dispatcher: when USULNET_TLS_LOCAL_SERVICES is unset or false,
# it execs the stock docker-entrypoint.sh and the postgres container
# behaves exactly like before (plain TCP). When the flag is true it
# generates a self-signed ECDSA P-256 server certificate (3650 days)
# on first boot, fixes the file ownership/permissions the postgres
# user expects, and re-execs the stock entrypoint with `-c ssl=on`
# and the cert paths appended.
#
# Defaults stay plain TCP — this script is opt-in via env var only.

set -eu

if [ "${USULNET_TLS_LOCAL_SERVICES:-false}" != "true" ]; then
    exec docker-entrypoint.sh postgres "$@"
fi

CERT_DIR="${USULNET_PG_TLS_DIR:-/var/lib/postgresql/tls}"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"
SUBJECT="${USULNET_PG_TLS_SUBJECT:-/CN=usulnet-postgres}"
SAN="${USULNET_PG_TLS_SAN:-DNS:postgres,DNS:localhost,IP:127.0.0.1}"

mkdir -p "$CERT_DIR"

if [ ! -s "$CERT_FILE" ] || [ ! -s "$KEY_FILE" ]; then
    echo "usulnet-postgres: generating self-signed ECDSA P-256 TLS cert"
    openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_FILE"
    openssl req -new -x509 \
        -key "$KEY_FILE" \
        -out "$CERT_FILE" \
        -days 3650 \
        -subj "$SUBJECT" \
        -addext "subjectAltName=$SAN"
fi

chown postgres:postgres "$CERT_FILE" "$KEY_FILE"
chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

exec docker-entrypoint.sh postgres \
    -c ssl=on \
    -c ssl_cert_file="$CERT_FILE" \
    -c ssl_key_file="$KEY_FILE" \
    "$@"
