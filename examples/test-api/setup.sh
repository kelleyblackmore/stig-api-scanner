#!/usr/bin/env bash
# Local dev setup: generate a self-signed cert and start the test API server.
# Run from the examples/test-api/ directory.
set -euo pipefail

CERT="cert.pem"
KEY="key.pem"
PORT="${PORT:-8443}"
TOKEN="${API_TOKEN:-stig-test-token}"

if [[ ! -f "$CERT" ]] || [[ ! -f "$KEY" ]]; then
  echo "[setup] Generating self-signed TLS certificate..."
  openssl req -x509 -newkey rsa:2048 \
    -keyout "$KEY" -out "$CERT" \
    -days 90 -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>/dev/null
  echo "[setup] Certificate written to $CERT / $KEY"
fi

export PORT API_TOKEN="$TOKEN" TLS_CERT="$CERT" TLS_KEY="$KEY"
echo "[setup] Starting test API on https://127.0.0.1:${PORT}"
exec python3 server.py
