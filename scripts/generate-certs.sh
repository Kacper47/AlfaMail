#!/usr/bin/env bash
# Generates a self-signed TLS certificate for LOCAL DEVELOPMENT ONLY.
# Output: nginx.crt and nginx.key in the project root (git-ignored).
# Usage: ./scripts/generate-certs.sh [output_dir]
set -euo pipefail

OUT_DIR="${1:-$(cd "$(dirname "$0")/.." && pwd)}"

if [[ -e "$OUT_DIR/nginx.key" || -e "$OUT_DIR/nginx.crt" ]]; then
  echo "nginx.key / nginx.crt already exist in $OUT_DIR - delete them first to regenerate." >&2
  exit 1
fi

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$OUT_DIR/nginx.key" -out "$OUT_DIR/nginx.crt" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 "$OUT_DIR/nginx.key"
echo "Created $OUT_DIR/nginx.crt and $OUT_DIR/nginx.key"
