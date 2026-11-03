#!/usr/bin/env bash
# Build the idp-mcp image offline: static binaries on the host, then docker build --network none.
# Usage: bash deploy/build.sh [TAG]     (default idp-mcp:<commit or dev>)
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
[[ -z "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]] || VERSION="$VERSION-dirty"
TAG="${1:-idp-mcp:$VERSION}"
OUT=build/image
rm -rf "$OUT" && mkdir -p "$OUT"
for cmd in mcp-gateway registry-service; do
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/$cmd" "./cmd/$cmd"
done
cp /etc/ssl/certs/ca-certificates.crt "$OUT/"
cp deploy/Dockerfile "$OUT/"
docker build --network none -q -t "$TAG" "$OUT" > /dev/null
echo "OK: $TAG $(docker image inspect --format '{{.Id}}' "$TAG" | cut -c1-19)… gateway sha256 $(sha256sum "$OUT/mcp-gateway" | cut -c1-12)…"
