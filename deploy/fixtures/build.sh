#!/usr/bin/env bash
# Build the upstream test-double image (two real MCP SDK servers) offline, for deploy/e2e.sh.
#   minimal   Node SDK modern-only reference server (echo/sum), :3111
#   reference Python SDK "Everything Server" (the conformance reference), :3221
# Sources (override by env): IDP_FIXTURE_MINIMAL_DIR  Node reference checkout (src/sdk/server.mjs, node_modules)
#                            IDP_FIXTURE_PYSDK_DIR    python-sdk checkout with a populated .venv (mcp-everything-server)
# The originals bind 127.0.0.1 and validate localhost Host headers, so the copies are patched here.
# Usage: bash deploy/fixtures/build.sh [TAG]      (default idp-fixture-upstream:local)
set -euo pipefail
cd "$(dirname "$0")/../.."
TAG="${1:-idp-fixture-upstream:local}"
MINIMAL="${IDP_FIXTURE_MINIMAL_DIR:-$HOME/workspace/idp-agentic/IDP_MCP_P2_01_Modern_Only_Reference}"
PYSDK="${IDP_FIXTURE_PYSDK_DIR:-$HOME/workspace/idp-agentic/mcp/IDP_MCP_P2_01F_Conformance_Fixture_V1.0/upstream/python-sdk}"
NODE="$(command -v node)" || { echo 'BLOCKED: node not found' >&2; exit 2; }
SITE="$(echo "$PYSDK"/.venv/lib/python3.12/site-packages)"
for p in "$MINIMAL/src/sdk/server.mjs" "$MINIMAL/node_modules" "$SITE/mcp_everything_server-0.1.0.dist-info" \
         "$PYSDK/src/mcp" "$PYSDK/examples/servers/everything-server/mcp_everything_server"; do
  [[ -e "$p" ]] || { echo "BLOCKED: missing $p" >&2; exit 2; }
done
OUT=build/fixtures; rm -rf "$OUT"; mkdir -p "$OUT/minimal" "$OUT/pysdk/everything"
cp "$NODE" "$OUT/node"
cp -r "$MINIMAL/package.json" "$MINIMAL/src" "$MINIMAL/node_modules" "$OUT/minimal/"
# listen on all interfaces of the container netns; accept any Host (private service names)
sed -i -e "s|^const HOST = '127.0.0.1';|const HOST = process.env.MCP_HOST ?? '0.0.0.0';|" \
       -e "s|^const validateHost = localhostHostValidation();|const validateHost = () => true;|" \
       -e "s|^const validateOrigin = localhostOriginValidation();|const validateOrigin = () => true;|" "$OUT/minimal/src/sdk/server.mjs"
grep -q "process.env.MCP_HOST" "$OUT/minimal/src/sdk/server.mjs" && grep -q "validateHost = () => true" "$OUT/minimal/src/sdk/server.mjs" \
  || { echo 'BLOCKED: fixture server patch did not apply (source changed?)' >&2; exit 2; }
rsync -a --exclude '__pycache__' --exclude '*.pth' --exclude 'pip*' --exclude '_pytest' --exclude 'pyright*' \
  "$SITE/" "$OUT/pysdk/site-packages/"
cp -r "$PYSDK/src" "$OUT/pysdk/src"
cp -r "$PYSDK/examples/servers/everything-server/mcp_everything_server" "$OUT/pysdk/everything/"
cp deploy/fixtures/Dockerfile.upstream deploy/fixtures/reference_main.py "$OUT/"
BASE="$(sed -nE 's/^ARG BASE=(.*)$/\1/p' deploy/fixtures/Dockerfile.upstream)"
docker image inspect "$BASE" > /dev/null 2>&1 || docker pull -q "$BASE" > /dev/null
docker build --network none --pull=false -t "$TAG" -f "$OUT/Dockerfile.upstream" "$OUT" > "$OUT/build.log" 2>&1 \
  || { tail -20 "$OUT/build.log" >&2; echo 'BLOCKED: docker build failed' >&2; exit 2; }
echo "OK: $TAG $(docker image inspect --format '{{.Id}}' "$TAG")"
