#!/usr/bin/env bash
# Fetches what `make conformance` runs against, at exact versions, so the evidence does not depend on
# anyone's home directory (ADR-0001 section 7):
#   runner            @modelcontextprotocol/conformance 0.2.0-alpha.12, installed by `npm ci` from the committed
#                     package-lock.json (integrity hashes); lands in tests/conformance/runner/node_modules
#   reference server  the Python SDK's "Everything Server" at one commit, its dependencies from the SDK's own
#                     uv.lock (`uv sync --frozen`, hashes); lands in $CONFORMANCE_DEPS/python-sdk
# Each part is skipped when the variable that overrides it (CONFORMANCE_ROOT, REFERENCE_SERVER) is given to make,
# and when it is already in place. To move to another version change the pin here (SDK) or in package.json and
# package-lock.json (runner), and record the new run in the ADR.
set -euo pipefail

SDK_URL=https://github.com/modelcontextprotocol/python-sdk
SDK_COMMIT=754254c08fe1c3eda18b69da3d336106fe8d72d6
UV_VERSION=0.12.18 # only used when uv is not installed

here="$(cd "$(dirname "$0")" && pwd)"
deps="${CONFORMANCE_DEPS:-$here/../../build/conformance-deps}"
mkdir -p "$deps"
deps="$(cd "$deps" && pwd)"

if [[ "${FETCH_RUNNER:-1}" == 1 && ! -f "$here/runner/node_modules/@modelcontextprotocol/conformance/dist/index.js" ]]; then
  echo "fetching the conformance runner (npm ci, locked)"
  (cd "$here/runner" && npm ci --ignore-scripts --no-audit --no-fund)
fi

if [[ "${FETCH_REFERENCE:-1}" == 1 && ! -x "$deps/python-sdk/.venv/bin/mcp-everything-server" ]]; then
  echo "fetching the reference server (python-sdk $SDK_COMMIT, uv sync --frozen)"
  if command -v uv >/dev/null; then
    uv=uv
  else
    python3 -m venv "$deps/uv-venv"
    "$deps/uv-venv/bin/pip" install --quiet "uv==$UV_VERSION"
    uv="$deps/uv-venv/bin/uv"
  fi
  rm -rf "$deps/python-sdk"
  mkdir -p "$deps/python-sdk"
  git -C "$deps/python-sdk" init --quiet
  git -C "$deps/python-sdk" fetch --quiet --depth 1 "$SDK_URL" "$SDK_COMMIT"
  git -C "$deps/python-sdk" checkout --quiet FETCH_HEAD
  [[ "$(git -C "$deps/python-sdk" rev-parse HEAD)" == "$SDK_COMMIT" ]] # the fetch gave the pinned commit
  (cd "$deps/python-sdk" && "$uv" sync --frozen --package mcp-everything-server)
fi
