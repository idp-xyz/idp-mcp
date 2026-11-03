#!/usr/bin/env bash
# End-to-end on the compose topology with real MCP SDK upstreams. From nothing each run:
# build image -> postgres -> migrate / service login / tenant -> registry -> gateway record and
# credential via the admin API -> gateway container -> tests/e2e (register, discover, approve,
# grant, release, deploy, MCP calls) -> tear down (KEEP=1 leaves it running).
#   MODE=apikey (default)  data plane API keys, HS256 development admin tokens
#   MODE=jwt               Keycloak: admin API verified with JWKS, data plane OAuth bearer JWTs
set -euo pipefail
cd "$(dirname "$0")/.."
ENVF=.local/compose.env
MODE="${MODE:-apikey}"
C=(docker compose -f deploy/compose.yaml --env-file "$ENVF" --profile jwt)
RESOURCE=http://127.0.0.1:3320/mcp
ISSUER=http://127.0.0.1:7080/realms/idp
mkdir -p .local
umask 077
if [[ ! -f "$ENVF" ]]; then
  { echo "IDP_PG_OWNER_PASSWORD=$(openssl rand -hex 16)"
    echo "IDP_APP_DB_PASSWORD=$(openssl rand -hex 16)"
    echo "IDP_DEV_ADMIN_SECRET=$(openssl rand -hex 32)"; } > "$ENVF"
fi
sed -i '/^IDP_GATEWAY_ID=/d; /^IDP_GATEWAY_TOKEN=/d' "$ENVF"
set -a; source "$ENVF"; set +a

if [[ "$MODE" == jwt ]]; then
  TENANT_FIXED="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  FOREIGN="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  rm -rf .local/keycloak && mkdir -p .local/keycloak && chmod 755 .local/keycloak
  python3 deploy/keycloak/realm.py .local/keycloak "$TENANT_FIXED" "$FOREIGN" "$RESOURCE" .local/keycloak-clients.json
  export IDP_ADMIN_JWKS_URL=http://keycloak:7080/realms/idp/protocol/openid-connect/certs IDP_ADMIN_ISSUER="$ISSUER"
fi
docker image inspect "${IDP_FIXTURE_IMAGE:-idp-fixture-upstream:local}" >/dev/null 2>&1 \
  || { echo "BLOCKED: fixture image missing (idp-telos/idp-mcp: bash ops/build_fixtures.sh)" >&2; exit 2; }
bash deploy/build.sh idp-mcp:dev
"${C[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
cleanup() { [[ "${KEEP:-0}" == 1 ]] || "${C[@]}" down -v --remove-orphans >/dev/null 2>&1; }
trap cleanup EXIT

SERVICES=(postgres minimal reference); [[ "$MODE" == jwt ]] && SERVICES+=(keycloak)
"${C[@]}" up -d --wait "${SERVICES[@]}"
"${C[@]}" run --rm -T registry-admin migrate
"${C[@]}" run --rm -T registry-admin ensure-login idp_mcp_svc
TENANT="$("${C[@]}" run --rm -T registry-admin seed-tenant acme ${TENANT_FIXED:-} | sed -n 's/^TENANT_ID=//p')"
[[ -n "$TENANT" ]] || { echo "BLOCKED: no tenant" >&2; exit 2; }
"${C[@]}" up -d registry
for _ in $(seq 1 60); do curl -sf --noproxy '*' http://127.0.0.1:8250/api/v1/health >/dev/null && break; sleep 0.5; done

if [[ "$MODE" == jwt ]]; then
  kc_token() { python3 - "$1" <<'PY'
import json, sys, urllib.parse, urllib.request
c = json.load(open(".local/keycloak-clients.json"))[sys.argv[1]]
data = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": c["clientId"], "client_secret": c["secret"]}).encode()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
print(json.load(opener.open("http://127.0.0.1:7080/realms/idp/protocol/openid-connect/token", data))["access_token"])
PY
  }
  ADMIN="$(kc_token carol)"
  GW_BODY="{\"name\":\"edge-1\",\"authMode\":\"jwt\",\"jwt\":{\"issuer\":\"$ISSUER\",\"resource\":\"$RESOURCE\",\"jwksUrl\":\"http://keycloak:7080/realms/idp/protocol/openid-connect/certs\",\"tenantClaim\":\"tenant_id\",\"rolesClaim\":\"roles\"}}"
else
  ADMIN="$("${C[@]}" run --rm -T registry-admin dev-token "$TENANT" carol admin)"
  GW_BODY='{"name":"edge-1","authMode":"api-key"}'
fi
GW="$(curl -sf --noproxy '*' -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "$GW_BODY" http://127.0.0.1:8250/api/v1/gateways)"
GW_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["gateway"]["gatewayId"])' <<<"$GW")"
GW_TOKEN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<<"$GW")"
printf 'IDP_GATEWAY_ID=%s\nIDP_GATEWAY_TOKEN=%s\n' "$GW_ID" "$GW_TOKEN" >> "$ENVF"
"${C[@]}" up -d mcp-gateway
for _ in $(seq 1 60); do curl -sf --noproxy '*' http://127.0.0.1:3320/healthz >/dev/null && break; sleep 0.5; done

echo "published ports: $(docker ps --filter label=com.docker.compose.project=idp-mcp-go --format '{{.Ports}}' | tr ',' '\n' | grep -- '->' | sed 's/^ *//' | sort -u | tr '\n' ' ')"
set +e
TEST=TestComposeEndToEnd; [[ "$MODE" == jwt ]] && TEST=TestComposeJWT
IDP_E2E_REGISTRY=http://127.0.0.1:8250 IDP_E2E_GATEWAY=http://127.0.0.1:3320 IDP_E2E_TENANT="$TENANT" \
IDP_E2E_GATEWAY_ID="$GW_ID" IDP_E2E_ADMIN_SECRET="$IDP_DEV_ADMIN_SECRET" IDP_E2E_MODE="$MODE" \
IDP_E2E_KEYCLOAK=http://127.0.0.1:7080/realms/idp IDP_E2E_KEYCLOAK_CLIENTS="$PWD/.local/keycloak-clients.json" \
  go test -count=1 -v -run "^$TEST\$" ./tests/e2e/
status=$?
set -e
[[ $status == 0 ]] || "${C[@]}" logs --tail 30 mcp-gateway registry
exit $status
