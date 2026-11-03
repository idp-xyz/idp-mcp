#!/usr/bin/env bash
# End-to-end on the compose topology with real MCP SDK upstreams. From nothing each run:
# build image -> postgres -> migrate / service login / tenant -> registry -> gateway record and
# credential via the admin API -> gateway container -> tests/e2e (register, discover, approve,
# grant, release, deploy, MCP calls) -> tear down (KEEP=1 leaves it running).
#   MODE=apikey (default)  data plane API keys, HS256 development admin tokens
#   MODE=jwt               Keycloak (dev mode): admin API verified with JWKS, data plane OAuth bearer JWTs
#   MODE=oidc              Keycloak in PRODUCTION mode (TLS, PostgreSQL) and TLS on registry and gateway;
#                          real users: authorization code + PKCE, RFC 8693 token exchange and delegation
set -euo pipefail
cd "$(dirname "$0")/.."
ENVF=.local/compose.env
MODE="${MODE:-apikey}"
C=(docker compose -f deploy/compose.yaml --env-file "$ENVF" --profile jwt --profile oidc)
RESOURCE=http://127.0.0.1:3320/mcp
ISSUER=http://127.0.0.1:7080/realms/idp
if [[ "$MODE" == oidc ]]; then RESOURCE=https://localhost:3320/mcp; ISSUER=https://localhost:8443/realms/idp; fi
mkdir -p .local/tls
CURL=(curl -sf --noproxy '*')
[[ "$MODE" == oidc ]] && CURL+=(--cacert .local/tls/ca.crt)
mkdir -p .local
umask 077
if [[ ! -f "$ENVF" ]]; then
  { echo "IDP_PG_OWNER_PASSWORD=$(openssl rand -hex 16)"
    echo "IDP_APP_DB_PASSWORD=$(openssl rand -hex 16)"
    echo "IDP_DEV_ADMIN_SECRET=$(openssl rand -hex 32)"; } > "$ENVF"
fi
grep -q '^KC_BOOTSTRAP_ADMIN_PASSWORD=' "$ENVF" || printf 'KC_BOOTSTRAP_ADMIN_USERNAME=admin\nKC_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 16)" >> "$ENVF"
sed -i '/^IDP_GATEWAY_ID=/d; /^IDP_GATEWAY_TOKEN=/d' "$ENVF"
set -a; source "$ENVF"; set +a

if [[ "$MODE" == jwt || "$MODE" == oidc ]]; then
  TENANT_FIXED="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  FOREIGN="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  rm -rf .local/keycloak && mkdir -p .local/keycloak && chmod 755 .local/keycloak
  FLAG=""; [[ "$MODE" == oidc ]] && FLAG=--oidc
  python3 deploy/keycloak/realm.py .local/keycloak "$TENANT_FIXED" "$FOREIGN" "$RESOURCE" .local/keycloak-clients.json $FLAG
  export IDP_ADMIN_ISSUER="$ISSUER"
  if [[ "$MODE" == oidc ]]; then
    export IDP_ADMIN_JWKS_URL=https://keycloak:8443/realms/idp/protocol/openid-connect/certs
    # a development CA and one server certificate each for Keycloak, the registry and the gateway
    rm -rf .local/tls && mkdir -p .local/tls && chmod 755 .local/tls && ( cd .local/tls
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7 -keyout ca.key -out ca.crt -subj /CN=idp-dev-ca \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
      for n in keycloak registry gateway; do
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$n.key" -out "$n.csr" -subj "/CN=$n" 2>/dev/null
        printf 'subjectAltName=DNS:%s,DNS:localhost,DNS:mcp-gateway,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' "$n" > "$n.ext"
        openssl x509 -req -in "$n.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 7 -out "$n.crt" -extfile "$n.ext" 2>/dev/null
      done
      chmod 644 ./*.crt ./*.key )   # dev keys: the Keycloak container (uid 1000) must read its key
    export IDP_REGISTRY_TLS_CERT=/etc/idp/tls/registry.crt IDP_REGISTRY_TLS_KEY=/etc/idp/tls/registry.key
    export IDP_GATEWAY_TLS_CERT=/etc/idp/tls/gateway.crt IDP_GATEWAY_TLS_KEY=/etc/idp/tls/gateway.key
    export IDP_IDENTITY_CA=/etc/idp/tls/ca.crt IDP_REGISTRY_URL_INTERNAL=https://registry:8250
  else
    export IDP_ADMIN_JWKS_URL=http://keycloak:7080/realms/idp/protocol/openid-connect/certs
  fi
fi
docker image inspect "${IDP_FIXTURE_IMAGE:-idp-fixture-upstream:local}" >/dev/null 2>&1 \
  || { echo "BLOCKED: fixture image missing (idp-telos/idp-mcp: bash ops/build_fixtures.sh)" >&2; exit 2; }
bash deploy/build.sh idp-mcp:dev
"${C[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
cleanup() { [[ "${KEEP:-0}" == 1 ]] || "${C[@]}" down -v --remove-orphans >/dev/null 2>&1; }
trap cleanup EXIT

SERVICES=(postgres minimal reference); [[ "$MODE" == jwt ]] && SERVICES+=(keycloak)
"${C[@]}" up -d --wait "${SERVICES[@]}"
if [[ "$MODE" == oidc ]]; then
  "${C[@]}" exec -T postgres psql -U postgres -q -c 'CREATE DATABASE keycloak' >/dev/null
  "${C[@]}" up -d --wait keycloak-prod
  for _ in $(seq 1 90); do "${CURL[@]}" -o /dev/null "$ISSUER/.well-known/openid-configuration" && break; sleep 2; done
fi
"${C[@]}" run --rm -T registry-admin migrate
"${C[@]}" run --rm -T registry-admin ensure-login idp_mcp_svc
TENANT="$("${C[@]}" run --rm -T registry-admin seed-tenant acme ${TENANT_FIXED:-} | sed -n 's/^TENANT_ID=//p')"
[[ -n "$TENANT" ]] || { echo "BLOCKED: no tenant" >&2; exit 2; }
"${C[@]}" up -d registry
REG=http://127.0.0.1:8250; [[ "$MODE" == oidc ]] && REG=https://localhost:8250
for _ in $(seq 1 60); do "${CURL[@]}" -o /dev/null "$REG/api/v1/health" && break; sleep 0.5; done

if [[ "$MODE" == jwt || "$MODE" == oidc ]]; then
  kc_token() { python3 - "$1" "$ISSUER" <<'PY'
import json, ssl, sys, urllib.parse, urllib.request
c = json.load(open(".local/keycloak-clients.json"))[sys.argv[1]]
data = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": c["clientId"], "client_secret": c["secret"]}).encode()
ctx = ssl.create_default_context(cafile=".local/tls/ca.crt") if sys.argv[2].startswith("https") else None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
print(json.load(opener.open(sys.argv[2] + "/protocol/openid-connect/token", data))["access_token"])
PY
  }
  ADMIN="$(kc_token carol)"
  JWKS=http://keycloak:7080/realms/idp/protocol/openid-connect/certs; [[ "$MODE" == oidc ]] && JWKS=https://keycloak:8443/realms/idp/protocol/openid-connect/certs
  GW_BODY="{\"name\":\"edge-1\",\"authMode\":\"jwt\",\"jwt\":{\"issuer\":\"$ISSUER\",\"resource\":\"$RESOURCE\",\"jwksUrl\":\"$JWKS\",\"tenantClaim\":\"tenant_id\",\"rolesClaim\":\"roles\"}}"
else
  ADMIN="$("${C[@]}" run --rm -T registry-admin dev-token "$TENANT" carol admin)"
  GW_BODY='{"name":"edge-1","authMode":"api-key"}'
fi
GW="$("${CURL[@]}" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "$GW_BODY" "$REG/api/v1/gateways")"
GW_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["gateway"]["gatewayId"])' <<<"$GW")"
GW_TOKEN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<<"$GW")"
printf 'IDP_GATEWAY_ID=%s\nIDP_GATEWAY_TOKEN=%s\n' "$GW_ID" "$GW_TOKEN" >> "$ENVF"
"${C[@]}" up -d mcp-gateway
GWURL=http://127.0.0.1:3320; [[ "$MODE" == oidc ]] && GWURL=https://localhost:3320
for _ in $(seq 1 60); do "${CURL[@]}" -o /dev/null "$GWURL/healthz" && break; sleep 0.5; done

echo "published ports: $(docker ps --filter label=com.docker.compose.project=idp-mcp-go --format '{{.Ports}}' | tr ',' '\n' | grep -- '->' | sed 's/^ *//' | sort -u | tr '\n' ' ')"
set +e
TEST=TestComposeEndToEnd; [[ "$MODE" == jwt ]] && TEST=TestComposeJWT; [[ "$MODE" == oidc ]] && TEST=TestComposeOIDC
KCURL=http://127.0.0.1:7080/realms/idp; [[ "$MODE" == oidc ]] && KCURL="$ISSUER"
IDP_E2E_REGISTRY="$REG" IDP_E2E_GATEWAY="$GWURL" IDP_E2E_TENANT="$TENANT" \
IDP_E2E_GATEWAY_ID="$GW_ID" IDP_E2E_ADMIN_SECRET="$IDP_DEV_ADMIN_SECRET" IDP_E2E_MODE="$MODE" \
IDP_E2E_KEYCLOAK="$KCURL" IDP_E2E_KEYCLOAK_CLIENTS="$PWD/.local/keycloak-clients.json" IDP_E2E_CA="$PWD/.local/tls/ca.crt" \
IDP_E2E_KC_ADMIN_USER="${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" IDP_E2E_KC_ADMIN_PASSWORD="${KC_BOOTSTRAP_ADMIN_PASSWORD:-}" \
  go test -count=1 -v -run "^$TEST\$" ./tests/e2e/
status=$?
set -e
[[ $status == 0 ]] || "${C[@]}" logs --tail 30 mcp-gateway registry keycloak-prod 2>/dev/null
exit $status
