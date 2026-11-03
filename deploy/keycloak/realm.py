#!/usr/bin/env python3
"""Generate the development Keycloak realm for the JWT end-to-end run (deploy/e2e.sh MODE=jwt).

Every identity is a confidential service-account client whose access tokens carry hardcoded
tenant_id and roles claims plus an audience: admin identities are bound to the registry
(idp-mcp-registry), agent identities to the gateway's MCP resource URI. Secrets are random per run.

  python3 deploy/keycloak/realm.py OUT_DIR TENANT_ID FOREIGN_TENANT_ID RESOURCE_URI CLIENTS_FILE
writes OUT_DIR/idp-realm.json (mounted into Keycloak for --import-realm) and CLIENTS_FILE (client
ids and secrets for the test). CLIENTS_FILE must not be in OUT_DIR: Keycloak imports every .json
file of that directory as a realm.
"""
import json
import os
import secrets
import sys

out, tenant, foreign, resource, clients_file = sys.argv[1:6]
oidc = len(sys.argv) > 6 and sys.argv[6] == "--oidc"
REGISTRY = "idp-mcp-registry"
identities = {
    # label: (tenant, roles, audience)
    "alice": (tenant, ["operator"], REGISTRY),
    "bob": (tenant, ["reviewer"], REGISTRY),
    "carol": (tenant, ["admin"], REGISTRY),
    "agent-allowed": (tenant, ["operator"], resource),
    "agent-viewer": (tenant, ["viewer"], resource),
    "agent-foreign": (foreign, ["operator"], resource),
}


def claim(name, value, json_type):
    return {"name": name, "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
            "config": {"claim.name": name, "claim.value": value, "jsonType.label": json_type,
                       "access.token.claim": "true", "id.token.claim": "false", "userinfo.token.claim": "false",
                       "introspection.token.claim": "true"}}


clients, saved = [], {}
for label, (tid, roles, aud) in identities.items():
    secret = secrets.token_urlsafe(32)
    saved[label] = {"clientId": "idp-" + label, "secret": secret}
    clients.append({
        "clientId": "idp-" + label, "name": "IDP MCP e2e " + label, "enabled": True, "protocol": "openid-connect",
        "publicClient": False, "secret": secret, "serviceAccountsEnabled": True, "standardFlowEnabled": False,
        "implicitFlowEnabled": False, "directAccessGrantsEnabled": False, "fullScopeAllowed": False,
        "protocolMappers": [
            {"name": "audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
             "config": {"included.custom.audience": aud, "access.token.claim": "true", "id.token.claim": "false",
                        "introspection.token.claim": "true"}},
            claim("tenant_id", tid, "String"),
            claim("roles", json.dumps(roles), "JSON"),
        ],
    })
realm = {"realm": "idp", "enabled": True, "sslRequired": "none", "accessTokenLifespan": 600, "clients": clients}
if oidc:
    # MODE=oidc: real users log in with the authorization code flow (PKCE) through agent-app; the agent
    # agent-exchange exchanges their tokens (RFC 8693, standard and delegation) for the gateway audience.
    realm["sslRequired"] = "external"
    realm["roles"] = {"realm": [{"name": "operator"}, {"name": "viewer"}]}
    tenant_attr = {"name": "tenant_id", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
                   "config": {"user.attribute": "tenant_id", "claim.name": "tenant_id", "jsonType.label": "String",
                              "access.token.claim": "true", "id.token.claim": "true", "userinfo.token.claim": "true", "introspection.token.claim": "true"}}
    roles_map = {"name": "roles", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-realm-role-mapper",
                 "config": {"claim.name": "roles", "jsonType.label": "String", "multivalued": "true",
                            "access.token.claim": "true", "id.token.claim": "false", "introspection.token.claim": "true"}}
    def audience(a):
        return {"name": "aud-" + a[-24:], "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": a, "access.token.claim": "true", "id.token.claim": "false", "introspection.token.claim": "true"}}
    users = {}
    for name, role in (("alice", "operator"), ("bob", "viewer")):
        users[name] = secrets.token_urlsafe(16)
    realm["users"] = [{"username": n, "enabled": True, "emailVerified": True, "email": n + "@example.com", "firstName": n, "lastName": "User",
                       "attributes": {"tenant_id": [tenant]}, "realmRoles": [r],
                       "credentials": [{"type": "password", "value": users[n], "temporary": False}]} for n, r in (("alice", "operator"), ("bob", "viewer"))]
    exchange_secret = secrets.token_urlsafe(32)
    realm["clients"] += [
        {"clientId": "agent-app", "name": "user login (authorization code + PKCE)", "enabled": True, "protocol": "openid-connect", "publicClient": True,
         "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "redirectUris": ["http://127.0.0.1:18080/callback"], "fullScopeAllowed": True,
         "attributes": {"pkce.code.challenge.method": "S256"}, "protocolMappers": [audience(resource), audience("agent-exchange"), tenant_attr, roles_map]},
        {"clientId": "agent-exchange", "name": "agent (token exchange requester)", "enabled": True, "protocol": "openid-connect", "publicClient": False,
         "secret": exchange_secret, "standardFlowEnabled": False, "serviceAccountsEnabled": True, "fullScopeAllowed": True,
         "attributes": {"standard.token.exchange.enabled": "true"}, "protocolMappers": [audience(resource), tenant_attr, roles_map]},
        {"clientId": resource, "name": "gateway resource (audience only)", "enabled": True, "protocol": "openid-connect", "bearerOnly": True,
         "publicClient": False, "standardFlowEnabled": False},
    ]
    saved["users"] = users
    saved["agent-exchange"] = {"clientId": "agent-exchange", "secret": exchange_secret}
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "idp-realm.json"), "w") as f:
    json.dump(realm, f, indent=1)
os.chmod(os.path.join(out, "idp-realm.json"), 0o644)  # read by the Keycloak container user; dev secrets only
with open(clients_file, "w") as f:
    json.dump(saved, f, indent=1)
os.chmod(clients_file, 0o600)
print("OK: realm idp with", len(clients), "clients")
