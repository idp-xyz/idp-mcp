-- idp-mcp registry schema v1 (ADR-0001 D2, D9, D10, D11).
-- Run by the schema owner (`registry-service migrate`). The service itself connects as a login role
-- that is a member of idp_mcp_app: not a superuser, no BYPASSRLS, so the policies below always apply.

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'idp_mcp_app') THEN
    CREATE ROLE idp_mcp_app NOLOGIN NOBYPASSRLS;
  END IF;
END $$;

CREATE TABLE tenants (
  id         uuid PRIMARY KEY,
  slug       text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE servers (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  target_name  text NOT NULL,
  display_name text NOT NULL,
  endpoint     text NOT NULL,
  network      text NOT NULL CHECK (network IN ('public', 'private', 'loopback')),
  lifecycle    text NOT NULL CHECK (lifecycle IN ('DRAFT', 'REVIEWED', 'APPROVED', 'RETIRED')),
  snapshot_id  uuid,          -- latest discovered snapshot
  approved_snapshot_id uuid,  -- the snapshot the reviewer approved
  created_by   text NOT NULL,
  approved_by  text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, target_name),
  UNIQUE (tenant_id, endpoint)
);

CREATE TABLE snapshots (
  id         uuid PRIMARY KEY,
  tenant_id  uuid NOT NULL REFERENCES tenants(id),
  server_id  uuid NOT NULL REFERENCES servers(id),
  digest     text NOT NULL,
  discovery  jsonb NOT NULL,
  tools      text NOT NULL,  -- canonical JSON, byte-exact (jsonb would rewrite numbers and break the digest)
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE grants (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  server_id   uuid NOT NULL REFERENCES servers(id),
  tools       text[] NOT NULL CHECK (cardinality(tools) > 0),
  roles       text[] NOT NULL CHECK (cardinality(roles) > 0),
  status      text NOT NULL CHECK (status IN ('PROPOSED', 'APPROVED', 'REVOKED')),
  created_by  text NOT NULL,
  decided_by  text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  decided_at  timestamptz
);

CREATE TABLE gateways (
  id                 uuid PRIMARY KEY,
  tenant_id          uuid NOT NULL REFERENCES tenants(id),
  name               text NOT NULL,
  auth_mode          text NOT NULL CHECK (auth_mode IN ('api-key', 'jwt')),
  jwt_profile        jsonb,
  drift_action       text NOT NULL CHECK (drift_action IN ('block', 'report')),
  desired_release_id uuid,
  last_status        jsonb,
  last_heartbeat_at  timestamptz,
  created_by         text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);

-- Looked up BEFORE the tenant is known (a gateway authenticates with its token), hence no RLS.
-- Only token hashes are stored.
CREATE TABLE gateway_credentials (
  token_sha256 text PRIMARY KEY,
  gateway_id   uuid NOT NULL REFERENCES gateways(id),
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  revoked_at   timestamptz
);

CREATE TABLE api_keys (
  id         uuid PRIMARY KEY,
  tenant_id  uuid NOT NULL REFERENCES tenants(id),
  gateway_id uuid NOT NULL REFERENCES gateways(id),
  subject    text NOT NULL,
  roles      text[] NOT NULL,
  sha256     text NOT NULL UNIQUE,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE TABLE releases (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES tenants(id),
  gateway_id       uuid NOT NULL REFERENCES gateways(id),
  status           text NOT NULL CHECK (status IN ('CANDIDATE', 'APPROVED', 'DEPLOYING', 'GOOD', 'FAILED', 'SUPERSEDED')),
  document         text NOT NULL,  -- canonical JSON as compiled; sealed into the envelope on approval
  digest           text,
  envelope         text,           -- byte-exact, see snapshots.tools
  created_by       text NOT NULL,
  approved_by      text,
  failure_reason   text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  approved_at      timestamptz,
  deployed_at      timestamptz
);

CREATE TABLE audit_events (
  id          bigserial PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  at          timestamptz NOT NULL DEFAULT now(),
  subject     text NOT NULL,
  action      text NOT NULL,
  resource_id text,
  detail      jsonb
);

CREATE TABLE invocations (
  id             bigserial PRIMARY KEY,
  tenant_id      uuid NOT NULL REFERENCES tenants(id),
  gateway_id     uuid NOT NULL REFERENCES gateways(id),
  at             timestamptz NOT NULL,
  release_digest text NOT NULL,
  subject        text NOT NULL,
  auth_method    text NOT NULL,
  tool           text NOT NULL,
  target         text,
  decision       text NOT NULL,
  outcome        text NOT NULL,
  latency_ms     bigint NOT NULL,
  trace_id       text,
  args_digest    text
);
CREATE INDEX invocations_tenant_at ON invocations (tenant_id, at DESC);
CREATE INDEX audit_tenant_at ON audit_events (tenant_id, at DESC);

-- Row-level security: every tenant table only shows rows of app.tenant_id, set per transaction.
-- FORCE applies the policies to the table owner too. current_setting(..., true) is NULL in a fresh
-- session but '' in a pooled session after a transaction-local setting ended; nullif maps both to
-- NULL, so a transaction that forgot to set the tenant sees nothing (and does not error).
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['servers', 'snapshots', 'grants', 'gateways', 'api_keys', 'releases', 'audit_events', 'invocations'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid) '
                   'WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)', t);
  END LOOP;
END $$;
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants USING (id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE ON servers, snapshots, grants, gateways, api_keys, releases TO idp_mcp_app;
GRANT SELECT, INSERT ON audit_events, invocations TO idp_mcp_app;   -- append-only for the service
GRANT SELECT ON tenants TO idp_mcp_app;
GRANT SELECT, INSERT, UPDATE ON gateway_credentials TO idp_mcp_app;
GRANT USAGE ON SEQUENCE audit_events_id_seq, invocations_id_seq TO idp_mcp_app;
