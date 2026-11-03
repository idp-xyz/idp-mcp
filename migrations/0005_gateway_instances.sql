-- M5: one gateway record may run as several replicas. Each replica attests with its own instance id;
-- a deployment is GOOD only when every live instance runs the release. gateways.last_status keeps
-- the most recent heartbeat as a summary.
CREATE TABLE gateway_instances (
  gateway_id        uuid NOT NULL REFERENCES gateways(id),
  instance_id       text NOT NULL,
  tenant_id         uuid NOT NULL REFERENCES tenants(id),
  status            jsonb NOT NULL,
  last_heartbeat_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (gateway_id, instance_id)
);
ALTER TABLE gateway_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_instances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON gateway_instances USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON gateway_instances TO idp_mcp_app;   -- DELETE: pruning instances gone for a day
