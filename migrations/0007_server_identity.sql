-- A server can be approved to receive the verified caller (subject, tenant, roles, client, actor) with
-- every call the gateway forwards to it (ADR-0001 D31). Default: no identity leaves the gateway.
ALTER TABLE servers ADD COLUMN identity text NOT NULL DEFAULT 'none' CHECK (identity IN ('none', 'forward'));
