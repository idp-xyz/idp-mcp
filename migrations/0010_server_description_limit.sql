-- The longest description, in bytes, that the catalog of a server of class external may have (ADR-0001 15.3): the
-- operator's setting for this server, NULL for the deployment default. A snapshot records the limit its catalog was
-- checked against, so the reviewer reads, and the approval pins, the limit that applied.
ALTER TABLE servers ADD COLUMN max_description_bytes integer CHECK (max_description_bytes > 0);
ALTER TABLE snapshots ADD COLUMN description_limit integer;
