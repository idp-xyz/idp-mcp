-- M5: resources and resource templates are pinned like tools and prompts. snapshots.digest now
-- covers {"tools", "prompts", "resources", "resourceTemplates"}.
ALTER TABLE snapshots ADD COLUMN resources text NOT NULL DEFAULT '[]';           -- canonical JSON, byte-exact
ALTER TABLE snapshots ADD COLUMN resource_templates text NOT NULL DEFAULT '[]';
