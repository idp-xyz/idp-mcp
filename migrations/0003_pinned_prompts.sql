-- M3: prompts are pinned like tools. snapshots.digest now covers {"tools": ..., "prompts": ...}.
ALTER TABLE snapshots ADD COLUMN prompts text NOT NULL DEFAULT '[]';  -- canonical JSON, byte-exact
