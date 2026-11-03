-- M2: grants on prompts and resources, tool naming per gateway, method of each recorded invocation.
ALTER TABLE grants ADD COLUMN prompts text[] NOT NULL DEFAULT '{}';
ALTER TABLE grants ADD COLUMN resources boolean NOT NULL DEFAULT false;
ALTER TABLE grants DROP CONSTRAINT grants_tools_check;
ALTER TABLE grants ADD CONSTRAINT grants_scope CHECK (cardinality(tools) > 0 OR cardinality(prompts) > 0 OR resources);

ALTER TABLE gateways ADD COLUMN tool_naming text NOT NULL DEFAULT 'prefixed' CHECK (tool_naming IN ('prefixed', 'native'));

ALTER TABLE invocations ADD COLUMN method text NOT NULL DEFAULT 'tools/call';
