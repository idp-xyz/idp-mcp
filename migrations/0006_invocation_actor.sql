-- M5: who acted for whom. client = the OAuth client the token was issued to (azp); actor = the
-- delegated party of an RFC 8693 token (act.client_id or act.sub). Audit only.
ALTER TABLE invocations ADD COLUMN client text;
ALTER TABLE invocations ADD COLUMN actor text;
