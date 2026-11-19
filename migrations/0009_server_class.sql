-- A server has a class (ADR-0001 D50): 'internal', which every server so far is, or 'external', a third party's
-- server whose calls the gateway restricts (D51). Fixed at registration; the release pins it.
ALTER TABLE servers ADD COLUMN class text NOT NULL DEFAULT 'internal' CHECK (class IN ('internal', 'external'));
