-- Client admission and the completed audit (ADR-0001 D46 to D49): why a request was refused (or let through by a
-- host-only exception), and how many bytes of an event stream were relayed. Both nullable: older records have neither.
ALTER TABLE invocations ADD COLUMN reason text;
ALTER TABLE invocations ADD COLUMN bytes bigint;
