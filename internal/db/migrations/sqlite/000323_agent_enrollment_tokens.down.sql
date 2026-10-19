-- W33-24: drops only the column 000323 added; the table belongs to 000240.
ALTER TABLE agent_enrollment_tokens DROP COLUMN tenant_id;
