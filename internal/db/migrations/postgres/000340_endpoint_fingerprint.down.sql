-- Rollback pair of 000340. Rows that use a protocol added by 000340 do not fit
-- the narrower CHECK, so they are recorded as 'other' (what they were before
-- the vocabulary grew) instead of being deleted.

UPDATE endpoints SET protocol = 'other'
 WHERE protocol IN ('mssql', 'mysql', 'oracle', 'redis', 'mongodb', 'kafka');

ALTER TABLE endpoints DROP CONSTRAINT IF EXISTS endpoints_protocol_check;
ALTER TABLE endpoints ADD CONSTRAINT endpoints_protocol_check
    CHECK (protocol IN ('tls', 'ldaps', 'imaps', 'smtps', 'pop3s',
                         'ftps', 'rdps', 'kubernetes', 'other',
                         'k8s-tls-secret', 'istio-mesh', 'linkerd-mesh'));

ALTER TABLE endpoints DROP COLUMN IF EXISTS tech_evidence;
ALTER TABLE endpoints DROP COLUMN IF EXISTS tls_stack;
ALTER TABLE endpoints DROP COLUMN IF EXISTS platform;
ALTER TABLE endpoints DROP COLUMN IF EXISTS tech_confidence;
ALTER TABLE endpoints DROP COLUMN IF EXISTS tech;
