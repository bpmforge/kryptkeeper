-- Rollback pair of 000058. Reverses cleanly only against data that fits the
-- original, narrower CHECKs (the same assumption every other down.sql in
-- this tree makes) -- any port=0 or mesh-protocol row written since 000058
-- landed has no valid representation under the pre-W19-22 schema, so it is
-- deleted (cascades to certificate_endpoints) rather than left to violate
-- the restored CHECK.

DELETE FROM endpoints WHERE port = 0 OR protocol IN ('k8s-tls-secret', 'istio-mesh', 'linkerd-mesh');

ALTER TABLE endpoints DROP CONSTRAINT IF EXISTS endpoints_protocol_check;
ALTER TABLE endpoints ADD CONSTRAINT endpoints_protocol_check
    CHECK (protocol IN ('tls', 'ldaps', 'imaps', 'smtps', 'pop3s',
                         'ftps', 'rdps', 'kubernetes', 'other'));

ALTER TABLE endpoints DROP CONSTRAINT IF EXISTS endpoints_port_check;
ALTER TABLE endpoints ADD CONSTRAINT endpoints_port_check
    CHECK (port BETWEEN 1 AND 65535);
