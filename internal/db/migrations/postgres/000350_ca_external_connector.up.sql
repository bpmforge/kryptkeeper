-- W36-02 (D-304): an external CA delegates signing to an issuer connector.
-- external_trust_pem holds the CA certificates an upstream response must
-- chain to; both columns stay NULL for hub CAs.
ALTER TABLE certificate_authorities ADD COLUMN connector_id TEXT;
ALTER TABLE certificate_authorities ADD COLUMN external_trust_pem TEXT;
