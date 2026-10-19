-- (postgres) Code-signing key attestation (W26-23, FR-P92): the verified hardware
-- attestation of a requester-supplied CSR, keyed by sha256 of the CSR PEM so
-- it joins the approval row's csr_pem. Holds public material only.
CREATE TABLE IF NOT EXISTS codesign_attestations (
    csr_sha256 TEXT PRIMARY KEY, template_id TEXT NOT NULL, format TEXT NOT NULL,
    serial TEXT, firmware TEXT, key_spki_sha256 TEXT NOT NULL, attestation_pem TEXT NOT NULL,
    intermediates_pem TEXT, vendor_root_sha256 TEXT NOT NULL, verified_at TEXT NOT NULL);
