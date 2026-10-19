-- W27-02: explicit cert-to-target binding for auto-renew. The renewal sweep
-- renews a certificate only onto targets an operator bound to it; it no longer
-- guesses from CN/SAN == target host. served_fingerprint is the certificate
-- currently installed on the target (fingerprints rotate on every renewal).
-- Rollback pair: 000200_cert_target_bindings.down.sql

CREATE TABLE IF NOT EXISTS cert_target_bindings (
    cert_fingerprint   TEXT NOT NULL,
    target_id          TEXT NOT NULL,
    served_fingerprint TEXT NOT NULL,
    tenant             TEXT NOT NULL DEFAULT 'default',
    source             TEXT NOT NULL DEFAULT 'operator' CHECK (source IN ('operator', 'backfill')),
    created_by         TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    PRIMARY KEY (cert_fingerprint, target_id)
);
CREATE INDEX IF NOT EXISTS idx_ctb_target ON cert_target_bindings(target_id);
CREATE INDEX IF NOT EXISTS idx_ctb_served ON cert_target_bindings(served_fingerprint);

-- One row, key 'backfill_done': the one-time migration of pre-existing
-- CN/SAN == host matches into bindings has run and must never run again
-- (a binding an operator deleted must stay deleted).
CREATE TABLE IF NOT EXISTS cert_target_binding_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
