-- W9-04/G-35: ledger of CA key re-key events (internal/ca/rotation.go's RotateCA).
CREATE TABLE IF NOT EXISTS ca_key_rotations (
    id          TEXT PRIMARY KEY,
    ca_id       TEXT NOT NULL REFERENCES certificate_authorities(id),
    old_key_id  TEXT NOT NULL,
    new_key_id  TEXT NOT NULL,
    new_cert_sn TEXT NOT NULL,
    method      TEXT NOT NULL CHECK (method IN ('rekey_reissue', 'cross_sign')),
    rotated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_ca_key_rotations_ca_id ON ca_key_rotations(ca_id);
CREATE INDEX IF NOT EXISTS idx_ca_key_rotations_rotated_at ON ca_key_rotations(rotated_at DESC);
