-- Wave W26 (W26-07, D-112): EST HTTP Basic users managed through the API.
-- Only a bcrypt hash is stored; the password is shown once at create/rotate.
-- Users defined in KRYPTKEEPER_EST_USERS_FILE take precedence on a name clash.
-- Times are RFC 3339 UTC text. disabled is INTEGER 0/1 (as acme_eab_keys).
-- Rollback pair: 000182_est_users.down.sql

CREATE TABLE IF NOT EXISTS est_users (
    username             TEXT PRIMARY KEY,
    bcrypt_hash          TEXT NOT NULL,
    allowed_dns_suffixes TEXT NOT NULL DEFAULT '[]',
    disabled             INTEGER NOT NULL DEFAULT 0,
    created_by           TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    password_rotated_at  TEXT
);
