-- Adds acme_accounts.jwk: the account's RFC 7517 JSON Web Key (JSON-encoded),
-- alongside the existing thumbprint column, so a kid-authenticated request
-- can resolve a usable crypto.PublicKey after a restart (G-90). Before this,
-- store_sqlite.go persisted only the thumbprint, which is one-way by design
-- (RFC 7638) and cannot be turned back into a verification key.
--
-- acme_accounts has never been created by any earlier migration -- it is
-- solely owned by internal/acme/store_sqlite.go's EnsureSchema, an idempotent
-- CREATE TABLE IF NOT EXISTS that runs at ACME store startup, strictly after
-- RunMigrations. CREATE TABLE IF NOT EXISTS here (mirroring
-- 000026_acme_eab's same reasoning) only takes effect on a genuinely fresh
-- database that migrations reach before EnsureSchema ever runs; it never
-- alters a table that already exists. A table already created in the
-- pre-jwk 5-column shape by a prior boot is repaired separately by
-- EnsureSchema's own best-effort `ALTER TABLE ... ADD COLUMN jwk`, which
-- tolerates the resulting "already exists" error the same way this
-- statement tolerates the table already existing -- see store_sqlite.go.
CREATE TABLE IF NOT EXISTS acme_accounts (
    id          TEXT PRIMARY KEY,
    contact     TEXT NOT NULL DEFAULT '[]',
    thumbprint  TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'valid',
    created_at  TEXT NOT NULL,
    jwk         TEXT
);
