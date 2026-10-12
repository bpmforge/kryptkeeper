-- disabled is INTEGER (not BOOLEAN) to match internal/acme/store_sqlite.go's
-- EnsureSchema, which runs one unbranched DDL string against both engines.
CREATE TABLE IF NOT EXISTS acme_eab_keys (
    kid        TEXT PRIMARY KEY,
    mac_key    TEXT NOT NULL,
    disabled   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_account_eab (
    account_id TEXT PRIMARY KEY,
    kid        TEXT NOT NULL,
    bound_at   TEXT NOT NULL
);
