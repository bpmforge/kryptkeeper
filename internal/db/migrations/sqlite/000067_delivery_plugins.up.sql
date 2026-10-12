-- Wave W20 (SQLite) (W20-20, D-113..D-120): delivery plugins. A plugin has
-- versions; each version keeps its manifest and WebAssembly module (in the
-- database, so every hub replica loads the same bytes) and its approval.
-- delivery_plugins.enabled_version is the version renewals run.
-- Rollback pair: 000067_delivery_plugins.down.sql

CREATE TABLE IF NOT EXISTS delivery_plugins (
    id               TEXT PRIMARY KEY,
    enabled_version  TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery_plugin_versions (
    plugin_id          TEXT NOT NULL REFERENCES delivery_plugins(id),
    version            TEXT NOT NULL,
    sha256             TEXT NOT NULL,
    manifest_json      TEXT NOT NULL,
    wasm               BLOB NOT NULL,
    tier               TEXT NOT NULL CHECK (tier IN ('first-party', 'verified', 'community')),
    status             TEXT NOT NULL CHECK (status IN ('installed', 'pending_approval', 'enabled', 'superseded', 'disabled')),
    installed_by       TEXT NOT NULL,
    installed_at       TEXT NOT NULL,
    approved_by        TEXT,
    approved_at        TEXT,
    pending_action_id  TEXT,
    PRIMARY KEY (plugin_id, version)
);
