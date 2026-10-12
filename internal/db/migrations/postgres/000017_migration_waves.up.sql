CREATE TABLE IF NOT EXISTS migration_waves (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    owner       TEXT,
    target_date TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS migration_wave_members (
    wave_id     TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    common_name TEXT
);
CREATE INDEX IF NOT EXISTS idx_wave_members_wave ON migration_wave_members(wave_id);
CREATE INDEX IF NOT EXISTS idx_wave_members_fp ON migration_wave_members(fingerprint);
