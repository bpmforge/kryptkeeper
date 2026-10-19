-- Purpose: W22-07 audit retention. One row per archive run, written (and
-- committed) BEFORE the archived audit_log rows are deleted. It holds the
-- signed Merkle checkpoint of the archive file, which is the trust anchor for
-- the archived prefix once those rows have left the live log.
-- Depends on: 000004

CREATE TABLE IF NOT EXISTS audit_archives (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    before_ts   TEXT NOT NULL,
    row_count   INTEGER NOT NULL,
    first_id    BIGINT NOT NULL,
    last_id     BIGINT NOT NULL,
    merkle_root TEXT NOT NULL,
    signature   TEXT NOT NULL,
    chain_head  TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    file_sha256 TEXT NOT NULL,
    approver    TEXT NOT NULL,
    action_id   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_archives_chain_head ON audit_archives(chain_head);
