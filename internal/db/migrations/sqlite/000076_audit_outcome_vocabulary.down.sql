-- Rollback pair of 000076. LOSSY-REFUSING: audit rows carrying an outcome or
-- actor_type introduced by 000076 cannot satisfy the original CHECK. The audit
-- log is append-only, so this rollback never deletes or rewrites them: it
-- fails (the transaction rolls back, every row intact) while any exist.

PRAGMA foreign_keys=OFF;

BEGIN;

-- Refuse while rows exist that the narrower CHECK cannot hold. The failing
-- CHECK's name is the operator-facing message.
CREATE TABLE refuse_000076_down (
    ok INTEGER NOT NULL CONSTRAINT audit_log_has_rows_that_need_the_000076_vocabulary CHECK (ok = 1)
);
INSERT INTO refuse_000076_down
SELECT CASE WHEN EXISTS (
    SELECT 1 FROM audit_log
     WHERE outcome NOT IN ('success', 'failure', 'denied')
        OR actor_type NOT IN ('user', 'api_key', 'system', 'agent')
) THEN 0 ELSE 1 END;
DROP TABLE refuse_000076_down;

CREATE TABLE audit_log_new (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    action                    TEXT NOT NULL,
    actor_type                TEXT NOT NULL CHECK (actor_type IN ('user', 'api_key', 'system', 'agent')),
    actor_id                  TEXT NOT NULL,
    actor_email               TEXT,
    resource_type             TEXT NOT NULL,
    resource_id               TEXT NOT NULL,
    client_ip                 TEXT,
    trace_id                  TEXT,
    details                   TEXT NOT NULL DEFAULT '{}',
    diff                      TEXT,
    outcome                   TEXT NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'failure', 'denied')),
    source_ip                 TEXT,
    user_agent                TEXT,
    session_id                TEXT,
    change_summary            TEXT,
    tenant                    TEXT NOT NULL DEFAULT 'default'
);

INSERT INTO audit_log_new (id, timestamp, action, actor_type, actor_id, actor_email, resource_type,
    resource_id, client_ip, trace_id, details, diff, outcome, source_ip, user_agent, session_id,
    change_summary, tenant)
SELECT id, timestamp, action, actor_type, actor_id, actor_email, resource_type,
    resource_id, client_ip, trace_id, details, diff, outcome, source_ip, user_agent, session_id,
    change_summary, tenant
FROM audit_log;

DROP TRIGGER IF EXISTS trg_audit_log_no_update;
DROP TRIGGER IF EXISTS trg_audit_log_no_delete;

DROP TABLE audit_log;
ALTER TABLE audit_log_new RENAME TO audit_log;

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_outcome_ts ON audit_log(outcome, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant);

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
BEFORE DELETE ON audit_log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

COMMIT;

PRAGMA foreign_keys=ON;
