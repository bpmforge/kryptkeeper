-- rc.7: audit_log.outcome CHECK only allowed success/failure/denied, but the hub
-- records skipped, pending_approval, proposed, executed, issuance_failed and
-- partial too (and spiffe.workload_attest writes actor_type 'workload'). Since
-- the DB became the default audit store (RC1 H1) every such append failed with
-- "CHECK constraint failed" and was only logged: silent audit loss. This
-- widens the CHECK to the full AuditOutcome vocabulary
-- (internal/bootstrap/audit_outcome.go; audit_outcome_test.go keeps them in sync).
--
-- SQLite cannot alter a CHECK, so this is the table rebuild dance (000075 is
-- the template). audit_log is append-only: every row is copied across with its
-- id, the append-only triggers are dropped and recreated inside the same
-- transaction, and all indexes are recreated.

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE audit_log_new (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    action                    TEXT NOT NULL,
    actor_type                TEXT NOT NULL CHECK (actor_type IN ('user', 'api_key', 'system', 'agent', 'workload')),
    actor_id                  TEXT NOT NULL,
    actor_email               TEXT,
    resource_type             TEXT NOT NULL,
    resource_id               TEXT NOT NULL,
    client_ip                 TEXT,
    trace_id                  TEXT,
    details                   TEXT NOT NULL DEFAULT '{}',
    diff                      TEXT,
    outcome                   TEXT NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'failure', 'denied', 'skipped', 'pending_approval', 'proposed', 'executed', 'issuance_failed', 'partial')),
    source_ip                 TEXT,
    user_agent                TEXT,
    session_id                TEXT,
    change_summary            TEXT,
    tenant                    TEXT NOT NULL DEFAULT 'default'
);

-- Every row, with its id (so AUTOINCREMENT never reuses one), is copied
-- before the old table is removed. A row the new CHECK rejects aborts the
-- whole transaction; nothing is skipped or rewritten.
INSERT INTO audit_log_new (id, timestamp, action, actor_type, actor_id, actor_email, resource_type,
    resource_id, client_ip, trace_id, details, diff, outcome, source_ip, user_agent, session_id,
    change_summary, tenant)
SELECT id, timestamp, action, actor_type, actor_id, actor_email, resource_type,
    resource_id, client_ip, trace_id, details, diff, outcome, source_ip, user_agent, session_id,
    change_summary, tenant
FROM audit_log;

-- The append-only triggers would block the implicit delete of removing the old
-- table, so they go first; they are recreated below inside the same
-- transaction, so the table is never observable without them.
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
