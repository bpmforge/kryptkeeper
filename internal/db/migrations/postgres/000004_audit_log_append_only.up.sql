-- Wave W4 (PostgreSQL)
-- Purpose: audit_log with append-only controls
-- Depends on: W1
-- Rollback pair: 000004_audit_log_append_only.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS audit_log (
    id                        BIGINT GENERATED ALWAYS AS IDENTITY,
    timestamp                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action                    VARCHAR(100) NOT NULL,
    actor_type                VARCHAR(20) NOT NULL
                              CHECK (actor_type IN ('user', 'api_key', 'system', 'agent')),
    actor_id                  VARCHAR(128) NOT NULL,
    actor_email               VARCHAR(255),
    resource_type             VARCHAR(50) NOT NULL,
    resource_id               VARCHAR(128) NOT NULL,
    client_ip                 INET,
    trace_id                  VARCHAR(64),
    details                   JSONB NOT NULL DEFAULT '{}',
    diff                      JSONB,
    outcome                   VARCHAR(10) NOT NULL DEFAULT 'success'
                              CHECK (outcome IN ('success', 'failure', 'denied')),
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

DO $$
DECLARE
    start_month DATE;
    end_month DATE;
    part_name TEXT;
BEGIN
    FOR i IN 0..2 LOOP
        start_month := date_trunc('month', NOW())::date + (i || ' month')::interval;
        end_month := start_month + interval '1 month';
        part_name := format('audit_log_%s', to_char(start_month, 'YYYY_MM'));

        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_log FOR VALUES FROM (%L) TO (%L)',
            part_name,
            start_month,
            end_month
        );
    END LOOP;
END $$;

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);

CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_log_append_only ON audit_log;
CREATE TRIGGER trg_audit_log_append_only
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_insert_only ON audit_log;
CREATE POLICY audit_insert_only ON audit_log
    FOR INSERT WITH CHECK (TRUE);

COMMIT;
