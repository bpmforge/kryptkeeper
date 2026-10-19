-- (SQLite) rollback of 000143. Drops only the triage columns; the table
-- itself predates this migration (EnsureSchema-owned since W6-06) and keeps
-- its findings. Triage state (who acknowledged what) is lost.
ALTER TABLE ct_findings DROP COLUMN tenant;
ALTER TABLE ct_findings DROP COLUMN resolved_at;
ALTER TABLE ct_findings DROP COLUMN resolved_by;
ALTER TABLE ct_findings DROP COLUMN resolution;
