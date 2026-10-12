-- Wave W18 (sqlite) -- rollback of 000051.
-- Drops the persisted classification; readers fall back to "" again.
ALTER TABLE certificates DROP COLUMN pqc_readiness;
