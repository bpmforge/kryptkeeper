-- W23-49: DB-backed CRL numbers. RFC 5280 5.2.3 requires the CRL number to
-- increase monotonically per CA/scope; a per-process counter restarts at 1 and
-- differs between replicas. `scope` is the CA id, or "<ca>/s<N>" for a shard.
-- Rollback pair: 000124_crl_numbers.down.sql

CREATE TABLE IF NOT EXISTS crl_numbers (
    scope       TEXT PRIMARY KEY,
    last_number INTEGER NOT NULL CHECK (last_number >= 0)
);
