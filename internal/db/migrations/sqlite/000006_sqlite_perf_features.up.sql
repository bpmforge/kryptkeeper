-- Wave W6 (SQLite)
-- Purpose: engine-specific performance features
-- Depends on: W5
-- Rollback pair: 000006_sqlite_perf_features.down.sql
--
-- W10-01/G-33: the original version of this migration created an FTS5
-- virtual table (certificates_fts) + triggers to keep it in sync. FTS5 is a
-- compile-time-optional SQLite extension, and no build target in this repo
-- (Makefile, go.mod, Dockerfile, CI) ever passes the sqlite_fts5 build tag or
-- CGO_CFLAGS=-DSQLITE_ENABLE_FTS5 that github.com/mattn/go-sqlite3 requires
-- to include it -- confirmed empirically running this migration for the
-- first time ever (via the new migration runner), which failed with
-- "no such module: fts5" against a plain `go test`/`go build` binary.
-- certificates_fts is also never referenced anywhere in Go code (grep
-- confirmed) -- no search feature was ever wired to depend on it. Removed
-- rather than reworked: if full-text search becomes a real, Go-code-backed
-- feature later, add it as a NEW migration once the build actually supports
-- FTS5, rather than resurrecting speculative dead SQL here.

BEGIN;

CREATE INDEX IF NOT EXISTS idx_cert_subject_dn ON certificates(subject_dn);
CREATE INDEX IF NOT EXISTS idx_cert_valid_window ON certificates(valid_from, valid_until);

COMMIT;
