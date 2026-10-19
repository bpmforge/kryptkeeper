-- Rollback of 000099_breakglass.up.sql (W22-37).
DROP INDEX IF EXISTS breakglass_reviews_one_open_per_scope;
DROP TABLE IF EXISTS breakglass_reviews;
DROP TABLE IF EXISTS breakglass_activations;
