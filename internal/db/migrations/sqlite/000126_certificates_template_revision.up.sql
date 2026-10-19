-- W23-44: the template revision a certificate was issued under. Nullable:
-- rows issued before this migration, imported and discovered certificates
-- have no revision to record.
ALTER TABLE certificates ADD COLUMN template_revision INTEGER;
