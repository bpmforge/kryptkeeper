-- (PostgreSQL) Restore the legacy role CHECK. Roles outside the legacy set are
-- coerced to the read-only 'pki-viewer' first, otherwise the constraint cannot
-- be re-added; this is lossy by design and never widens access.

BEGIN;

UPDATE users SET role = 'pki-viewer'
 WHERE role NOT IN ('pki-admin','pki-operator','pki-viewer','pki-auditor','discovery-operator','service-account');

ALTER TABLE users ADD CONSTRAINT users_role_check
    CHECK (role IN ('pki-admin','pki-operator','pki-viewer','pki-auditor','discovery-operator','service-account'));

COMMIT;
