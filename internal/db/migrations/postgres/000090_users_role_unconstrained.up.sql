-- (PostgreSQL) W22-19: users.role was pinned to six legacy names by 000001,
-- but the runtime role vocabulary is viewer / auditor / approver / custom roles,
-- and an SSO user with no mapped group is stored with an empty role (denied at
-- login). The CHECK made every such write fail (SCIM create, SSO role persist).
-- Role validity is enforced in the application (roleKnown / custom roles).
-- Rollback pair: 000090_users_role_unconstrained.down.sql

BEGIN;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;

COMMIT;
