-- Wave W7 rollback (PostgreSQL)
-- Paired with: 000007_seed_baseline_data.up.sql

BEGIN;

-- Do not delete from audit_log here; append-only controls intentionally block mutation.
-- Audit seed entries are removed when W4 down drops audit_log.

DELETE FROM scan_results
 WHERE id = '00000000-0000-0000-0000-000000000110';

DELETE FROM certificate_endpoints
 WHERE certificate_fingerprint = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
   AND endpoint_id = '00000000-0000-0000-0000-000000000109';

DELETE FROM endpoints
 WHERE id = '00000000-0000-0000-0000-000000000109';

DELETE FROM scan_jobs
 WHERE id = '00000000-0000-0000-0000-000000000108';

UPDATE certificate_authorities
   SET certificate_fingerprint_sha256 = NULL
 WHERE id = '00000000-0000-0000-0000-000000000107';

DELETE FROM certificates
 WHERE fingerprint_sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

DELETE FROM certificate_authorities
 WHERE id = '00000000-0000-0000-0000-000000000107';

DELETE FROM certificate_templates
 WHERE id = '00000000-0000-0000-0000-000000000106';

DELETE FROM api_keys
 WHERE id = '00000000-0000-0000-0000-000000000105';

DELETE FROM team_members
 WHERE team_id = '00000000-0000-0000-0000-000000000102';

DELETE FROM users
 WHERE id IN ('00000000-0000-0000-0000-000000000103', '00000000-0000-0000-0000-000000000104');

DELETE FROM teams
 WHERE id = '00000000-0000-0000-0000-000000000102';

DELETE FROM notification_policies
 WHERE id = '00000000-0000-0000-0000-000000000101';

COMMIT;
