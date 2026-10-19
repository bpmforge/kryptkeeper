-- W22-14 (PostgreSQL): remove the baseline policy row.
BEGIN;
DELETE FROM issuance_policies WHERE id = 'pol-baseline';
COMMIT;
