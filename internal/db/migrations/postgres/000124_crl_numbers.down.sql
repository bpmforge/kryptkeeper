-- Rollback pair of 000124. Dropping the counters lets CRL numbers restart,
-- so roll back only together with the code that reads the table.

DROP TABLE IF EXISTS crl_numbers;
