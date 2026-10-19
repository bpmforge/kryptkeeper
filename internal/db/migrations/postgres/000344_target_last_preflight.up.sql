-- W34-15: latest privilege preflight report (JSON, secret-free) per target.
ALTER TABLE managed_targets ADD COLUMN last_preflight TEXT;
