-- W24-09: operator-confirmed SSH host key pin (authorized_keys format) for
-- ssh/keychain targets. NULL = legacy target, falls back to the credential's
-- host_public_key.
ALTER TABLE managed_targets ADD COLUMN ssh_host_key TEXT;
