-- W26-01: operator-minted ACME EAB credentials and per-kid account-key binding.
-- acme_eab_keys (env seed) is untouched.
CREATE TABLE IF NOT EXISTS acme_eab_admin (
  kid TEXT PRIMARY KEY,
  label TEXT NOT NULL DEFAULT '',
  provisioner TEXT NOT NULL DEFAULT '',
  template_id TEXT NOT NULL DEFAULT '',
  sealed_mac_key TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS acme_eab_use (
  kid TEXT PRIMARY KEY,
  thumbprint TEXT NOT NULL,
  uses INTEGER NOT NULL DEFAULT 0,
  first_used_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL
);
