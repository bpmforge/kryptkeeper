-- W26-02: named ACME provisioners (per-path directories with allow-lists).
CREATE TABLE IF NOT EXISTS acme_provisioners (
  name TEXT PRIMARY KEY,
  ca_id TEXT NOT NULL,
  template_id TEXT NOT NULL DEFAULT '',
  allow_names TEXT NOT NULL DEFAULT '[]',
  challenges TEXT NOT NULL DEFAULT '[]',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
