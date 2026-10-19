-- W33-03: per-user UI preferences (onboarding dismissal), keyed on the
-- authenticated principal id so a second browser for the same user agrees.
CREATE TABLE IF NOT EXISTS user_prefs (
  principal_id          TEXT PRIMARY KEY,
  onboarding_dismissed  INTEGER NOT NULL DEFAULT 0,
  updated_at            TEXT NOT NULL
);
