CREATE TABLE IF NOT EXISTS notification_rule_options (
    rule_id       TEXT PRIMARY KEY,
    threshold_pct INTEGER,
    template_id   TEXT NOT NULL DEFAULT '',
    tenant        TEXT NOT NULL DEFAULT ''
);
