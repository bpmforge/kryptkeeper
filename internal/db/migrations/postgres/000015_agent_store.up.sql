CREATE TABLE IF NOT EXISTS agents (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL,
    token           TEXT NOT NULL,
    registered_at   TEXT NOT NULL,
    last_seen       TEXT,
    inventory_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS agent_inventory (
    agent_id       TEXT NOT NULL,
    fingerprint    TEXT NOT NULL,
    subject        TEXT,
    issuer         TEXT,
    not_before     TEXT,
    not_after      TEXT,
    source         TEXT,
    auto_renewable INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS agent_endpoints (
    agent_id    TEXT NOT NULL,
    server_type TEXT,
    cert_path   TEXT,
    key_path    TEXT,
    server_name TEXT,
    listen_port INTEGER,
    config_path TEXT
);
CREATE TABLE IF NOT EXISTS agent_tasks (
    task_id          TEXT PRIMARY KEY,
    agent_id         TEXT NOT NULL,
    fingerprint      TEXT,
    subject          TEXT,
    action           TEXT,
    ca_url           TEXT,
    not_after        TEXT,
    server_type      TEXT,
    cert_path        TEXT,
    key_path         TEXT,
    reload_method    TEXT,
    verify_host_port TEXT
);
CREATE TABLE IF NOT EXISTS agent_results (
    id                 TEXT PRIMARY KEY,
    agent_id           TEXT NOT NULL,
    task_id            TEXT,
    fingerprint        TEXT,
    outcome            TEXT,
    served_fingerprint TEXT,
    rolled_back        INTEGER NOT NULL DEFAULT 0,
    detail             TEXT,
    reported_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_inventory_agent ON agent_inventory(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_endpoints_agent ON agent_endpoints(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent ON agent_tasks(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_results_agent ON agent_results(agent_id);
