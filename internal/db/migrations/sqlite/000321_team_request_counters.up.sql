-- W33-21: per-team monthly issuance counters. team_id is "<tenant>/<team>";
-- period is the UTC month "YYYY-MM". Reserve is one atomic upsert.
CREATE TABLE IF NOT EXISTS team_request_counters (
    team_id TEXT NOT NULL,
    period  TEXT NOT NULL,
    count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (team_id, period)
);
