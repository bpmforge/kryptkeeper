CREATE TABLE IF NOT EXISTS notification_team_routes (
    id         TEXT PRIMARY KEY,
    owner_team TEXT NOT NULL,
    channel    TEXT NOT NULL,
    target     TEXT NOT NULL,
    tenant     TEXT NOT NULL DEFAULT '',
    UNIQUE (owner_team, channel, target)
);
