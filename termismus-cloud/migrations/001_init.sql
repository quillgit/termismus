CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS vault_versions (
    id          TEXT PRIMARY KEY NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_blob BLOB NOT NULL,
    version     INTEGER NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- The unique index also serves ORDER BY version DESC lookups.
DROP INDEX IF EXISTS idx_vault_user_version;
CREATE UNIQUE INDEX IF NOT EXISTS ux_vault_user_version ON vault_versions(user_id, version);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
