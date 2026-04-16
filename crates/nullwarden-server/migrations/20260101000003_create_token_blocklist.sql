CREATE TABLE IF NOT EXISTS token_blocklist (
    token_hash TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);
