CREATE TABLE IF NOT EXISTS token_blocklist (
    token_hash TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_token_blocklist_expires_at
    ON token_blocklist(expires_at);
