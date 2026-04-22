CREATE TABLE IF NOT EXISTS token_blocklist (
    token_hash TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_token_blocklist_expires_at
    ON token_blocklist(expires_at);

ALTER TABLE token_blocklist ENABLE ROW LEVEL SECURITY;

CREATE POLICY "No direct user access"
  ON token_blocklist
  FOR ALL
  USING (false); -- Only accessible via service_role bypass
