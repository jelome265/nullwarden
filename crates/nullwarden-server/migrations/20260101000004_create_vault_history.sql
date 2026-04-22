CREATE TABLE IF NOT EXISTS vault_history (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    blob BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vault_history_user_id_created_at
    ON vault_history(user_id, created_at DESC);

ALTER TABLE vault_history ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can access own history"
  ON vault_history
  FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);
