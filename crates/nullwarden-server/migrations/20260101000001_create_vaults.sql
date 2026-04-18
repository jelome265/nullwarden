CREATE TABLE IF NOT EXISTS vaults (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    version BIGINT NOT NULL DEFAULT 1,
    blob BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE vaults ENABLE ROW LEVEL SECURITY;

-- Policy: users can only access their own vault
CREATE POLICY "Users can only access their own vault" ON vaults
    FOR ALL USING (auth.uid() = user_id);
