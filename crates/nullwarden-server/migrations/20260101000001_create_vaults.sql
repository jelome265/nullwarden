CREATE TABLE IF NOT EXISTS vaults (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    version BIGINT NOT NULL DEFAULT 1,
    blob BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS (Internal use only, server scopes all queries)
ALTER TABLE vaults ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Internal access" ON vaults
    FOR ALL USING (true);
