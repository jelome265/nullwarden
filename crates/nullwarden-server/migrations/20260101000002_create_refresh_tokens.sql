CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;

-- Policy: users can only see their own refresh tokens
CREATE POLICY "Users can only see their own tokens" ON refresh_tokens
    FOR ALL USING (auth.uid() = user_id);
