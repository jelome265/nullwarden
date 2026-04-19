CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS (Internal use only, server scopes all queries)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Enable select for auth" ON users
    FOR SELECT USING (true);

CREATE POLICY "Users can only update themselves" ON users
    FOR UPDATE USING (true);
