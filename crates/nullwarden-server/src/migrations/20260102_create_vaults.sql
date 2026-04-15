CREATE TABLE IF NOT EXISTS vaults (
    owner_id UUID PRIMARY KEY,
    version BIGINT NOT NULL,
    blob BYTEA NOT NULL
);
