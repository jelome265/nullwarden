use crate::config::Config;
use crate::db::{
    RefreshTokenRepository, TokenBlocklistRepository, UserRepository, VaultRepository,
};
use std::sync::Arc;
use uuid::Uuid;

pub type SharedState = Arc<AppState>;

#[derive(Debug, Clone)]
pub struct StoredUser {
    pub id: Uuid,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
pub struct StoredVault {
    pub version: u64,
    pub blob: Vec<u8>,
}

pub struct AppState {
    pub config: Config,
    pub users: Arc<dyn UserRepository>,
    pub vaults: Arc<dyn VaultRepository>,
    pub refresh_tokens: Arc<dyn RefreshTokenRepository>,
    pub token_blocklist: Arc<dyn TokenBlocklistRepository>,
    pub dummy_hash: String, // C-02: To prevent login timing oracle
}

impl AppState {
    pub fn init(
        config: Config,
        users: Arc<dyn UserRepository>,
        vaults: Arc<dyn VaultRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        token_blocklist: Arc<dyn TokenBlocklistRepository>,
        dummy_hash: String,
    ) -> Self {
        Self {
            config,
            users,
            vaults,
            refresh_tokens,
            token_blocklist,
            dummy_hash,
        }
    }
}
