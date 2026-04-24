use crate::config::Config;
use crate::db::{
    RefreshTokenRepository, TokenBlocklistRepository, UserRepository, VaultRepository,
};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use std::{num::NonZeroU32, sync::Arc};
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
    pub vault_rate_limiter: DefaultKeyedRateLimiter<Uuid>,
    pub force_push_rate_limiter: DefaultKeyedRateLimiter<Uuid>,
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
        let vault_rate_limiter = RateLimiter::keyed(Quota::per_minute(
            NonZeroU32::new(config.rate_limit_vault_requests_per_minute)
                .expect("vault rate limit must be non-zero"),
        ));
        let force_push_rate_limiter = RateLimiter::keyed(Quota::per_hour(
            NonZeroU32::new(config.rate_limit_force_pushes_per_hour)
                .expect("force-push rate limit must be non-zero"),
        ));
        Self {
            config,
            users,
            vaults,
            refresh_tokens,
            token_blocklist,
            dummy_hash,
            vault_rate_limiter,
            force_push_rate_limiter,
        }
    }
}
