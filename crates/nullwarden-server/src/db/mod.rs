pub mod pool;
pub mod tokens;
pub mod users;
pub mod vaults;

use crate::db::pool::{StoredUser, StoredVault};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn insert_user(
        &self,
        username: String,
        password_hash: String,
    ) -> Result<StoredUser, sqlx::Error>;
    async fn find_user(&self, username: &str) -> Result<Option<StoredUser>, sqlx::Error>;
    async fn delete_user(&self, user_id: Uuid) -> Result<u64, sqlx::Error>;
}

#[async_trait]
pub trait VaultRepository: Send + Sync {
    async fn get_vault(&self, user_id: Uuid) -> Result<Option<StoredVault>, sqlx::Error>;
    async fn put_vault(
        &self,
        user_id: Uuid,
        blob: Vec<u8>,
        expected_version: Option<u64>,
        force: bool,
    ) -> Result<StoredVault, sqlx::Error>;
}

#[derive(Debug, Clone)]
pub struct StoredRefreshToken {
    pub secret_hash: String,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    async fn insert_token(
        &self,
        id: Uuid,
        secret_hash: String,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error>;

    async fn find_token(&self, id: Uuid) -> Result<Option<StoredRefreshToken>, sqlx::Error>;

    async fn delete_token(&self, id: Uuid) -> Result<(), sqlx::Error>;

    async fn delete_tokens_for_user(&self, user_id: Uuid) -> Result<u64, sqlx::Error>;

    async fn cleanup_expired_tokens(&self, now: DateTime<Utc>) -> Result<u64, sqlx::Error>;
}

#[async_trait]
pub trait TokenBlocklistRepository: Send + Sync {
    async fn insert_blocked_token(
        &self,
        token_hash: String,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error>;

    async fn contains_token(&self, token_hash: &str) -> Result<bool, sqlx::Error>;

    async fn cleanup_expired_tokens(&self, now: DateTime<Utc>) -> Result<u64, sqlx::Error>;
}
