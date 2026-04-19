pub mod pool;
pub mod users;
pub mod vaults;

use crate::db::pool::{StoredUser, StoredVault};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn insert_user(
        &self,
        username: String,
        password_hash: String,
    ) -> Result<StoredUser, sqlx::Error>;
    async fn find_user(&self, username: &str) -> Result<Option<StoredUser>, sqlx::Error>;
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
