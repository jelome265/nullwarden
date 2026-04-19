use crate::config::Config;
use crate::db::{UserRepository, VaultRepository};
use sqlx::PgPool;
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
    pub db: PgPool,
    pub users: Arc<dyn UserRepository>,
    pub vaults: Arc<dyn VaultRepository>,
    pub dummy_hash: String, // C-02: To prevent login timing oracle
}

impl AppState {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let url = config
            .database_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("DATABASE_URL must be set for persistent storage"))?;
        let _db = PgPool::connect(url).await?;

        Err(anyhow::anyhow!("AppState::new is deprecated. Use AppState::init instead."))
    }

    pub fn init(
        config: Config,
        db: PgPool,
        users: Arc<dyn UserRepository>,
        vaults: Arc<dyn VaultRepository>,
        dummy_hash: String,
    ) -> Self {
        Self {
            config,
            db,
            users,
            vaults,
            dummy_hash,
        }
    }
}
