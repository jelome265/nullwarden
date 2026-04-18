use crate::config::Config;
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
}

impl AppState {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let url = config
            .database_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("DATABASE_URL must be set for persistent storage"))?;
        let db = PgPool::connect(url).await?;

        Ok(Self { config, db })
    }
}
