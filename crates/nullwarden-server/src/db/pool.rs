use crate::config::Config;
use sqlx::PgPool;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;
use uuid::Uuid;
use tracing::warn;

pub type SharedState = Arc<AppState>;
n#[derive(Debug, Clone)]
pub struct StoredUser {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
pub struct StoredVault {
    pub owner_id: Uuid,
    pub version: u64,
    pub blob: Vec<u8>,
}
pub struct AppState {
    pub config: Config,
    pub db: PgPool,
}

impl AppState {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let url = config.database_url.as_ref().ok_or_else(|| {
            anyhow::anyhow!("DATABASE_URL must be set for persistent storage")
        })?;
        let db = PgPool::connect(url).await?;

        Ok(Self { config, db })
    }
}

