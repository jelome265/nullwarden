use crate::config::Config;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;
use uuid::Uuid;

pub type SharedState = Arc<AppState>;

#[derive(Debug, Clone)]
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
    pub users: RwLock<HashMap<String, StoredUser>>,
    pub refresh_tokens: RwLock<HashSet<String>>,
    pub vaults: RwLock<HashMap<Uuid, StoredVault>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            users: RwLock::new(HashMap::new()),
            refresh_tokens: RwLock::new(HashSet::new()),
            vaults: RwLock::new(HashMap::new()),
        }
    }
}
