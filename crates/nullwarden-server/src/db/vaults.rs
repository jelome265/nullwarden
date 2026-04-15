use crate::db::pool::{SharedState, StoredVault};
use uuid::Uuid;

pub async fn get_vault(state: &SharedState, user_id: Uuid) -> Option<StoredVault> {
    state.vaults.read().await.get(&user_id).cloned()
}

pub async fn put_vault(state: &SharedState, user_id: Uuid, blob: Vec<u8>) -> StoredVault {
    let mut vaults = state.vaults.write().await;
    let version = vaults.get(&user_id).map_or(1, |v| v.version + 1);
    let stored = StoredVault {
        owner_id: user_id,
        version,
        blob,
    };
    vaults.insert(user_id, stored.clone());
    stored
}
