use crate::db::pool::{SharedState, StoredUser};
use uuid::Uuid;

pub async fn insert_user(state: &SharedState, username: String, password_hash: String) -> Option<StoredUser> {
    let mut users = state.users.write().await;
    if users.contains_key(&username) {
        return None;
    }
    let user = StoredUser {
        id: Uuid::new_v4(),
        username: username.clone(),
        password_hash,
    };
    users.insert(username, user.clone());
    Some(user)
}

pub async fn find_user(state: &SharedState, username: &str) -> Option<StoredUser> {
    state.users.read().await.get(username).cloned()
}
