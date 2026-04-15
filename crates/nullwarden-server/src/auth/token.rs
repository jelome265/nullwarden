use crate::db::pool::SharedState;
use uuid::Uuid;

pub async fn issue_refresh_token(state: &SharedState) -> String {
    let token = Uuid::new_v4().to_string();
    state.refresh_tokens.write().await.insert(token.clone());
    token
}

pub async fn consume_refresh_token(state: &SharedState, token: &str) -> Option<String> {
    let mut tokens = state.refresh_tokens.write().await;
    if tokens.remove(token) {
        Some(token.to_string())
    } else {
        None
    }
}

pub async fn revoke_refresh_token(state: &SharedState, token: &str) {
    state.refresh_tokens.write().await.remove(token);
}
