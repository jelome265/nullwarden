use crate::db::pool::SharedState;
use crate::error::AppError;
use chrono::{Duration, Utc};
use constant_time_eq::constant_time_eq;
use sha2::{Digest, Sha256};
use uuid::Uuid;


/// Issues a new refresh token for a user.
/// Returns a string in the format "token_id:secret".
pub async fn issue_refresh_token(state: &SharedState, user_id: Uuid) -> anyhow::Result<String> {
    let token_id = Uuid::new_v4();
    let secret = Uuid::new_v4().to_string();
    let secret_hash = sha256_hex(&secret);
    let expires_at = Utc::now() + Duration::days(state.config.jwt_refresh_expire_days);

    state
        .refresh_tokens
        .insert_token(token_id, secret_hash, user_id, expires_at)
        .await?;

    Ok(format!("{}:{}", token_id, secret))
}

/// Consumes a refresh token and returns the associated user_id if valid.
/// The token string should be in the format "token_id:secret".
pub async fn consume_refresh_token(state: &SharedState, token: &str) -> Result<Uuid, AppError> {
    let (id_str, secret) = token
        .split_once(':')
        .ok_or_else(|| AppError::Unauthorized("Invalid token format".to_string()))?;

    let token_id = Uuid::parse_str(id_str)
        .map_err(|_| AppError::Unauthorized("Invalid token ID".to_string()))?;

    match state.refresh_tokens.find_token(token_id).await? {
        Some(row) if row.expires_at > Utc::now() => {
            if secure_secret_matches(&row.secret_hash, secret) {
                // Revoke after one-time use
                let _ = revoke_refresh_token(state, token_id).await;
                Ok(row.user_id)
            } else {
                Err(AppError::Unauthorized("Invalid token secret".to_string()))
            }
        }
        None => Err(AppError::Unauthorized(
            "Token expired or not found".to_string(),
        )),
        Some(_) => Err(AppError::Unauthorized(
            "Token expired or not found".to_string(),
        )),
    }
}

/// Revokes a refresh token by its ID.
pub async fn revoke_refresh_token(state: &SharedState, id: Uuid) -> anyhow::Result<()> {
    state.refresh_tokens.delete_token(id).await?;
    Ok(())
}

/// Revokes all refresh tokens for a user.
pub async fn revoke_all_user_tokens(state: &SharedState, user_id: Uuid) -> anyhow::Result<()> {
    let _ = state.refresh_tokens.delete_tokens_for_user(user_id).await?;
    Ok(())
}

/// Cleanup expired tokens.
pub async fn cleanup_expired_tokens(state: &SharedState) -> anyhow::Result<u64> {
    Ok(state.refresh_tokens.cleanup_expired_tokens(Utc::now()).await?)
}

fn sha256_hex(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

fn secure_secret_matches(expected_hash: &str, candidate_secret: &str) -> bool {
    let candidate_hash = sha256_hex(candidate_secret);
    constant_time_eq(expected_hash.as_bytes(), candidate_hash.as_bytes())
}
