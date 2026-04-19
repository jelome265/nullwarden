use crate::auth::password::{hash_password, verify_password};
use crate::db::pool::SharedState;
use crate::error::AppError;
use chrono::{Duration, Utc};
use sqlx::Row;
use uuid::Uuid;

/// Issues a new refresh token for a user.
/// Returns a string in the format "token_id:secret".
pub async fn issue_refresh_token(state: &SharedState, user_id: Uuid) -> anyhow::Result<String> {
    let token_id = Uuid::new_v4();
    let secret = Uuid::new_v4().to_string();
    let secret_hash = hash_password(&state.config, &secret).await?;
    let expires_at = Utc::now() + Duration::days(state.config.jwt_refresh_expire_days);

    sqlx::query(
        "INSERT INTO refresh_tokens (id, secret_hash, user_id, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(token_id)
    .bind(secret_hash)
    .bind(user_id)
    .bind(expires_at)
    .execute(&state.db)
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

    let row = sqlx::query(
        "SELECT secret_hash, user_id FROM refresh_tokens WHERE id = $1 AND expires_at > now()",
    )
    .bind(token_id)
    .fetch_optional(&state.db)
    .await?;

    match row {
        Some(row) => {
            let secret_hash: String = row.get("secret_hash");
            let user_id: Uuid = row.get("user_id");

            if verify_password(&secret_hash, secret).await.unwrap_or(false) {
                // Revoke after one-time use
                let _ = revoke_refresh_token(state, token_id).await;
                Ok(user_id)
            } else {
                Err(AppError::Unauthorized("Invalid token secret".to_string()))
            }
        }
        None => Err(AppError::Unauthorized(
            "Token expired or not found".to_string(),
        )),
    }
}

/// Revokes a refresh token by its ID.
pub async fn revoke_refresh_token(state: &SharedState, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM refresh_tokens WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// Revokes all refresh tokens for a user.
pub async fn revoke_all_user_tokens(state: &SharedState, user_id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// Cleanup expired tokens.
pub async fn cleanup_expired_tokens(state: &SharedState) -> anyhow::Result<u64> {
    let res = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < now()")
        .execute(&state.db)
        .await?;
    Ok(res.rows_affected())
}
