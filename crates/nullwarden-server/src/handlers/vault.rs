use crate::{
    db::pool::SharedState,
    error::{AppError, AppResult},
    middleware::auth::CurrentUser,
};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

pub async fn get_vault(
    State(state): State<SharedState>,
    user: CurrentUser,
) -> AppResult<impl IntoResponse> {
    state
        .vault_rate_limiter
        .check_key(&user.id)
        .map_err(|_| AppError::TooManyRequests("vault request rate limit exceeded".to_string()))?;

    let vault = state
        .vaults
        .get_vault(user.id)
        .await?
        .ok_or_else(|| AppError::NotFound("Resource not found".to_string()))?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        "X-Vault-Version",
        axum::http::HeaderValue::from_str(&vault.version.to_string())
            .expect("version is always a valid header value"),
    );
    tracing::info!(user_id = %user.id, version = vault.version, "vault downloaded");

    Ok((StatusCode::OK, response_headers, vault.blob))
}

pub async fn put_vault(
    State(state): State<SharedState>,
    user: CurrentUser,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    let expected_version = headers
        .get("X-If-Match")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());

    let force = headers.get("X-Force").is_some();
    state
        .vault_rate_limiter
        .check_key(&user.id)
        .map_err(|_| AppError::TooManyRequests("vault request rate limit exceeded".to_string()))?;
    if force {
        state
            .force_push_rate_limiter
            .check_key(&user.id)
            .map_err(|_| AppError::TooManyRequests("force-push rate limit exceeded".to_string()))?;
    }
    nullwarden_core::vault::header::VaultHeader::decode(&body)
        .map_err(|_| AppError::BadRequest("invalid vault blob header".to_string()))?;
    tracing::info!(user_id = %user.id, expected_version, force, "vault upload attempt");

    match state
        .vaults
        .put_vault(
            user.id,
            body.to_vec(),
            expected_version,
            force,
            state.config.vault_history_retention_days,
        )
        .await
    {
        Ok(stored) => {
            tracing::info!(user_id = %user.id, version = stored.version, force, "vault uploaded");
            Ok((StatusCode::OK, format!("version={}", stored.version)))
        }
        Err(sqlx::Error::RowNotFound) => {
            tracing::warn!(user_id = %user.id, expected_version, "vault upload conflict");
            Err(AppError::Conflict("Vault version mismatch".to_string()))
        }
        Err(e) => Err(AppError::Database(e)),
    }
}

pub async fn purge_vault_history(
    State(state): State<SharedState>,
    user: CurrentUser,
) -> AppResult<StatusCode> {
    state.vaults.purge_history(user.id).await?;
    tracing::warn!(user_id = %user.id, "vault history purged");
    Ok(StatusCode::NO_CONTENT)
}
