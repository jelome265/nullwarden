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
    let vault = state.vaults.get_vault(user.id)
        .await?
        .ok_or_else(|| AppError::NotFound("Vault not found".to_string()))?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        "X-Vault-Version",
        axum::http::HeaderValue::from_str(&vault.version.to_string())
            .expect("version is always a valid header value"),
    );

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

    match state.vaults.put_vault(user.id, body.to_vec(), expected_version, force).await {
        Ok(stored) => Ok((StatusCode::OK, format!("version={}", stored.version))),
        Err(sqlx::Error::RowNotFound) => Err(AppError::Conflict("Vault version mismatch".to_string())),
        Err(e) => Err(AppError::Database(e)),
    }
}
