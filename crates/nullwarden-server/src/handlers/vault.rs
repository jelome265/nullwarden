use crate::{
    auth::jwt,
    db::{pool::SharedState, vaults},
};
use axum::{
    body::Bytes,
    extract::State,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::IntoResponse,
};

pub async fn get_vault(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&state, &headers).await?;
    let vault = vaults::get_vault(&state, user_id)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert("X-Vault-Version", vault.version.into());

    Ok((StatusCode::OK, response_headers, vault.blob))
}

pub async fn put_vault(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&state, &headers).await?;

    let expected_version = headers
        .get("X-If-Match")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());

    match vaults::put_vault(&state, user_id, body.to_vec(), expected_version).await {
        Ok(stored) => Ok((StatusCode::OK, format!("version={}", stored.version))),
        Err(sqlx::Error::RowNotFound) => Err(StatusCode::CONFLICT),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn extract_user_id(
    state: &SharedState,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, StatusCode> {
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    jwt::validate_access_token(state, token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)
}
