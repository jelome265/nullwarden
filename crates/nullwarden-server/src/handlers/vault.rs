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
    let user_id = extract_user_id(&state, &headers)?;
    let vault = vaults::get_vault(&state, user_id)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;
    let _ = vault.owner_id;
    Ok((StatusCode::OK, vault.blob))
}

pub async fn put_vault(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&state, &headers)?;
    let stored = vaults::put_vault(&state, user_id, body.to_vec()).await;
    Ok((StatusCode::OK, format!("version={}", stored.version)))
}

fn extract_user_id(state: &SharedState, headers: &HeaderMap) -> Result<uuid::Uuid, StatusCode> {
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = auth.strip_prefix("Bearer ").ok_or(StatusCode::UNAUTHORIZED)?;
    jwt::validate_access_token(state, token).map_err(|_| StatusCode::UNAUTHORIZED)
}
