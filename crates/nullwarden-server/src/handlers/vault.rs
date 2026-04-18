use crate::{
    db::{pool::SharedState, vaults},
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
) -> Result<impl IntoResponse, StatusCode> {
    let vault = vaults::get_vault(&state, user.id)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert("X-Vault-Version", vault.version.into());

    Ok((StatusCode::OK, response_headers, vault.blob))
}

pub async fn put_vault(
    State(state): State<SharedState>,
    user: CurrentUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let expected_version = headers
        .get("X-If-Match")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    
    let force = headers.get("X-Force").is_some();

    match vaults::put_vault(&state, user.id, body.to_vec(), expected_version, force).await {
        Ok(stored) => Ok((StatusCode::OK, format!("version={}", stored.version))),
        Err(sqlx::Error::RowNotFound) => Err(StatusCode::CONFLICT),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
