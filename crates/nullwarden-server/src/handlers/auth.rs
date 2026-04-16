use crate::{
    auth::{jwt, password, token},
    db::{pool::SharedState, users},
};
use axum::{
    extract::State,
    http::{StatusCode, HeaderMap},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub async fn register(
    State(state): State<SharedState>,
    Json(payload): Json<AuthRequest>,
) -> Result<StatusCode, StatusCode> {
    let hash = password::hash_password(&state, &payload.password)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    users::insert_user(&state, payload.username, hash)
        .await
        .ok_or(StatusCode::CONFLICT)?;
    Ok(StatusCode::CREATED)
}

pub async fn login(
    State(state): State<SharedState>,
    Json(payload): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let user = users::find_user(&state, &payload.username)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let ok = password::verify_password(&user.password_hash, &payload.password)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !ok {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let access_token = jwt::issue_access_token(&state, user.id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let refresh_token = token::issue_refresh_token(&state, user.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
    }))
}

pub async fn refresh(
    State(state): State<SharedState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let user_id = token::consume_refresh_token(&state, &payload.refresh_token)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let access_token = jwt::issue_access_token(&state, user_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let refresh_token = token::issue_refresh_token(&state, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
    }))
}

pub async fn logout(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(payload): Json<RefreshRequest>,
) -> Result<StatusCode, StatusCode> {
    // 1. Block access token if present
    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let _ = jwt::block_token(&state, token).await;
            }
        }
    }

    // 2. Revoke refresh token
    let _ = token::consume_refresh_token(&state, &payload.refresh_token).await;

    Ok(StatusCode::NO_CONTENT)
}
