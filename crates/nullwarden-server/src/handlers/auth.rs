use crate::{
    auth::{jwt, password, token},
    db::pool::SharedState,
    error::{AppError, AppResult},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub async fn register(
    State(state): State<SharedState>,
    Json(payload): Json<AuthRequest>,
) -> AppResult<StatusCode> {
    validate_username(&payload.username)?;
    let username = payload.username.clone();
    let hash = password::hash_password(&state.config, &payload.password).await?;

    state
        .users
        .insert_user(payload.username, hash)
        .await
        .map_err(|e| {
            if let Some(db_err) = e.as_database_error() {
                if db_err.is_unique_violation() {
                    return AppError::Conflict("User already exists".to_string());
                }
            }
            AppError::Database(e)
        })?;

    tracing::info!(username = %username, "user registered");

    Ok(StatusCode::CREATED)
}

pub async fn login(
    State(state): State<SharedState>,
    Json(payload): Json<AuthRequest>,
) -> AppResult<Json<AuthResponse>> {
    validate_username(&payload.username)?;
    let user_opt = state.users.find_user(&payload.username).await?;

    // C-02: Always verify a hash to prevent timing oracle for username enumeration
    let hash = user_opt
        .as_ref()
        .map(|u| u.password_hash.as_str())
        .unwrap_or(&state.dummy_hash);

    let ok = password::verify_password(hash, &payload.password).await?;

    if !ok || user_opt.is_none() {
        tracing::warn!(username = %payload.username, "login failed");
        return Err(AppError::Unauthorized(
            "Invalid username or password".to_string(),
        ));
    }

    let user = user_opt.unwrap();
    let access_token = jwt::issue_access_token(&state, user.id)?;
    let refresh_token = token::issue_refresh_token(&state, user.id).await?;

    tracing::info!(user_id = %user.id, "user logged in");

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
    }))
}

pub async fn refresh(
    State(state): State<SharedState>,
    Json(payload): Json<RefreshRequest>,
) -> AppResult<Json<AuthResponse>> {
    let user_id = token::consume_refresh_token(&state, &payload.refresh_token).await?;

    let access_token = jwt::issue_access_token(&state, user_id)?;
    let refresh_token = token::issue_refresh_token(&state, user_id).await?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
    }))
}

pub async fn logout(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(payload): Json<RefreshRequest>,
) -> AppResult<StatusCode> {
    let auth_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|auth_header| auth_header.to_str().ok())
        .and_then(|auth_str| auth_str.strip_prefix("Bearer "));

    let user_id = token::consume_refresh_token(&state, &payload.refresh_token).await?;

    if let Some(token) = auth_token {
        jwt::block_token(&state, token).await?;
    }

    tracing::info!(user_id = %user_id, "user logged out");

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_user(
    State(state): State<SharedState>,
    user: crate::middleware::auth::CurrentUser,
) -> AppResult<StatusCode> {
    token::revoke_all_user_tokens(&state, user.id).await?;
    state.users.delete_user(user.id).await?;
    tracing::warn!(user_id = %user.id, "user deleted");
    Ok(StatusCode::NO_CONTENT)
}

fn validate_username(username: &str) -> AppResult<()> {
    let len = username.chars().count();
    if !(3..=64).contains(&len) {
        return Err(AppError::BadRequest(
            "username must be between 3 and 64 characters".to_string(),
        ));
    }
    Ok(())
}
