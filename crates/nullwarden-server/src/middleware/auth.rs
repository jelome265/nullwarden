use crate::{auth::jwt, db::pool::SharedState};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
};
use uuid::Uuid;

pub struct CurrentUser {
    pub id: Uuid,
}

#[async_trait]
impl FromRequestParts<SharedState> for CurrentUser {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &SharedState) -> Result<Self, Self::Rejection> {
        // Extract Authorization header
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        if !auth_header.starts_with("Bearer ") {
            return Err(StatusCode::UNAUTHORIZED);
        }

        let token = &auth_header[7..];

        // Validate token
        let user_id = jwt::validate_access_token(state, token)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        Ok(CurrentUser { id: user_id })
    }
}
