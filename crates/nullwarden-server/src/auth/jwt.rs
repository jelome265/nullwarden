use crate::db::pool::SharedState;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub fn issue_access_token(state: &SharedState, user_id: Uuid) -> anyhow::Result<String> {
    let exp = (Utc::now() + Duration::seconds(state.config.jwt_access_expire_secs)).timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        exp,
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )?)
}

pub fn validate_access_token(state: &SharedState, token: &str) -> anyhow::Result<Uuid> {
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::default(),
    )?
    .claims;
    Ok(Uuid::parse_str(&claims.sub)?)
}
