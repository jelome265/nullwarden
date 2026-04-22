use crate::db::pool::SharedState;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iss: String,
    aud: String,
}

pub fn issue_access_token(state: &SharedState, user_id: Uuid) -> anyhow::Result<String> {
    let exp =
        (Utc::now() + Duration::seconds(state.config.jwt_access_expire_secs)).timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        exp,
        iss: state.config.jwt_issuer.clone(),
        aud: state.config.jwt_audience.clone(),
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.0.as_bytes()),
    )?)
}

pub async fn validate_access_token(state: &SharedState, token: &str) -> anyhow::Result<Uuid> {
    // H-03: Check blocklist
    if is_token_blocked(state, token).await? {
        anyhow::bail!("token is blocked");
    }

    let mut validation = Validation::default();
    validation.set_audience(&[state.config.jwt_audience.as_str()]);
    validation.set_issuer(&[state.config.jwt_issuer.as_str()]);

    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.0.as_bytes()),
        &validation,
    )?
    .claims;

    // Defense against jsonwebtoken type confusion vulnerability (CVE pending)
    // Explicitly validate exp is a valid timestamp and not malformed
    if claims.exp == 0 {
        anyhow::bail!("invalid token: missing or malformed exp claim");
    }
    let now = Utc::now().timestamp() as usize;
    if claims.exp < now {
        anyhow::bail!("token expired");
    }

    Ok(Uuid::parse_str(&claims.sub)?)
}

pub async fn block_token(state: &SharedState, token: &str) -> anyhow::Result<()> {
    let mut validation = Validation::default();
    validation.set_audience(&[state.config.jwt_audience.as_str()]);
    validation.set_issuer(&[state.config.jwt_issuer.as_str()]);

    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.0.as_bytes()),
        &validation,
    )?
    .claims;

    // Defense against jsonwebtoken type confusion vulnerability
    if claims.exp == 0 {
        anyhow::bail!("invalid token: missing or malformed exp claim");
    }

    let expires_at = chrono::DateTime::<Utc>::from_timestamp(claims.exp as i64, 0)
        .ok_or_else(|| anyhow::anyhow!("invalid expiry in token"))?;

    // Hash token for storage
    let token_hash = sha256_hash(token);

    state
        .token_blocklist
        .insert_blocked_token(token_hash, expires_at)
        .await?;

    Ok(())
}

async fn is_token_blocked(state: &SharedState, token: &str) -> anyhow::Result<bool> {
    let token_hash = sha256_hash(token);
    Ok(state.token_blocklist.contains_token(&token_hash).await?)
}

pub async fn cleanup_blocked_tokens(state: &SharedState) -> anyhow::Result<u64> {
    Ok(state
        .token_blocklist
        .cleanup_expired_tokens(Utc::now())
        .await?)
}

fn sha256_hash(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}
