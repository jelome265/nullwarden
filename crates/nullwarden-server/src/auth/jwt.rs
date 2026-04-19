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
    let exp =
        (Utc::now() + Duration::seconds(state.config.jwt_access_expire_secs)).timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        exp,
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

    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.0.as_bytes()),
        &Validation::default(),
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
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.0.as_bytes()),
        &Validation::default(),
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

    sqlx::query("INSERT INTO token_blocklist (token_hash, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(token_hash)
        .bind(expires_at)
        .execute(&state.db)
        .await?;

    Ok(())
}

async fn is_token_blocked(state: &SharedState, token: &str) -> anyhow::Result<bool> {
    let token_hash = sha256_hash(token);
    let row = sqlx::query("SELECT 1 FROM token_blocklist WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(&state.db)
        .await?;
    Ok(row.is_some())
}

fn sha256_hash(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}
