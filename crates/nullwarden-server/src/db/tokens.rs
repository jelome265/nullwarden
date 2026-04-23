use crate::db::{RefreshTokenRepository, StoredRefreshToken, TokenBlocklistRepository};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::query::query;
use sqlx::row::Row;
use sqlx_postgres::{PgPool, Postgres};
use uuid::Uuid;

pub struct SqlxRefreshTokenRepository {
    pub pool: PgPool,
}

#[async_trait]
impl RefreshTokenRepository for SqlxRefreshTokenRepository {
    async fn insert_token(
        &self,
        id: Uuid,
        secret_hash: String,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        query::<Postgres>(
            "INSERT INTO refresh_tokens (id, secret_hash, user_id, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(secret_hash)
        .bind(user_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn find_token(&self, id: Uuid) -> Result<Option<StoredRefreshToken>, sqlx::Error> {
        let row = query::<Postgres>(
            "SELECT secret_hash, user_id, expires_at FROM refresh_tokens WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| StoredRefreshToken {
            secret_hash: row.get("secret_hash"),
            user_id: row.get("user_id"),
            expires_at: row.get("expires_at"),
        }))
    }

    async fn delete_token(&self, id: Uuid) -> Result<(), sqlx::Error> {
        query::<Postgres>("DELETE FROM refresh_tokens WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_tokens_for_user(&self, user_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = query::<Postgres>("DELETE FROM refresh_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn cleanup_expired_tokens(&self, now: DateTime<Utc>) -> Result<u64, sqlx::Error> {
        let result = query::<Postgres>("DELETE FROM refresh_tokens WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

pub struct SqlxTokenBlocklistRepository {
    pub pool: PgPool,
}

#[async_trait]
impl TokenBlocklistRepository for SqlxTokenBlocklistRepository {
    async fn insert_blocked_token(
        &self,
        token_hash: String,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        query::<Postgres>(
            "INSERT INTO token_blocklist (token_hash, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(token_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn contains_token(&self, token_hash: &str) -> Result<bool, sqlx::Error> {
        let row = query::<Postgres>("SELECT 1 FROM token_blocklist WHERE token_hash = $1")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    async fn cleanup_expired_tokens(&self, now: DateTime<Utc>) -> Result<u64, sqlx::Error> {
        let result = query::<Postgres>("DELETE FROM token_blocklist WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
