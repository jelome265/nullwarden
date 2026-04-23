use crate::db::pool::StoredUser;
use crate::db::UserRepository;
use async_trait::async_trait;
use sqlx::query::query;
use sqlx::row::Row;
use sqlx_postgres::{PgPool, Postgres};
use uuid::Uuid;

pub struct SqlxUserRepository {
    pub pool: PgPool,
}

#[async_trait]
impl UserRepository for SqlxUserRepository {
    async fn insert_user(
        &self,
        username: String,
        password_hash: String,
    ) -> Result<StoredUser, sqlx::Error> {
        let res = query::<Postgres>(
            "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, password_hash",
        )
        .bind(&username)
        .bind(&password_hash)
        .fetch_one(&self.pool)
        .await?;

        Ok(StoredUser {
            id: res.get::<Uuid, _>("id"),
            password_hash: res.get::<String, _>("password_hash"),
        })
    }

    async fn find_user(&self, username: &str) -> Result<Option<StoredUser>, sqlx::Error> {
        let res = query::<Postgres>("SELECT id, password_hash FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;

        Ok(res.map(|row| StoredUser {
            id: row.get::<Uuid, _>("id"),
            password_hash: row.get::<String, _>("password_hash"),
        }))
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = query::<Postgres>("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}
