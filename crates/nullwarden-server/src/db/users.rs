use crate::db::pool::{SharedState, StoredUser};
use sqlx::Row;
use tracing::error;
use uuid::Uuid;

pub async fn insert_user(
    state: &SharedState,
    username: String,
    password_hash: String,
) -> Option<StoredUser> {
    let id = Uuid::new_v4();
    let res = sqlx::query(
        "INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3) RETURNING id, username, password_hash",
    )
    .bind(id)
    .bind(&username)
    .bind(&password_hash)
    .fetch_one(&state.db)
    .await;

    match res {
        Ok(row) => Some(StoredUser {
            id: row.get::<Uuid, _>("id"),
            password_hash: row.get::<String, _>("password_hash"),
        }),
        Err(e) => {
            error!("DB insert_user failed: {}", e);
            None
        }
    }
}

pub async fn find_user(state: &SharedState, username: &str) -> Option<StoredUser> {
    let res = sqlx::query("SELECT id, password_hash FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(&state.db)
        .await;

    match res {
        Ok(Some(row)) => Some(StoredUser {
            id: row.get::<Uuid, _>("id"),
            password_hash: row.get::<String, _>("password_hash"),
        }),
        Ok(None) => None,
        Err(e) => {
            error!("DB find_user failed: {}", e);
            None
        }
    }
}
