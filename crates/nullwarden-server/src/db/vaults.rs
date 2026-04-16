use crate::db::pool::{SharedState, StoredVault};
use sqlx::Row;
use uuid::Uuid;
use tracing::error;
pub async fn get_vault(state: &SharedState, user_id: Uuid) -> Option<StoredVault> {
    let res = sqlx::query("SELECT user_id, version, blob FROM vaults WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    match res {
        Ok(Some(row)) => Some(StoredVault {
            owner_id: row.get::<Uuid, _>("user_id"),
            version: row.get::<i64, _>("version") as u64,
            blob: row.get::<Vec<u8>, _>("blob"),
        }),
        Ok(None) => None,
        Err(e) => {
            error!("DB get_vault failed: {}", e);
            None
        }
    }
}

pub async fn put_vault(
    state: &SharedState,
    user_id: Uuid,
    blob: Vec<u8>,
    expected_version: Option<u64>,
) -> Result<StoredVault, sqlx::Error> {
    // If expected_version is None, we allow the first push (version 1)
    // If expected_version is Some(v), we only allow update if current version matches v

    let res = if let Some(ev) = expected_version {
        sqlx::query(
            "UPDATE vaults SET blob = $1, version = version + 1, updated_at = now() 
             WHERE user_id = $2 AND version = $3 
             RETURNING user_id, version, blob"
        )
        .bind(&blob)
        .bind(user_id)
        .bind(ev as i64)
        .fetch_optional(&state.db)
        .await
    } else {
        // First push
        sqlx::query(
            "INSERT INTO vaults (user_id, blob, version) VALUES ($1, $2, 1) 
             RETURNING user_id, version, blob"
        )
        .bind(user_id)
        .bind(&blob)
        .fetch_optional(&state.db)
        .await
    };

    match res {
        Ok(Some(row)) => Ok(StoredVault {
            owner_id: row.get::<Uuid, _>("user_id"),
            version: row.get::<i64, _>("version") as u64,
            blob: row.get::<Vec<u8>, _>("blob"),
        }),
        Ok(None) => {
            // Mismatch or already exists (for INSERT)
            Err(sqlx::Error::RowNotFound) // We'll map this to 409 in handler
        }
        Err(e) => Err(e),
    }
}

