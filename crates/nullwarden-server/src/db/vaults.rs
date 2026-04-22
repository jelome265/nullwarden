use crate::db::pool::StoredVault;
use crate::db::VaultRepository;
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub struct SqlxVaultRepository {
    pub pool: PgPool,
}

#[async_trait]
impl VaultRepository for SqlxVaultRepository {
    async fn get_vault(&self, user_id: Uuid) -> Result<Option<StoredVault>, sqlx::Error> {
        let res = sqlx::query("SELECT version, blob FROM vaults WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(res.map(|row| StoredVault {
            version: row.get::<i64, _>("version") as u64,
            blob: row.get::<Vec<u8>, _>("blob"),
        }))
    }

    async fn put_vault(
        &self,
        user_id: Uuid,
        blob: Vec<u8>,
        expected_version: Option<u64>,
        force: bool,
    ) -> Result<StoredVault, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        let res = if force {
            backup_current_vault(&mut tx, user_id).await?;
            sqlx::query(
                "INSERT INTO vaults (user_id, blob, version) VALUES ($1, $2, 1)
                 ON CONFLICT (user_id) DO UPDATE SET blob = EXCLUDED.blob, version = vaults.version + 1, updated_at = now()
                 RETURNING version, blob",
            )
            .bind(user_id)
            .bind(&blob)
            .fetch_optional(&mut *tx)
            .await?
        } else if let Some(ev) = expected_version {
            backup_current_vault_if_version_matches(&mut tx, user_id, ev).await?;
            sqlx::query(
                "UPDATE vaults SET blob = $1, version = version + 1, updated_at = now() 
                 WHERE user_id = $2 AND version = $3 
                 RETURNING version, blob",
            )
            .bind(&blob)
            .bind(user_id)
            .bind(ev as i64)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            // First push
            // H-11: Use ON CONFLICT DO NOTHING and detect no-rows to handle race
            sqlx::query(
                "INSERT INTO vaults (user_id, blob, version) VALUES ($1, $2, 1) 
                 ON CONFLICT (user_id) DO NOTHING
                 RETURNING version, blob",
            )
            .bind(user_id)
            .bind(&blob)
            .fetch_optional(&mut *tx)
            .await?
        };
        match res {
            Some(row) => {
                tx.commit().await?;
                Ok(StoredVault {
                    version: row.get::<i64, _>("version") as u64,
                    blob: row.get::<Vec<u8>, _>("blob"),
                })
            }
            None => {
                tx.rollback().await?;
                Err(sqlx::Error::RowNotFound)
            }
        }
    }
}

async fn backup_current_vault(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO vault_history (user_id, version, blob)
         SELECT user_id, version, blob FROM vaults WHERE user_id = $1",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await?;

    // Cap history at 3 versions per user
    sqlx::query(
        "DELETE FROM vault_history
         WHERE user_id = $1 AND id NOT IN (
             SELECT id FROM vault_history
             WHERE user_id = $1
             ORDER BY created_at DESC
             LIMIT 3
         )",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

async fn backup_current_vault_if_version_matches(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    expected_version: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO vault_history (user_id, version, blob)
         SELECT user_id, version, blob FROM vaults WHERE user_id = $1 AND version = $2",
    )
    .bind(user_id)
    .bind(expected_version as i64)
    .execute(&mut **tx)
    .await?;

    // Cap history at 3 versions per user
    sqlx::query(
        "DELETE FROM vault_history
         WHERE user_id = $1 AND id NOT IN (
             SELECT id FROM vault_history
             WHERE user_id = $1
             ORDER BY created_at DESC
             LIMIT 3
         )",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await?;

    Ok(())
}
