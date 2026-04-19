use crate::db::pool::StoredVault;
use crate::db::VaultRepository;
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub struct SqlxVaultRepository {
    pub pool: PgPool,
}

impl SqlxVaultRepository {
    async fn rls_transaction(
        &self,
        user_id: Uuid,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(&format!("SET LOCAL auth.uid = '{}'", user_id))
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }
}

#[async_trait]
impl VaultRepository for SqlxVaultRepository {
    async fn get_vault(&self, user_id: Uuid) -> Result<Option<StoredVault>, sqlx::Error> {
        let mut tx = self.rls_transaction(user_id).await?;

        let res = sqlx::query("SELECT version, blob FROM vaults WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;

        tx.commit().await?;

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
        let mut tx = self.rls_transaction(user_id).await?;

        let res = if force {
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
