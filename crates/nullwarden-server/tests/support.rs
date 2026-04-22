use async_trait::async_trait;
use axum::Router;
use chrono::{DateTime, Utc};
use nullwarden_core::types::SecretString;
use nullwarden_server::{
    app::build_router,
    auth::password,
    config::Config,
    db::{
        pool::{AppState, StoredUser, StoredVault},
        RefreshTokenRepository, StoredRefreshToken, TokenBlocklistRepository, UserRepository,
        VaultRepository,
    },
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Default)]
pub struct InMemoryState {
    pub users_by_name: HashMap<String, StoredUser>,
    pub vaults: HashMap<Uuid, StoredVault>,
    pub refresh_tokens: HashMap<Uuid, StoredRefreshToken>,
    pub blocked_tokens: HashSet<String>,
}

pub async fn test_app() -> Router {
    test_app_with_limits(5, 600).await
}

pub async fn test_app_with_state() -> (Router, Arc<Mutex<InMemoryState>>) {
    test_app_with_limits_and_state(5, 600).await
}

pub async fn test_app_with_limits(
    rate_limit_auth_requests: u32,
    rate_limit_auth_window_secs: u64,
) -> Router {
    let (app, _) = test_app_with_limits_and_state(rate_limit_auth_requests, rate_limit_auth_window_secs).await;
    app
}

pub async fn test_app_with_limits_and_state(
    rate_limit_auth_requests: u32,
    rate_limit_auth_window_secs: u64,
) -> (Router, Arc<Mutex<InMemoryState>>) {
    let config = Config {
        database_url: None,
        jwt_secret: SecretString("integration-test-jwt-secret-32-bytes".to_string()),
        server_host: "127.0.0.1".to_string(),
        server_port: 0,
        rate_limit_auth_requests,
        rate_limit_auth_window_secs,
        jwt_access_expire_secs: 900,
        jwt_refresh_expire_days: 7,
        jwt_issuer: "nullwarden-server".to_string(),
        jwt_audience: "nullwarden-cli".to_string(),
        auth_argon2_m_cost: 8 * 1024,
        auth_argon2_t_cost: 2,
        auth_argon2_p_cost: 1,
        tls_cert_path: None,
        tls_key_path: None,
        db_max_connections: 1,
        cleanup_interval_secs: 3600,
    };

    let state = Arc::new(Mutex::new(InMemoryState::default()));
    let dummy_hash = password::hash_password(&config, "dummy-password").await.unwrap();

    let app = build_router(Arc::new(AppState::init(
        config,
        Arc::new(InMemoryUserRepository {
            state: state.clone(),
        }),
        Arc::new(InMemoryVaultRepository {
            state: state.clone(),
        }),
        Arc::new(InMemoryRefreshTokenRepository {
            state: state.clone(),
        }),
        Arc::new(InMemoryTokenBlocklistRepository {
            state: state.clone(),
        }),
        dummy_hash,
    )));

    (app, state)
}

struct InMemoryUserRepository {
    state: Arc<Mutex<InMemoryState>>,
}

#[async_trait]
impl UserRepository for InMemoryUserRepository {
    async fn insert_user(
        &self,
        username: String,
        password_hash: String,
    ) -> Result<StoredUser, sqlx::Error> {
        let mut state = self.state.lock().unwrap();
        let user = StoredUser {
            id: Uuid::new_v4(),
            password_hash,
        };
        state.users_by_name.insert(username, user.clone());
        Ok(user)
    }

    async fn find_user(&self, username: &str) -> Result<Option<StoredUser>, sqlx::Error> {
        let state = self.state.lock().unwrap();
        Ok(state.users_by_name.get(username).cloned())
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<u64, sqlx::Error> {
        let mut state = self.state.lock().unwrap();
        let before = state.users_by_name.len();
        state.users_by_name.retain(|_, user| user.id != user_id);
        Ok((before - state.users_by_name.len()) as u64)
    }
}

struct InMemoryVaultRepository {
    state: Arc<Mutex<InMemoryState>>,
}

#[async_trait]
impl VaultRepository for InMemoryVaultRepository {
    async fn get_vault(&self, user_id: Uuid) -> Result<Option<StoredVault>, sqlx::Error> {
        let state = self.state.lock().unwrap();
        Ok(state.vaults.get(&user_id).cloned())
    }

    async fn put_vault(
        &self,
        user_id: Uuid,
        blob: Vec<u8>,
        expected_version: Option<u64>,
        force: bool,
    ) -> Result<StoredVault, sqlx::Error> {
        let mut state = self.state.lock().unwrap();
        let current = state.vaults.get(&user_id).cloned();

        let stored = if force {
            let version = current.map_or(1, |vault| vault.version + 1);
            StoredVault { version, blob }
        } else if let Some(expected_version) = expected_version {
            match current {
                Some(vault) if vault.version == expected_version => StoredVault {
                    version: vault.version + 1,
                    blob,
                },
                _ => return Err(sqlx::Error::RowNotFound),
            }
        } else if current.is_none() {
            StoredVault { version: 1, blob }
        } else {
            return Err(sqlx::Error::RowNotFound);
        };

        state.vaults.insert(user_id, stored.clone());
        Ok(stored)
    }
}

struct InMemoryRefreshTokenRepository {
    state: Arc<Mutex<InMemoryState>>,
}

#[async_trait]
impl RefreshTokenRepository for InMemoryRefreshTokenRepository {
    async fn insert_token(
        &self,
        id: Uuid,
        secret_hash: String,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        let mut state = self.state.lock().unwrap();
        state.refresh_tokens.insert(
            id,
            StoredRefreshToken {
                secret_hash,
                user_id,
                expires_at,
            },
        );
        Ok(())
    }

    async fn find_token(&self, id: Uuid) -> Result<Option<StoredRefreshToken>, sqlx::Error> {
        let state = self.state.lock().unwrap();
        Ok(state.refresh_tokens.get(&id).cloned())
    }

    async fn delete_token(&self, id: Uuid) -> Result<(), sqlx::Error> {
        let mut state = self.state.lock().unwrap();
        state.refresh_tokens.remove(&id);
        Ok(())
    }

    async fn delete_tokens_for_user(&self, user_id: Uuid) -> Result<u64, sqlx::Error> {
        let mut state = self.state.lock().unwrap();
        let before = state.refresh_tokens.len();
        state.refresh_tokens.retain(|_, token| token.user_id != user_id);
        Ok((before - state.refresh_tokens.len()) as u64)
    }

    async fn cleanup_expired_tokens(&self, now: DateTime<Utc>) -> Result<u64, sqlx::Error> {
        let mut state = self.state.lock().unwrap();
        let before = state.refresh_tokens.len();
        state.refresh_tokens.retain(|_, token| token.expires_at >= now);
        Ok((before - state.refresh_tokens.len()) as u64)
    }
}

struct InMemoryTokenBlocklistRepository {
    state: Arc<Mutex<InMemoryState>>,
}

#[async_trait]
impl TokenBlocklistRepository for InMemoryTokenBlocklistRepository {
    async fn insert_blocked_token(
        &self,
        token_hash: String,
        _expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        let mut state = self.state.lock().unwrap();
        state.blocked_tokens.insert(token_hash);
        Ok(())
    }

    async fn contains_token(&self, token_hash: &str) -> Result<bool, sqlx::Error> {
        let state = self.state.lock().unwrap();
        Ok(state.blocked_tokens.contains(token_hash))
    }

    async fn cleanup_expired_tokens(&self, _now: DateTime<Utc>) -> Result<u64, sqlx::Error> {
        Ok(0)
    }
}
