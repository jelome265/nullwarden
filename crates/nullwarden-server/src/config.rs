use nullwarden_core::types::SecretString;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub database_url: Option<String>,
    pub jwt_secret: SecretString,
    #[serde(default = "default_host")]
    pub server_host: String,
    #[serde(default = "default_port")]
    pub server_port: u16,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_auth_requests: u32,
    #[serde(default = "default_rate_limit_window")]
    pub rate_limit_auth_window_secs: u64,
    #[serde(default)]
    pub cors_allowed_origins: String,
    #[serde(default = "default_vault_rate_limit")]
    pub rate_limit_vault_requests_per_minute: u32,
    #[serde(default = "default_force_push_limit")]
    pub rate_limit_force_pushes_per_hour: u32,
    #[serde(default)]
    pub trusted_proxy_cidrs: String,
    #[serde(default = "default_access_expire")]
    pub jwt_access_expire_secs: i64,
    #[serde(default = "default_refresh_expire")]
    pub jwt_refresh_expire_days: i64,
    #[serde(default = "default_jwt_issuer")]
    pub jwt_issuer: String,
    #[serde(default = "default_jwt_audience")]
    pub jwt_audience: String,
    #[serde(default = "default_m_cost")]
    pub auth_argon2_m_cost: u32,
    #[serde(default = "default_t_cost")]
    pub auth_argon2_t_cost: u32,
    #[serde(default = "default_p_cost")]
    pub auth_argon2_p_cost: u32,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    #[serde(default = "default_db_max_connections")]
    pub db_max_connections: u32,
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
    #[serde(default = "default_history_retention_days")]
    pub vault_history_retention_days: i64,
    pub health_check_token: Option<SecretString>,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}
fn default_port() -> u16 {
    8080
}
fn default_rate_limit() -> u32 {
    5
}
fn default_rate_limit_window() -> u64 {
    600
}
fn default_vault_rate_limit() -> u32 {
    60
}
fn default_force_push_limit() -> u32 {
    3
}
fn default_access_expire() -> i64 {
    900
}
fn default_refresh_expire() -> i64 {
    7
}
fn default_jwt_issuer() -> String {
    "nullwarden-server".to_string()
}
fn default_jwt_audience() -> String {
    "nullwarden-cli".to_string()
}
fn default_m_cost() -> u32 {
    65536
}
fn default_t_cost() -> u32 {
    3
}
fn default_p_cost() -> u32 {
    4
}
fn default_db_max_connections() -> u32 {
    10
}
fn default_cleanup_interval() -> u64 {
    3600
}
fn default_history_retention_days() -> i64 {
    30
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let mut cfg = envy::from_env::<Self>()?;
        // Prefer explicit Supabase URL env var if provided (SUPABASE_DATABASE_URL or SUPABASE_URL)
        if cfg.database_url.is_none() {
            if let Ok(supabase_url) =
                std::env::var("SUPABASE_DATABASE_URL").or_else(|_| std::env::var("SUPABASE_URL"))
            {
                cfg.database_url = Some(supabase_url);
            }
        }
        if cfg.cleanup_interval_secs < 60 {
            anyhow::bail!("CLEANUP_INTERVAL_SECS must be at least 60 seconds");
        }
        if cfg.rate_limit_auth_requests == 0
            || cfg.rate_limit_vault_requests_per_minute == 0
            || cfg.rate_limit_force_pushes_per_hour == 0
        {
            anyhow::bail!("rate limit values must be greater than zero");
        }
        if cfg.vault_history_retention_days < 1 {
            anyhow::bail!("VAULT_HISTORY_RETENTION_DAYS must be at least 1 day");
        }
        Ok(cfg)
    }
}
