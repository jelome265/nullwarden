use nullwarden_core::types::SecretString;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub database_url: Option<String>,
    pub jwt_secret: SecretString,
    pub server_host: String,
    pub server_port: u16,
    pub rate_limit_auth_requests: u32,
    pub rate_limit_auth_window_secs: u64,
    pub jwt_access_expire_secs: i64,
    pub jwt_refresh_expire_days: i64,
    pub auth_argon2_m_cost: u32,
    pub auth_argon2_t_cost: u32,
    pub auth_argon2_p_cost: u32,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
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
        Ok(cfg)
    }
}
