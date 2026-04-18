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
    #[serde(default = "default_access_expire")]
    pub jwt_access_expire_secs: i64,
    #[serde(default = "default_m_cost")]
    pub auth_argon2_m_cost: u32,
    #[serde(default = "default_t_cost")]
    pub auth_argon2_t_cost: u32,
    #[serde(default = "default_p_cost")]
    pub auth_argon2_p_cost: u32,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

fn default_host() -> String { "0.0.0.0".to_string() }
fn default_port() -> u16 { 8080 }
fn default_rate_limit() -> u32 { 5 }
fn default_access_expire() -> i64 { 900 }
fn default_m_cost() -> u32 { 65536 }
fn default_t_cost() -> u32 { 3 }
fn default_p_cost() -> u32 { 4 }

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
