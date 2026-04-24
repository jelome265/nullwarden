use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    pub vault_path: PathBuf,
}

pub const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8080";

impl Default for Config {
    fn default() -> Self {
        let data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nullwarden");
        Self {
            server_url: DEFAULT_SERVER_URL.to_string(),
            vault_path: data_dir.join("vault.nw"),
        }
    }
}

pub fn warn_if_default_server_url(config: &Config, command: &str) {
    if config.server_url == DEFAULT_SERVER_URL {
        eprintln!(
            "Warning: `{command}` is using the default server URL ({DEFAULT_SERVER_URL}). Configure `server_url` before using a real sync server."
        );
    }
}

pub fn ensure_non_default_server_url(config: &Config, command: &str) -> anyhow::Result<()> {
    if config.server_url == DEFAULT_SERVER_URL
        && std::env::var("NULLWARDEN_ALLOW_DEFAULT_SERVER_URL")
            .ok()
            .as_deref()
            != Some("1")
    {
        anyhow::bail!(
            "`{command}` refuses to use the default server URL ({DEFAULT_SERVER_URL}). Set `server_url` explicitly or set NULLWARDEN_ALLOW_DEFAULT_SERVER_URL=1 to override."
        );
    }
    Ok(())
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config_path = config_path();
        if !config_path.exists() {
            let default = Self::default();
            default.save()?;
            return Ok(default);
        }
        let raw = fs::read_to_string(&config_path).context("failed to read cli config")?;
        toml::from_str(&raw).context("failed to parse cli config")
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }
}

fn config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("nullwarden")
        .join("config.toml")
}
