use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    pub vault_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        let data_dir = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
        Self {
            server_url: "http://127.0.0.1:8080".to_string(),
            vault_path: data_dir.join("nullwarden").join("vault.nwd"),
        }
    }
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
