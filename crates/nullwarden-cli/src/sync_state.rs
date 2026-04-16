use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncState {
    pub last_version: u64,
}

impl SyncState {
    pub fn load(vault_path: &Path) -> anyhow::Result<Self> {
        let path = state_path(vault_path);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path).context("failed to read sync state")?;
        serde_json::from_str(&raw).context("failed to parse sync state")
    }

    pub fn save(&self, vault_path: &Path) -> anyhow::Result<()> {
        let path = state_path(vault_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(self)?;
        fs::write(path, raw).context("failed to save sync state")?;
        Ok(())
    }
}

fn state_path(vault_path: &Path) -> PathBuf {
    let mut path = vault_path.to_path_buf();
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".sync");
    path.set_file_name(name);
    path
}
