use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

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
        let tmp_path = path.with_extension("sync.tmp");
        let mut file =
            fs::File::create(&tmp_path).context("failed to create sync state temp file")?;
        file.write_all(raw.as_bytes())
            .context("failed to write sync state temp file")?;
        file.sync_all()
            .context("failed to sync sync state temp file")?;
        fs::rename(&tmp_path, &path).context("failed to atomically replace sync state")?;
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
