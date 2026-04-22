use crate::config::Config;
use anyhow::Context;
use std::path::{Path, PathBuf};

pub async fn run(output: Option<PathBuf>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let output = export_vault(&config.vault_path, output).await?;
    println!("Exported encrypted vault backup to {}", output.display());
    Ok(())
}

pub async fn export_vault(vault_path: &Path, output: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let output = output.unwrap_or_else(|| vault_path.with_extension("nwbackup"));

    if let Some(parent) = output.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("failed to create export directory")?;
    }

    let bytes = tokio::fs::read(vault_path)
        .await
        .context("failed to read local vault for export")?;

    tokio::fs::write(&output, bytes)
        .await
        .context("failed to write exported vault backup")?;

    Ok(output)
}
