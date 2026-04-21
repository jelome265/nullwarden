use crate::config::Config;
use anyhow::Context;
use std::path::PathBuf;

pub async fn run(output: Option<PathBuf>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let output = output.unwrap_or_else(|| config.vault_path.with_extension("nwbackup"));

    if let Some(parent) = output.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("failed to create export directory")?;
    }

    let bytes = tokio::fs::read(&config.vault_path)
        .await
        .context("failed to read local vault for export")?;

    tokio::fs::write(&output, bytes)
        .await
        .context("failed to write exported vault backup")?;

    println!("Exported encrypted vault backup to {}", output.display());
    Ok(())
}
