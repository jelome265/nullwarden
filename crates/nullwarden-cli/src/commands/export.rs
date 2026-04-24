use crate::config::Config;
use crate::input::{prompt_password, validate_password_strength};
use anyhow::Context;
use nullwarden_core::vault::VaultStore;
use std::path::{Path, PathBuf};

pub async fn run(output: Option<PathBuf>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let output = output.unwrap_or_else(|| config.vault_path.with_extension("nwbackup"));

    println!("Exporting vault to {}...", output.display());

    let password = prompt_password("Enter current master password")?;

    println!("\nTo secure your backup, you must provide a backup password.");
    let backup_password = loop {
        let p1 = prompt_password("Enter new backup password")?;
        validate_password_strength(&p1)?;
        let p2 = prompt_password("Confirm backup password")?;
        if p1 == p2 {
            break p1;
        }
        println!("Passwords do not match. Try again.");
    };

    export_vault(&config.vault_path, &output, &password, &backup_password).await?;

    println!(
        "\nExported re-encrypted vault backup to {}",
        output.display()
    );
    Ok(())
}

pub async fn export_vault(
    vault_path: &Path,
    output: &Path,
    master_password: &str,
    backup_password: &str,
) -> anyhow::Result<()> {
    validate_password_strength(backup_password)?;
    let store = VaultStore::new(vault_path);
    let data = store
        .unlock(master_password)
        .context("Failed to unlock current vault")?;

    if let Some(parent) = output.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("failed to create export directory")?;
    }

    let backup_store = VaultStore::new(output);
    backup_store
        .save(backup_password, &data)
        .context("Failed to save backup vault")?;

    Ok(())
}
