use crate::{
    client::sync::SyncClient,
    config::{warn_if_default_server_url, Config},
    input::prompt_password,
    session::load_access_token,
    sync_state::SyncState,
};
use anyhow::Context;
use nullwarden_core::vault::VaultStore;

pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;
    warn_if_default_server_url(&config, "pull");
    let token = load_access_token()?;
    let mut sync_state = SyncState::load(&config.vault_path)?;

    let client = SyncClient::new(config.server_url, Some(token));
    let (version, bytes) = client.pull(sync_state.last_version).await?;

    let master_password = prompt_password("Master password")?;
    let store = VaultStore::new(&config.vault_path);

    // UC-06: Validate integrity before writing
    store
        .unlock_bytes(&master_password, &bytes)
        .context("failed to decrypt downloaded vault (integrity check failed)")?;

    create_local_backup(&config.vault_path)
        .await
        .context("failed to create a local backup before overwrite")?;

    tokio::fs::write(&config.vault_path, &bytes)
        .await
        .context("failed to write local vault")?;

    sync_state.last_version = version;
    sync_state.save(&config.vault_path)?;

    println!("Vault pull completed (version {})", version);
    Ok(())
}

async fn create_local_backup(vault_path: &std::path::Path) -> anyhow::Result<()> {
    if !tokio::fs::try_exists(vault_path).await? {
        return Ok(());
    }

    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let backup_path = vault_path.with_extension(format!("bak.{suffix}"));
    tokio::fs::copy(vault_path, &backup_path)
        .await
        .with_context(|| format!("failed to write backup to {}", backup_path.display()))?;
    Ok(())
}
