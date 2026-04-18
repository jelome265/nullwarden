use crate::{
    client::sync::SyncClient, config::Config, input::prompt_password, session::load_access_token,
    sync_state::SyncState,
};
use anyhow::Context;
use nullwarden_core::vault::VaultStore;

pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;
    let token = load_access_token()?;
    let mut sync_state = SyncState::load(&config.vault_path)?;

    let client = SyncClient::new(config.server_url, Some(token));
    let (version, bytes) = client.pull(sync_state.last_version).await?;

    let master_password = prompt_password("Master password")?;
    let store = VaultStore::new(&config.vault_path);

    // UC-06: Validate integrity before writing
    store.unlock_bytes(&master_password, &bytes).context("failed to decrypt downloaded vault (integrity check failed)")?;

    tokio::fs::write(&config.vault_path, bytes)
        .await
        .context("failed to write local vault")?;

    sync_state.last_version = version;
    sync_state.save(&config.vault_path)?;

    println!("Vault pull completed (version {})", version);
    Ok(())
}
