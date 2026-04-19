use crate::{
    client::sync::SyncClient,
    config::Config,
    error::CliError,
    input::{prompt_choice, prompt_password},
    session::load_access_token,
    sync_state::SyncState,
};
use anyhow::Context;
use nullwarden_core::vault::VaultStore;

pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;
    let token = load_access_token()?;
    let mut sync_state = SyncState::load(&config.vault_path)?;

    let client = SyncClient::new(config.server_url.clone(), Some(token));

    let res = client
        .push(&config.vault_path, sync_state.last_version, false)
        .await;

    match res {
        Ok(new_version) => {
            sync_state.last_version = new_version;
            sync_state.save(&config.vault_path)?;
            println!("Vault push completed (version {})", new_version);
        }
        Err(e)
            if e.downcast_ref::<CliError>()
                .is_some_and(|ce| matches!(ce, CliError::SyncConflict)) =>
        {
            println!("Conflict detected: remote vault has been updated by another device.");
            let choice = prompt_choice(
                "How would you like to proceed?",
                &["local", "remote", "abort"],
            )?;

            match choice {
                0 => {
                    // Overwrite server (force push)
                    println!("WARNING: Force pushing will overwrite the remote vault. This is destructive.");
                    let confirm = prompt_choice("Are you absolutely sure?", &["yes", "no"])?;
                    if confirm != 0 {
                        println!("Sync aborted.");
                        return Ok(());
                    }

                    println!("Force pushing local vault...");
                    let new_version = client.push(&config.vault_path, 0, true).await?;
                    sync_state.last_version = new_version;
                    sync_state.save(&config.vault_path)?;
                    println!("Vault push completed (version {})", new_version);
                }
                1 => {
                    // Keep remote (pull)
                    println!("Pulling remote vault...");
                    let (version, bytes) = client.pull(sync_state.last_version).await?;
                    let master_password = prompt_password("Master password")?;
                    let store = VaultStore::new(&config.vault_path);
                    store
                        .unlock_bytes(&master_password, &bytes)
                        .context("failed to decrypt downloaded vault (integrity check failed)")?;

                    tokio::fs::write(&config.vault_path, bytes)
                        .await
                        .context("failed to write local vault")?;
                    sync_state.last_version = version;
                    sync_state.save(&config.vault_path)?;
                    println!("Vault pull completed (version {})", version);
                }
                _ => {
                    println!("Sync aborted.");
                }
            }
        }
        Err(e) => return Err(e),
    }

    Ok(())
}
