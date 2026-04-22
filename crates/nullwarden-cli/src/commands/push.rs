use crate::{
    client::sync::SyncClient,
    config::{warn_if_default_server_url, Config},
    error::CliError,
    input::{prompt_choice, prompt_password},
    session::load_access_token,
    sync_state::SyncState,
};
use anyhow::Context;
use nullwarden_core::vault::VaultStore;

pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;
    warn_if_default_server_url(&config, "push");
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
            if let Ok((local_count, remote_count, remote_version, remote_bytes)) =
                load_conflict_context(&client, &config.vault_path, sync_state.last_version).await
            {
                let delta = remote_count as i64 - local_count as i64;
                println!(
                    "Local entries: {local_count}, remote entries: {remote_count}, remote version: {remote_version}, delta: {delta:+}"
                );

                let choice = prompt_choice(
                    "How would you like to proceed?",
                    &["local", "remote", "abort"],
                )?;

                match choice {
                    0 => {
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
                        apply_remote_bytes(&config.vault_path, remote_version, remote_bytes)
                            .await?;
                        sync_state.last_version = remote_version;
                        sync_state.save(&config.vault_path)?;
                        println!("Vault pull completed (version {})", remote_version);
                    }
                    _ => println!("Sync aborted."),
                }

                return Ok(());
            }

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
                    apply_remote_bytes(&config.vault_path, version, bytes).await?;
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

async fn load_conflict_context(
    client: &SyncClient,
    vault_path: &std::path::Path,
    current_version: u64,
) -> anyhow::Result<(usize, usize, u64, Vec<u8>)> {
    let master_password = prompt_password("Master password (for conflict review)")?;
    let store = VaultStore::new(vault_path);
    let local_vault = store
        .unlock(&master_password)
        .context("failed to unlock local vault")?;
    let (remote_version, remote_bytes) = client.pull(current_version).await?;
    let remote_vault = store
        .unlock_bytes(&master_password, &remote_bytes)
        .context("failed to decrypt downloaded vault (integrity check failed)")?;

    Ok((
        local_vault.entries.len(),
        remote_vault.entries.len(),
        remote_version,
        remote_bytes,
    ))
}

async fn apply_remote_bytes(
    vault_path: &std::path::Path,
    version: u64,
    bytes: Vec<u8>,
) -> anyhow::Result<()> {
    let master_password = prompt_password("Master password")?;
    let store = VaultStore::new(vault_path);
    store
        .unlock_bytes(&master_password, &bytes)
        .context("failed to decrypt downloaded vault (integrity check failed)")?;

    tokio::fs::write(vault_path, &bytes)
        .await
        .context("failed to write local vault")?;

    println!("Downloaded and validated remote vault version {}", version);
    Ok(())
}
