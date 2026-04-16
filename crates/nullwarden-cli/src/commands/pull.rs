use crate::{
    client::sync::SyncClient, config::Config, session::load_access_token, sync_state::SyncState,
};

pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;
    let token = load_access_token()?;
    let mut sync_state = SyncState::load(&config.vault_path)?;

    let client = SyncClient::new(config.server_url, Some(token));
    let version = client.pull(&config.vault_path).await?;

    sync_state.last_version = version;
    sync_state.save(&config.vault_path)?;

    println!("Vault pull completed (version {})", version);
    Ok(())
}
