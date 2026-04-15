use crate::{client::sync::SyncClient, config::Config, session::load_access_token};

pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;
    let token = load_access_token()?;
    let client = SyncClient::new(config.server_url, token);
    client.pull(&config.vault_path).await?;
    println!("Vault pull completed");
    Ok(())
}
