use crate::{config::Config, input::prompt_password};
use anyhow::Context;
use nullwarden_core::vault::VaultStore;

pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;
    let password = prompt_password("Master password")?;
    let store = VaultStore::new(&config.vault_path);
    let vault = store.unlock(&password).context("failed to unlock vault")?;
    for entry in &vault.entries {
        println!("{}", entry.title);
    }
    Ok(())
}
