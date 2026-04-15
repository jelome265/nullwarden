use crate::{config::Config, input::prompt_password};
use anyhow::Context;
use nullwarden_core::vault::VaultStore;

pub async fn run(title: String) -> anyhow::Result<()> {
    let config = Config::load()?;
    let password = prompt_password("Master password")?;
    let store = VaultStore::new(&config.vault_path);
    let mut vault = store.unlock(&password).context("failed to unlock vault")?;
    vault.delete_entry(&title)?;
    store.save(&password, &vault)?;
    println!("Deleted entry `{title}`");
    Ok(())
}
