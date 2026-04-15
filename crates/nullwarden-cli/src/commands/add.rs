use crate::{config::Config, input::{prompt_password, validate_password_strength}};
use anyhow::Context;
use nullwarden_core::vault::VaultStore;

pub async fn run(
    title: String,
    username: String,
    password: Option<String>,
    notes: Option<String>,
) -> anyhow::Result<()> {
    let config = Config::load()?;
    let master_password = prompt_password("Master password")?;
    let entry_password = match password {
        Some(value) => value,
        None => prompt_password("Entry password")?,
    };
    validate_password_strength(&entry_password)?;
    let store = VaultStore::new(&config.vault_path);
    let mut vault = store.unlock(&master_password).context("failed to unlock vault")?;
    vault.add_entry(title.clone(), username, entry_password, notes)?;
    store.save(&master_password, &vault)?;
    println!("Added entry `{title}`");
    Ok(())
}
