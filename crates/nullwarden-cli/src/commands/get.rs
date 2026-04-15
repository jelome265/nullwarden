use crate::{config::Config, input::prompt_password};
use anyhow::Context;
use nullwarden_core::vault::VaultStore;

pub async fn run(title: String) -> anyhow::Result<()> {
    let config = Config::load()?;
    let password = prompt_password("Master password")?;
    let store = VaultStore::new(&config.vault_path);
    let vault = store.unlock(&password).context("failed to unlock vault")?;
    let entry = vault
        .get_entry(&title)
        .with_context(|| format!("entry `{title}` not found"))?;
    println!("title: {}", entry.title);
    println!("username: {}", entry.username);
    println!("password: {}", entry.password);
    if let Some(notes) = &entry.notes {
        println!("notes: {notes}");
    }
    Ok(())
}
