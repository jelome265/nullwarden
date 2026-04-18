use crate::{config::Config, input::prompt_password};
use anyhow::Context;
use nullwarden_core::vault::VaultStore;

pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;
    let password = prompt_password("Master password")?;
    let store = VaultStore::new(&config.vault_path);
    let vault = store.unlock(&password).context("failed to unlock vault")?;
    
    if vault.entries.is_empty() {
        println!("No entries in vault.");
        return Ok(());
    }
    
    println!("{:<40} {:<30}", "TITLE", "USERNAME");
    println!("{}", "-".repeat(70));
    for entry in &vault.entries {
        println!("{:<40} {:<30}", entry.title, entry.username);
    }
    println!("\nTotal entries: {}", vault.entries.len());
    Ok(())
}
