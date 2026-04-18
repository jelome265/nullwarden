use crate::{
    config::Config,
    input::{prompt_password, validate_password_strength},
};
use anyhow::Context;
use nullwarden_core::vault::VaultStore;

pub async fn run(
    title: String,
    username: Option<String>,
    password: Option<String>,
    notes: Option<String>,
) -> anyhow::Result<()> {
    let config = Config::load()?;
    let master_password = prompt_password("Master password")?;
    
    let store = VaultStore::new(&config.vault_path);
    let mut vault = store
        .unlock(&master_password)
        .context("failed to unlock vault")?;

    if let Some(ref p) = password {
        validate_password_strength(p)?;
    }

    // Note: We use Option<Option<String>> for notes to allow clearing them if we wanted, 
    // but for now we just pass through the Some(notes) or None (no change).
    // If the user provided a notes string, we update it.
    vault.update_entry(&title, username, password, notes.map(Some))?;
    
    store.save(&master_password, &vault)?;
    println!("Updated entry `{title}`");
    Ok(())
}
