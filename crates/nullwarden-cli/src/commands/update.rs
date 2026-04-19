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
    clear_notes: bool,
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

    // M-05: Handle clear_notes flag
    let notes_update = if clear_notes {
        Some(None)
    } else {
        notes.map(Some)
    };

    vault.update_entry(&title, username, password, notes_update)?;

    store.save(&master_password, &vault)?;
    println!("Updated entry `{title}`");
    Ok(())
}
