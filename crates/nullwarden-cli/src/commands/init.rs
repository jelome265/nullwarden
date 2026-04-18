use crate::{
    config::Config,
    input::{prompt_password, validate_password_strength},
};
use anyhow::{bail, Context};
use nullwarden_core::vault::VaultStore;

pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;

    if config.vault_path.exists() {
        bail!(
            "A vault already exists at {}. Refusing to overwrite.",
            config.vault_path.display()
        );
    }

    let password = prompt_password("Master password")?;
    validate_password_strength(&password)?;

    let confirm = prompt_password("Confirm master password")?;
    if password != confirm {
        bail!("Passwords do not match");
    }

    let store = VaultStore::new(&config.vault_path);
    store
        .init(&password)
        .context("failed to initialize vault")?;
    println!("Vault initialized at {}", config.vault_path.display());
    Ok(())
}
