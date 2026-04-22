use crate::config::Config;
use crate::input::prompt_password;
use anyhow::Context;
use nullwarden_core::vault::VaultStore;
use nullwarden_core::kdf::KdfParams;

pub async fn run(
    m_cost: Option<u32>,
    t_cost: Option<u32>,
    p_cost: Option<u32>,
) -> anyhow::Result<()> {
    let config = Config::load()?;
    let password = prompt_password("Master password")?;
    
    let store = VaultStore::new(&config.vault_path);
    let data = store.unlock(&password).context("failed to unlock vault")?;

    let mut new_params = KdfParams::default();
    if let Some(m) = m_cost { new_params.m_cost = m; }
    if let Some(t) = t_cost { new_params.t_cost = t; }
    if let Some(p) = p_cost { new_params.p_cost = p; }

    println!("Migrating vault to new KDF parameters: m={}, t={}, p={}", 
        new_params.m_cost, new_params.t_cost, new_params.p_cost);

    let new_store = VaultStore::with_params(&config.vault_path, new_params);
    new_store.save(&password, &data).context("failed to save migrated vault")?;

    println!("Vault migration successful.");
    Ok(())
}
