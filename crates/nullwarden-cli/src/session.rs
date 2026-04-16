use anyhow::Context;
use keyring::Entry;

pub fn save_access_token(token: &str) -> anyhow::Result<()> {
    let entry =
        Entry::new("nullwarden", "access_token").context("failed to create keyring entry")?;
    entry
        .set_password(token)
        .context("failed to save access token to keyring")?;
    Ok(())
}

pub fn load_access_token() -> anyhow::Result<String> {
    let entry =
        Entry::new("nullwarden", "access_token").context("failed to create keyring entry")?;
    entry
        .get_password()
        .context("no active session. please login or register.")
}

pub fn clear_access_token() -> anyhow::Result<()> {
    let entry =
        Entry::new("nullwarden", "access_token").context("failed to create keyring entry")?;
    let _ = entry.delete_password();
    Ok(())
}
