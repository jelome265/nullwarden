use crate::session::{clear_access_token, clear_refresh_token};

pub async fn run() -> anyhow::Result<()> {
    // L-03: Actively clear session tokens from the keyring
    clear_access_token()?;
    clear_refresh_token()?;

    println!("NullWarden CLI session locked.");
    println!("Session tokens have been cleared from the keyring.");
    println!("Master password material is never persisted in memory between commands.");
    Ok(())
}
