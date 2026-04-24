use crate::{
    client::auth::AuthClient,
    config::{warn_if_default_server_url, Config},
    session::{clear_access_token, clear_refresh_token, load_access_token, load_refresh_token},
};

pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;
    warn_if_default_server_url(&config, "lock");

    let access_token = load_access_token().ok();
    let refresh_token = load_refresh_token().ok();

    if let (Some(at), Some(rt)) = (access_token, refresh_token) {
        let client = AuthClient::new(config.server_url);
        if let Err(e) = client.logout(&at, &rt).await {
            eprintln!("Warning: server-side logout failed during lock: {e}");
        }
    }

    clear_access_token()?;
    clear_refresh_token()?;

    println!("NullWarden CLI session locked.");
    println!("Session tokens have been cleared locally and revocation was attempted server-side.");
    println!("Master password material is never persisted in memory between commands.");
    Ok(())
}
