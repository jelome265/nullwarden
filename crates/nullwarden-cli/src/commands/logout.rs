use crate::{
    client::auth::AuthClient,
    config::Config,
    session::{clear_access_token, clear_refresh_token, load_access_token, load_refresh_token},
};

pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;

    // We try to logout on the server if tokens exist
    let access_token = load_access_token().ok();
    let refresh_token = load_refresh_token().ok();

    if let (Some(at), Some(rt)) = (access_token, refresh_token) {
        let client = AuthClient::new(config.server_url);
        if let Err(e) = client.logout(&at, &rt).await {
            eprintln!("Warning: server-side logout failed: {e}");
        }
    }

    // Always clear local tokens
    clear_access_token()?;
    clear_refresh_token()?;

    println!("Logged out successfully");
    Ok(())
}
