use crate::{
    client::auth::AuthClient,
    config::{warn_if_default_server_url, Config},
    input::{prompt_password, validate_password_strength},
};

pub async fn run(username: String, password: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    warn_if_default_server_url(&config, "register");
    let password = match password {
        Some(value) => {
            eprintln!("Warning: providing passwords as command-line arguments can leak them via shell history or process inspection.");
            value
        }
        None => prompt_password("Account password")?,
    };
    validate_password_strength(&password)?;
    AuthClient::new(config.server_url)
        .register(username, password)
        .await?;
    println!("Registration request completed");
    Ok(())
}
