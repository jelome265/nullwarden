use crate::{client::auth::AuthClient, config::Config, input::prompt_password};

pub async fn run(username: String, password: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let password = match password {
        Some(value) => value,
        None => prompt_password("Account password")?,
    };
    AuthClient::new(config.server_url)
        .register(username, password)
        .await?;
    println!("Registration request completed");
    Ok(())
}
