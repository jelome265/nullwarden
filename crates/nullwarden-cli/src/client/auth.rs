use crate::session::{save_access_token, save_refresh_token};
use anyhow::Context;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct AuthClient {
    http: Client,
    base_url: String,
}

#[derive(Serialize)]
struct AuthRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct AuthResponse {
    access_token: String,
    refresh_token: String,
}

impl AuthClient {
    pub fn new(base_url: String) -> Self {
        Self {
            http: Client::new(),
            base_url,
        }
    }

    pub async fn register(&self, username: String, password: String) -> anyhow::Result<()> {
        self.http
            .post(format!("{}/auth/register", self.base_url))
            .json(&AuthRequest {
                username: username.clone(),
                password: password.clone(),
            })
            .send()
            .await
            .map_err(|err| map_network_error(err, &self.base_url, "register"))?
            .error_for_status()
            .context("register response was not successful")?;

        let login = self
            .http
            .post(format!("{}/auth/login", self.base_url))
            .json(&AuthRequest { username, password })
            .send()
            .await
            .map_err(|err| map_network_error(err, &self.base_url, "login"))?
            .error_for_status()
            .context("login response was not successful")?
            .json::<AuthResponse>()
            .await
            .context("failed to parse login response")?;

        save_access_token(&login.access_token)?;
        save_refresh_token(&login.refresh_token)?;
        Ok(())
    }

    pub async fn logout(&self, access_token: &str, refresh_token: &str) -> anyhow::Result<()> {
        self.http
            .post(format!("{}/auth/logout", self.base_url))
            .bearer_auth(access_token)
            .json(&serde_json::json!({ "refresh_token": refresh_token }))
            .send()
            .await
            .map_err(|err| map_network_error(err, &self.base_url, "logout"))?
            .error_for_status()
            .context("logout response was not successful")?;
        Ok(())
    }
}

fn map_network_error(
    err: reqwest::Error,
    base_url: &str,
    operation: &'static str,
) -> anyhow::Error {
    if err.is_connect() || err.is_timeout() || err.is_request() {
        return crate::error::CliError::ServerUnavailable {
            url: base_url.to_string(),
            operation,
            source: err,
        }
        .into();
    }

    anyhow::Error::new(err)
}
