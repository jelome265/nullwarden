use crate::session::save_access_token;
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
            .context("register request failed")?
            .error_for_status()
            .context("register response was not successful")?;

        let login = self
            .http
            .post(format!("{}/auth/login", self.base_url))
            .json(&AuthRequest { username, password })
            .send()
            .await
            .context("login request failed")?
            .error_for_status()
            .context("login response was not successful")?
            .json::<AuthResponse>()
            .await
            .context("failed to parse login response")?;
        let _ = login.refresh_token;
        save_access_token(&login.access_token)?;
        Ok(())
    }
}
