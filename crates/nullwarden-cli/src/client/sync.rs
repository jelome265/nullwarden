use anyhow::Context;
use reqwest::Client;
use std::path::Path;

#[derive(Clone)]
pub struct SyncClient {
    http: Client,
    base_url: String,
    token: Option<String>,
}

impl SyncClient {
    pub fn new(base_url: String, token: Option<String>) -> Self {
        Self {
            http: Client::new(),
            base_url,
            token,
        }
    }

    pub async fn push(&self, path: &Path, expected_version: u64) -> anyhow::Result<u64> {
        let bytes = tokio::fs::read(path)
            .await
            .context("failed to read local vault")?;
        let mut request = self
            .http
            .put(format!("{}/vault", self.base_url))
            .body(bytes);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if expected_version > 0 {
            request = request.header("X-If-Match", expected_version.to_string());
        }

        let response = request.send().await.context("push request failed")?;

        if response.status() == reqwest::StatusCode::CONFLICT {
            anyhow::bail!("conflict detected: remote vault has been updated. please pull first.");
        }

        let body = response
            .error_for_status()
            .context("push response was not successful")?
            .text()
            .await
            .context("failed to read push response body")?;

        // Response format is "version=N"
        let new_version = body
            .split('=')
            .nth(1)
            .and_then(|v| v.parse::<u64>().ok())
            .context("failed to parse new version from server")?;

        Ok(new_version)
    }

    pub async fn pull(&self, path: &Path) -> anyhow::Result<u64> {
        let mut request = self.http.get(format!("{}/vault", self.base_url));
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .context("pull request failed")?
            .error_for_status()
            .context("pull response was not successful")?;

        let version = response
            .headers()
            .get("X-Vault-Version")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .context("server did not return vault version")?;

        let bytes = response
            .bytes()
            .await
            .context("failed to read pull response body")?;

        tokio::fs::write(path, bytes)
            .await
            .context("failed to write local vault")?;

        Ok(version)
    }
}
