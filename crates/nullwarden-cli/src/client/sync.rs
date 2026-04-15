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

    pub async fn push(&self, path: &Path) -> anyhow::Result<()> {
        let bytes = tokio::fs::read(path).await.context("failed to read local vault")?;
        let mut request = self.http.put(format!("{}/vault", self.base_url)).body(bytes);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        request
            .send()
            .await
            .context("push request failed")?
            .error_for_status()
            .context("push response was not successful")?;
        Ok(())
    }

    pub async fn pull(&self, path: &Path) -> anyhow::Result<()> {
        let mut request = self.http.get(format!("{}/vault", self.base_url));
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let bytes = request
            .send()
            .await
            .context("pull request failed")?
            .error_for_status()
            .context("pull response was not successful")?
            .bytes()
            .await
            .context("failed to read pull response body")?;
        tokio::fs::write(path, bytes)
            .await
            .context("failed to write local vault")?;
        Ok(())
    }
}
