use anyhow::Context;
use reqwest::Client;
use std::path::Path;
use tokio::time::{sleep, Duration};

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

    pub async fn push(
        &self,
        path: &Path,
        expected_version: u64,
        force: bool,
    ) -> anyhow::Result<u64> {
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
        if force {
            request = request.header("X-Force", "true");
        } else if expected_version > 0 {
            request = request.header("X-If-Match", expected_version.to_string());
        }

        let response = self
            .send_with_retry(request, "push")
            .await
            .context("push request failed")?;

        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(crate::error::CliError::SyncConflict.into());
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

    pub async fn pull(&self, current_version: u64) -> anyhow::Result<(u64, Vec<u8>)> {
        let mut request = self.http.get(format!("{}/vault", self.base_url));
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .try_clone()
            .context("failed to clone pull request")?;
        let response = self
            .send_with_retry(response, "pull")
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

        if version < current_version {
            anyhow::bail!(
                "rollback detected: server version ({}) is older than local version ({}).",
                version,
                current_version
            );
        }

        let bytes = response
            .bytes()
            .await
            .context("failed to read pull response body")?;

        Ok((version, bytes.to_vec()))
    }

    async fn send_with_retry(
        &self,
        request: reqwest::RequestBuilder,
        operation: &'static str,
    ) -> anyhow::Result<reqwest::Response> {
        for attempt in 0..3u32 {
            let cloned = request
                .try_clone()
                .context("failed to clone outbound request")?;

            match cloned.send().await {
                Ok(response) => return Ok(response),
                Err(err) if should_retry(&err) && attempt < 2 => {
                    sleep(Duration::from_millis(250 * (1 << attempt))).await;
                }
                Err(err) => {
                    return Err(map_network_error(err, &self.base_url, operation));
                }
            }
        }

        unreachable!("retry loop always returns or errors")
    }
}

fn should_retry(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_timeout() || err.is_request()
}

fn map_network_error(
    err: reqwest::Error,
    base_url: &str,
    operation: &'static str,
) -> anyhow::Error {
    if should_retry(&err) {
        return crate::error::CliError::ServerUnavailable {
            url: base_url.to_string(),
            operation,
            source: err,
        }
        .into();
    }

    anyhow::Error::new(err)
}
