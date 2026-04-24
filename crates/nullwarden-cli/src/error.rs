use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CliError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Authentication failed: {0}")]
    Auth(String),
    #[error("Vault error: {0}")]
    Vault(#[from] nullwarden_core::VaultError),
    #[error("Sync conflict: remote vault has been updated by another device")]
    SyncConflict,
    #[error("Cannot reach NullWarden server at {url} during `{operation}`. Check your configured `server_url`, network path, TLS settings, and whether the server is reachable. {source}")]
    ServerUnavailable {
        url: String,
        operation: &'static str,
        source: reqwest::Error,
    },
    #[error("Input error: {0}")]
    Input(String),
    #[error("Keyring error: {0}")]
    Keyring(#[from] keyring::Error),
}
