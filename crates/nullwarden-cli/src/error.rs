use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("configuration error")]
    Config,
    #[error("sync conflict: remote vault has been updated")]
    SyncConflict,
}
