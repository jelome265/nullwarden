use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("configuration error")]
    Config,
}
