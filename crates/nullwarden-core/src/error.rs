use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("invalid vault format")]
    InvalidFormat,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("argon2 error: {0}")]
    Argon2(#[from] argon2::Error),
    #[error("password hash error: {0}")]
    PasswordHash(#[from] argon2::password_hash::Error),
    #[error("entry not found")]
    EntryNotFound,
    #[error("duplicate entry")]
    DuplicateEntry,
}
