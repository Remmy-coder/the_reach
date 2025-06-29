use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON (de)serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Invalid salt format")]
    InvalidSaltFormat,

    #[error("Password hashing failed: {0}")]
    HashingFailed(argon2::password_hash::Error),

    #[error("Password verification failed")]
    VerificationFailed,

    #[error("Vault already exists")]
    VaultExists,

    #[error("Vault is not loaded")]
    VaultNotLoaded,

    #[error("Not found error: {0}")]
    NotFound(String),

    #[error("Invalid application state: {0}")]
    StateError(String),

    #[error("Failed to load or save vault file: {0}")]
    VaultFileError(String),

    #[error("Unknown error: {0}")]
    Other(String),
}

pub type AppResult<T> = Result<T, AppError>;
