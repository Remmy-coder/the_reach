use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::constant::NONCE_SIZE;

#[derive(Serialize, Deserialize, Clone)]
pub struct Credentials {
    pub id: String,
    pub service: String,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CredentialsSummary {
    pub id: String,
    pub service: String,
    pub username: String,
    pub has_notes: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub credentials: Vec<Credentials>,
}

#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_SIZE],
}
