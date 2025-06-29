use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng},
};
use rand_core::RngCore;

use crate::{
    constant::{KEY_SIZE, NONCE_SIZE}, model::{EncryptedData, Vault}, AppError, AppResult
};


pub fn generate_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt_vault(vault: &Vault, key: &[u8]) -> AppResult<EncryptedData> {
    if key.len() != KEY_SIZE {
        return Err(AppError::Encryption("Invalid key size".to_string()));
    }

    let json = serde_json::to_vec(vault).map_err(|e| AppError::SerdeJson(e))?;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Encryption(format!("Invalid key: {}", e)))?;

    let nonce = generate_nonce();
    let nonce_ref = Nonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce_ref, json.as_ref())
        .map_err(|e| AppError::Encryption(format!("Encryption failed: {}", e)))?;

    Ok(EncryptedData { ciphertext, nonce })
}

pub fn decrypt_vault(encrypted_data: &EncryptedData, key: &[u8]) -> AppResult<Vault> {
    if key.len() != KEY_SIZE {
        return Err(AppError::Decryption("Invalid key size".to_string()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Decryption(format!("Invalid key: {}", e)))?;

    let nonce_ref = Nonce::from_slice(&encrypted_data.nonce);

    let plaintext = cipher
        .decrypt(nonce_ref, encrypted_data.ciphertext.as_ref())
        .map_err(|e| AppError::Decryption(format!("Decryption failed: {}", e)))?;

    let vault = serde_json::from_slice(&plaintext).map_err(|e| AppError::SerdeJson(e))?;

    Ok(vault)
}

pub fn encrypt_vault_with_nonce(vault: &Vault, key: &[u8], nonce: &[u8]) -> AppResult<Vec<u8>> {
    if key.len() != KEY_SIZE {
        return Err(AppError::Encryption("Invalid key size".to_string()));
    }

    if nonce.len() != NONCE_SIZE {
        return Err(AppError::Encryption("Invalid nonce size".to_string()));
    }

    let json = serde_json::to_vec(vault).map_err(|e| AppError::SerdeJson(e))?;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Encryption(format!("Invalid key: {}", e)))?;

    let nonce_ref = Nonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce_ref, json.as_ref())
        .map_err(|e| AppError::Encryption(format!("Encryption failed: {}", e)))?;

    Ok(ciphertext)
}

pub fn decrypt_vault_with_nonce(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> AppResult<Vault> {
    if key.len() != KEY_SIZE {
        return Err(AppError::Decryption("Invalid key size".to_string()));
    }
    if nonce.len() != NONCE_SIZE {
        return Err(AppError::Decryption("Invalid nonce size".to_string()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Decryption(format!("Invalid key: {}", e)))?;

    let nonce_ref = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce_ref, ciphertext)
        .map_err(|e| AppError::Decryption(format!("Decryption failed: {}", e)))?;

    let vault = serde_json::from_slice(&plaintext).map_err(|e| AppError::SerdeJson(e))?;
    Ok(vault)
}
