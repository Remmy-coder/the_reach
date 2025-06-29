use argon2::{
    Argon2, PasswordHash,
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
};
use rand_core::OsRng;

use crate::{AppError, AppResult};

pub fn generate_salt() -> String {
    let salt = SaltString::generate(&mut OsRng);
    salt.as_str().to_string()
}

pub fn hash_password(password: &str, base64_salt: &str) -> AppResult<String> {
    let salt = SaltString::from_b64(base64_salt).map_err(|_| AppError::InvalidSaltFormat)?;

    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::HashingFailed(e))?
        .to_string();

    Ok(hash)
}

pub fn verify_password(hash: &str, password: &str) -> AppResult<bool> {
    let parsed_hash = PasswordHash::new(hash).map_err(|_| AppError::VerificationFailed)?;

    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
