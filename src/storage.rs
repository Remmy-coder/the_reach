use std::path::PathBuf;

use crate::{AppError, AppResult, constant::NONCE_SIZE, model::EncryptedData};

pub struct FileStorage {
    file_path: PathBuf,
}

impl FileStorage {
    pub fn new(file_path: PathBuf) -> Self {
        Self { file_path }
    }
}

pub trait VaultStorage {
    fn save_encrypted_vault(&self, data: &EncryptedData) -> AppResult<()>;
    fn load_encrypted_vault(&self) -> AppResult<EncryptedData>;
    fn vault_exists(&self) -> bool;
}

impl VaultStorage for FileStorage {
    fn save_encrypted_vault(&self, data: &EncryptedData) -> AppResult<()> {
        use std::fs;

        let mut file_data = Vec::new();
        file_data.extend_from_slice(&data.nonce);
        file_data.extend_from_slice(&data.ciphertext);

        fs::write(&self.file_path, file_data).map_err(|e| AppError::Io(e))?;

        Ok(())
    }

    fn load_encrypted_vault(&self) -> AppResult<EncryptedData> {
        use std::fs;

        let file_data = fs::read(&self.file_path).map_err(|e| AppError::Io(e))?;

        if file_data.len() < NONCE_SIZE {
            return Err(AppError::Decryption(
                "Invalid vault file format".to_string(),
            ));
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&file_data[..NONCE_SIZE]);
        let ciphertext = file_data[NONCE_SIZE..].to_vec();

        Ok(EncryptedData { ciphertext, nonce })
    }

    fn vault_exists(&self) -> bool {
        self.file_path.exists()
    }
}
