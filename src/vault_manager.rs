use chrono::Utc;
use nanoid::nanoid;

use crate::{
    AppError, AppResult,
    constant::KEY_SIZE,
    model::{Credentials, CredentialsSummary, Vault},
    storage::VaultStorage,
    vault::{decrypt_vault, encrypt_vault},
};

pub struct VaultManager<S: VaultStorage> {
    storage: S,
    key: [u8; KEY_SIZE],
}

impl<S: VaultStorage> VaultManager<S> {
    pub fn new(storage: S, key: [u8; KEY_SIZE]) -> Self {
        Self { storage, key }
    }

    pub fn initialize_vault(&self) -> AppResult<()> {
        if self.storage.vault_exists() {
            return Err(AppError::VaultExists);
        }

        let empty_vault = Vault {
            credentials: Vec::new(),
        };

        let encrypted_data = encrypt_vault(&empty_vault, &self.key)?;
        self.storage.save_encrypted_vault(&encrypted_data)?;

        Ok(())
    }

    pub fn load_vault(&self) -> AppResult<Vault> {
        let encrypted_data = self.storage.load_encrypted_vault()?;
        decrypt_vault(&encrypted_data, &self.key)
    }

    fn save_vault(&self, vault: &Vault) -> AppResult<()> {
        let encrypted_data = encrypt_vault(vault, &self.key)?;
        self.storage.save_encrypted_vault(&encrypted_data)
    }

    pub fn add_credentials(
        &self,
        service: String,
        username: String,
        password: String,
        notes: Option<String>,
    ) -> AppResult<String> {
        let mut vault = self.load_vault()?;

        let id = nanoid!(10);
        let now = Utc::now();

        let credentials = Credentials {
            id: id.clone(),
            service,
            username,
            password,
            notes,
            created_at: now,
            updated_at: now,
        };

        vault.credentials.push(credentials);
        self.save_vault(&vault)?;

        Ok(id)
    }

    pub fn get_credentials(&self, id: &str) -> AppResult<Credentials> {
        let vault = self.load_vault()?;
        vault
            .credentials
            .into_iter()
            .find(|cred| cred.id == id)
            .ok_or_else(|| AppError::NotFound(format!("Credentials with ID {} not found", id)))
    }

    pub fn get_credentials_by_service(&self, service: &str) -> AppResult<Vec<Credentials>> {
        let vault = self.load_vault()?;
        let matching_creds: Vec<Credentials> = vault
            .credentials
            .into_iter()
            .filter(|cred| {
                cred.service
                    .to_lowercase()
                    .contains(&service.to_lowercase())
            })
            .collect();

        if matching_creds.is_empty() {
            Err(AppError::NotFound(format!(
                "No credentials found for service: {}",
                service
            )))
        } else {
            Ok(matching_creds)
        }
    }

    pub fn list_credentials(&self) -> AppResult<Vec<CredentialsSummary>> {
        let vault = self.load_vault()?;
        let summaries = vault
            .credentials
            .into_iter()
            .map(|cred| CredentialsSummary {
                id: cred.id,
                service: cred.service,
                username: cred.username,
                has_notes: cred.notes.is_some(),
                created_at: cred.created_at,
                updated_at: cred.updated_at,
            })
            .collect();

        Ok(summaries)
    }

    pub fn update_credentials(
        &self,
        id: &str,
        service: Option<String>,
        username: Option<String>,
        password: Option<String>,
        notes: Option<Option<String>>,
    ) -> AppResult<()> {
        let mut vault = self.load_vault()?;

        let credential = vault
            .credentials
            .iter_mut()
            .find(|cred| cred.id == id)
            .ok_or_else(|| AppError::NotFound(format!("Credentials with ID {} not found", id)))?;

        let now = Utc::now();

        if let Some(service) = service {
            credential.service = service;
        }
        if let Some(username) = username {
            credential.username = username;
        }
        if let Some(password) = password {
            credential.password = password;
        }
        if let Some(notes) = notes {
            credential.notes = notes;
        }
        credential.updated_at = now;

        self.save_vault(&vault)?;
        Ok(())
    }

    pub fn delete_credentials(&self, id: &str) -> AppResult<()> {
        let mut vault = self.load_vault()?;

        let initial_len = vault.credentials.len();
        vault.credentials.retain(|cred| cred.id != id);

        if vault.credentials.len() == initial_len {
            return Err(AppError::NotFound(format!(
                "Credentials with ID {} not found",
                id
            )));
        }

        self.save_vault(&vault)?;
        Ok(())
    }

    pub fn search_credentials(&self, query: &str) -> AppResult<Vec<Credentials>> {
        let vault = self.load_vault()?;
        let query_lower = query.to_lowercase();

        let results: Vec<Credentials> = vault
            .credentials
            .into_iter()
            .filter(|cred| {
                cred.service.to_lowercase().contains(&query_lower)
                    || cred.username.to_lowercase().contains(&query_lower)
                    || cred
                        .notes
                        .as_ref()
                        .map_or(false, |n| n.to_lowercase().contains(&query_lower))
            })
            .collect();

        Ok(results)
    }

    pub fn change_key(&mut self, new_key: [u8; 32]) -> AppResult<()> {
        let vault = self.load_vault()?;

        self.key = new_key;

        self.save_vault(&vault)?;

        Ok(())
    }

    pub fn export_vault(&self) -> AppResult<Vault> {
        self.load_vault()
    }

    pub fn import_vault(&self, imported_vault: Vault, merge: bool) -> AppResult<()> {
        if merge {
            let mut existing_vault = self.load_vault().unwrap_or_else(|_| Vault {
                credentials: Vec::new(),
            });

            for imported_cred in imported_vault.credentials {
                let exists = existing_vault.credentials.iter().any(|existing| {
                    existing.service == imported_cred.service
                        && existing.username == imported_cred.username
                });

                if !exists {
                    existing_vault.credentials.push(imported_cred);
                }
            }

            self.save_vault(&existing_vault)?;
        } else {
            self.save_vault(&imported_vault)?;
        }

        Ok(())
    }
}
