#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::constant::KEY_SIZE;
    use crate::model::EncryptedData;
    use crate::storage::VaultStorage;
    use crate::vault_manager::VaultManager;
    use crate::{AppError, AppResult};

    #[derive(Clone)]
    struct MockStorage {
        data: Arc<Mutex<Option<EncryptedData>>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                data: Arc::new(Mutex::new(None)),
            }
        }
    }

    impl VaultStorage for MockStorage {
        fn save_encrypted_vault(&self, data: &EncryptedData) -> AppResult<()> {
            let mut storage = self.data.lock().unwrap();
            *storage = Some(EncryptedData {
                ciphertext: data.ciphertext.clone(),
                nonce: data.nonce,
            });
            Ok(())
        }

        fn load_encrypted_vault(&self) -> AppResult<EncryptedData> {
            let storage = self.data.lock().unwrap();
            storage
                .clone()
                .ok_or(AppError::NotFound("No vault data found".to_string()))
        }

        fn vault_exists(&self) -> bool {
            self.data.lock().unwrap().is_some()
        }
    }

    fn create_test_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7);
        }
        key
    }

    #[test]
    fn test_vault_initialization() {
        let storage = MockStorage::new();
        let key = create_test_key();
        let vault_manager = VaultManager::new(storage.clone(), key);

        assert!(!storage.vault_exists());

        vault_manager.initialize_vault().unwrap();
        assert!(storage.vault_exists());

        assert!(vault_manager.initialize_vault().is_err());
    }

    #[test]
    fn test_add_and_get_credentials() {
        let storage = MockStorage::new();
        let key = create_test_key();
        let vault_manager = VaultManager::new(storage, key);

        vault_manager.initialize_vault().unwrap();

        let id = vault_manager
            .add_credentials(
                "GitHub".to_string(),
                "testuser".to_string(),
                "testpass".to_string(),
                Some("Test account".to_string()),
            )
            .unwrap();

        let creds = vault_manager.get_credentials(&id).unwrap();
        assert_eq!(creds.service, "GitHub");
        assert_eq!(creds.username, "testuser");
        assert_eq!(creds.password, "testpass");
        assert_eq!(creds.notes, Some("Test account".to_string()));
    }

    #[test]
    fn test_get_nonexistent_credentials() {
        let storage = MockStorage::new();
        let key = create_test_key();
        let vault_manager = VaultManager::new(storage, key);

        vault_manager.initialize_vault().unwrap();

        let result = vault_manager.get_credentials("nonexistent-id");
        assert!(result.is_err());
    }

    #[test]
    fn test_update_credentials() {
        let storage = MockStorage::new();
        let key = create_test_key();
        let vault_manager = VaultManager::new(storage, key);

        vault_manager.initialize_vault().unwrap();

        let id = vault_manager
            .add_credentials(
                "GitHub".to_string(),
                "olduser".to_string(),
                "oldpass".to_string(),
                None,
            )
            .unwrap();

        vault_manager
            .update_credentials(
                &id,
                Some("GitLab".to_string()),
                Some("newuser".to_string()),
                Some("newpass".to_string()),
                Some(Some("Updated account".to_string())),
            )
            .unwrap();

        let creds = vault_manager.get_credentials(&id).unwrap();
        assert_eq!(creds.service, "GitLab");
        assert_eq!(creds.username, "newuser");
        assert_eq!(creds.password, "newpass");
        assert_eq!(creds.notes, Some("Updated account".to_string()));
    }

    #[test]
    fn test_delete_credentials() {
        let storage = MockStorage::new();
        let key = create_test_key();
        let vault_manager = VaultManager::new(storage, key);

        vault_manager.initialize_vault().unwrap();

        let id = vault_manager
            .add_credentials(
                "GitHub".to_string(),
                "testuser".to_string(),
                "testpass".to_string(),
                None,
            )
            .unwrap();

        assert!(vault_manager.get_credentials(&id).is_ok());

        vault_manager.delete_credentials(&id).unwrap();

        assert!(vault_manager.get_credentials(&id).is_err());
    }

    #[test]
    fn test_list_credentials() {
        let storage = MockStorage::new();
        let key = create_test_key();
        let vault_manager = VaultManager::new(storage, key);

        vault_manager.initialize_vault().unwrap();

        vault_manager
            .add_credentials(
                "GitHub".to_string(),
                "user1".to_string(),
                "pass1".to_string(),
                Some("Notes 1".to_string()),
            )
            .unwrap();

        vault_manager
            .add_credentials(
                "GitLab".to_string(),
                "user2".to_string(),
                "pass2".to_string(),
                None,
            )
            .unwrap();

        let summaries = vault_manager.list_credentials().unwrap();
        assert_eq!(summaries.len(), 2);

        let github_summary = summaries.iter().find(|s| s.service == "GitHub").unwrap();
        assert_eq!(github_summary.username, "user1");
        assert!(github_summary.has_notes);

        let gitlab_summary = summaries.iter().find(|s| s.service == "GitLab").unwrap();
        assert_eq!(gitlab_summary.username, "user2");
        assert!(!gitlab_summary.has_notes);
    }

    #[test]
    fn test_search_credentials() {
        let storage = MockStorage::new();
        let key = create_test_key();
        let vault_manager = VaultManager::new(storage, key);

        vault_manager.initialize_vault().unwrap();

        vault_manager
            .add_credentials(
                "GitHub".to_string(),
                "developer".to_string(),
                "pass1".to_string(),
                Some("Work account".to_string()),
            )
            .unwrap();

        vault_manager
            .add_credentials(
                "GitLab".to_string(),
                "user".to_string(),
                "pass2".to_string(),
                Some("Personal account".to_string()),
            )
            .unwrap();

        vault_manager
            .add_credentials(
                "Bitbucket".to_string(),
                "developer".to_string(),
                "pass3".to_string(),
                None,
            )
            .unwrap();

        let results = vault_manager.search_credentials("git").unwrap();
        assert_eq!(results.len(), 2);

        let results = vault_manager.search_credentials("developer").unwrap();
        assert_eq!(results.len(), 2);

        let results = vault_manager.search_credentials("work").unwrap();
        assert_eq!(results.len(), 1);
    }

    //#[test]
    //fn test_vault_encryption_decryption() {
    //    let  vault = Vault {
    //        credentials: vec![Credentials {
    //            id: "test-id".to_string(),
    //            service: "Test Service".to_string(),
    //            username: "testuser".to_string(),
    //            password: "testpass".to_string(),
    //            notes: Some("Test notes".to_string()),
    //            created_at: Utc::now(),
    //            updated_at: Utc::now(),
    //        }],
    //    };
    //
    //    let key = create_test_key();
    //
    //    // Encrypt vault
    //    let encrypted = encrypt_vault(&vault, &key).unwrap();
    //    assert!(!encrypted.ciphertext.is_empty());
    //
    //    // Decrypt vault
    //    let decrypted = decrypt_vault(&encrypted, &key).unwrap();
    //    assert_eq!(decrypted.credentials.len(), 1);
    //    assert_eq!(decrypted.credentials[0].service, "Test Service");
    //    assert_eq!(decrypted.credentials[0].username, "testuser");
    //    assert_eq!(decrypted.credentials[0].password, "testpass");
    //}
    //
    //#[test]
    //fn test_wrong_key_decryption() {
    //    let vault = Vault {
    //        credentials: vec![],
    //    };
    //
    //    let key1 = create_test_key();
    //    let mut key2 = create_test_key();
    //    key2[0] = key2[0].wrapping_add(1); // Make it different
    //
    //    // Encrypt with key1
    //    let encrypted = encrypt_vault(&vault, &key1).unwrap();
    //
    //    // Try to decrypt with key2
    //    let result = decrypt_vault(&encrypted, &key2);
    //    assert!(result.is_err());
    //}
}
