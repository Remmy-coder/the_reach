# Password Manager - Backend Overview

A secure, encrypted password manager written in Rust that provides safe storage and management of credentials.

## Features

### Security
- **AES-256-GCM encryption** - Military-grade encryption for all stored data
- **Unique nonces** - Each encryption operation uses a cryptographically secure random nonce
- **Key-based access** - All data is encrypted with a user-provided key
- **No plaintext storage** - Passwords are never stored in plaintext

### Functionality
- **CRUD operations** - Create, read, update, and delete credentials
- **Search capabilities** - Find credentials by service name, username, or notes
- **Secure listing** - List credentials without exposing passwords
- **Import/Export** - Backup and restore vault data with merge options
- **Key rotation** - Change encryption keys while preserving data

## Architecture

The project follows a clean architecture pattern with clear separation of concerns:

### Core Components

#### `Vault` (Data Model)
```rust
pub struct Vault {
    pub credentials: Vec<Credentials>,
}

pub struct Credentials {
    pub id: String,
    pub service: String,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

#### `VaultManager` (Business Logic)
The main interface for vault operations:
- Handles encryption/decryption automatically
- Provides CRUD operations for credentials
- Manages vault persistence through storage backends
- Implements search and filtering functionality

#### `VaultStorage` Trait (Storage Abstraction)
```rust
pub trait VaultStorage {
    fn save_encrypted_vault(&self, data: &EncryptedData) -> AppResult<()>;
    fn load_encrypted_vault(&self) -> AppResult<EncryptedData>;
    fn vault_exists(&self) -> bool;
}
```

#### Crypto Module
- `encrypt_vault()` / `decrypt_vault()` - Main encryption functions
- `generate_key()` / `generate_nonce()` - Secure random generation
- Support for custom nonces when needed

## Storage Backends

### File Storage
Basic file-based storage implementation included:
```rust
let storage = FileStorage::new("vault.dat".into());
let vault_manager = VaultManager::new(storage, encryption_key);
```

### Extensible Design
The `VaultStorage` trait allows for easy implementation of additional backends:
- Database storage
- Cloud storage
- In-memory storage (for testing)

## API Overview

### Initialization
```rust
// Create and initialize a new vault
vault_manager.initialize_vault()?;
```

### Managing Credentials
```rust
// Add new credentials
let id = vault_manager.add_credentials(
    "GitHub".to_string(),
    "username".to_string(),
    "password".to_string(),
    Some("Personal account".to_string())
)?;

// Retrieve credentials
let creds = vault_manager.get_credentials(&id)?;

// Update credentials
vault_manager.update_credentials(
    &id,
    Some("GitLab".to_string()), // new service
    None,                       // keep username
    Some("new_password".to_string()),
    None                        // keep notes
)?;

// Delete credentials
vault_manager.delete_credentials(&id)?;
```

### Search and Discovery
```rust
// List all credentials (passwords not included)
let summaries = vault_manager.list_credentials()?;

// Search by service, username, or notes
let results = vault_manager.search_credentials("github")?;

// Get credentials by service name
let github_creds = vault_manager.get_credentials_by_service("GitHub")?;
```

### Backup and Restore
```rust
// Export vault for backup
let vault_backup = vault_manager.export_vault()?;

// Import vault (merge with existing or replace)
vault_manager.import_vault(imported_vault, merge: true)?;
```

### Key Management
```rust
// Rotate encryption key
vault_manager.change_key(new_key)?;
```

## Testing

The project includes comprehensive tests covering:

### Unit Tests
- **Vault initialization** - Creating new vaults and preventing duplicates
- **CRUD operations** - Adding, retrieving, updating, and deleting credentials
- **Search functionality** - Finding credentials by various criteria
- **Data persistence** - Ensuring encryption/decryption works correctly
- **Error handling** - Testing invalid operations and edge cases
- **Security** - Verifying wrong keys cannot decrypt data

### Mock Storage
Tests use an in-memory mock storage implementation for fast, reliable testing without file I/O dependencies.

### Test Coverage
- ✅ Vault manager operations
- ✅ Encryption/decryption through persistence
- ✅ Search and filtering
- ✅ Error conditions
- ✅ Security boundaries

## Dependencies

- `aes-gcm` - AES-GCM encryption
- `serde` - Serialization/deserialization
- `chrono` - Date and time handling
- `nanoid` - Unique identifier generation
- `rand_core` - Cryptographic random number generation

## Error Handling

The project uses a custom `AppResult<T>` type with comprehensive error variants:
- `AppError::Encryption` - Encryption/decryption failures
- `AppError::Decryption` - Decryption-specific errors
- `AppError::NotFound` - Missing credentials or vault
- `AppError::SerdeJson` - JSON serialization errors
- `AppError::Io` - File system operations

## Security Considerations

- **No key storage** - Encryption keys must be provided by the application
- **Secure random generation** - Uses OS entropy for nonces and keys
- **Memory safety** - Rust's ownership system prevents common security bugs
- **No password exposure** - List operations never return plaintext passwords
- **Authenticated encryption** - AES-GCM provides both confidentiality and integrity
