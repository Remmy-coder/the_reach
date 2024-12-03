use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;

use clap::{Arg, Command};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct PasswordEntity {
    username: String,
    password: Vec<u8>,
    salt: Vec<u8>,
    nonce: Vec<u8>,
}

struct PasswordManager {
    storage_path: String,
    entries: HashMap<String, PasswordEntity>,
    master_key: Option<Vec<u8>>,
}

impl PasswordManager {
    fn new(storage_path: &str) -> Self {
        Self {
            storage_path: storage_path.to_string(),
            entries: HashMap::new(),
            master_key: None,
        }
    }

    fn set_master_key(&mut self, master_password: &str) -> io::Result<()> {
        if master_password.len() < 8 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Master password must be at least 8 characters long",
            ));
        }

        let salt = Self::generate_salt();
        self.master_key = Some(Self::derive_key(master_password, &salt));
        Ok(())
    }

    fn generate_salt() -> Vec<u8> {
        let mut salt = vec![0u8; 16];
        SystemRandom::new()
            .fill(&mut salt)
            .expect("Could not generate salt");
        salt
    }

    fn derive_key(password: &str, salt: &[u8]) -> Vec<u8> {
        let mut key = vec![0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(100_000).unwrap(),
            salt,
            password.as_bytes(),
            &mut key,
        );
        key
    }

    fn encrypt_password(&self, password: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), io::Error> {
        let master_key = self
            .master_key
            .as_ref()
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "Master key not set"))?;

        let mut nonce_bytes = vec![0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| io::Error::new(ErrorKind::Other, "Failed to generate nonce"))?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, master_key)
            .map_err(|_| io::Error::new(ErrorKind::Other, "Failed to create key"))?;
        let key = LessSafeKey::new(unbound_key);

        let aad = Aad::empty();
        let mut in_out = password.as_bytes().to_vec();

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| io::Error::new(ErrorKind::Other, "Invalid nonce"))?;

        key.seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|_| io::Error::new(ErrorKind::Other, "Encryption failed"))?;

        Ok((in_out, nonce_bytes, vec![]))
    }

    fn decrypt_password(&self, encrypted_password: &[u8], nonce: &[u8]) -> Option<String> {
        let master_key = self.master_key.clone()?;

        let unbound_key = match UnboundKey::new(&AES_256_GCM, &master_key) {
            Ok(key) => key,
            Err(_) => return None,
        };
        let key = LessSafeKey::new(unbound_key);

        let aad = Aad::empty();
        let nonce = match Nonce::try_assume_unique_for_key(nonce) {
            Ok(n) => n,
            Err(_) => return None,
        };

        let mut decrypted = encrypted_password.to_vec();

        match key.open_in_place(nonce, aad, &mut decrypted) {
            Ok(_) => String::from_utf8(decrypted).ok(),
            Err(_) => None,
        }
    }

    fn add_entry(&mut self, service: &str, username: &str, password: &str) -> io::Result<()> {
        let (encrypted_password, nonce, salt) = self.encrypt_password(password)?;

        let entry = PasswordEntity {
            username: username.to_string(),
            password: encrypted_password,
            nonce,
            salt,
        };

        self.entries.insert(service.to_lowercase(), entry);
        self.save_entries()
    }

    fn get_entry(&self, service: &str) -> Option<(String, String)> {
        let service_lower = service.to_lowercase();

        self.entries.get(&service_lower).and_then(|entry| {
            let decrypted_password = self.decrypt_password(&entry.password, &entry.nonce)?;
            Some((entry.username.clone(), decrypted_password))
        })
    }

    fn save_entries(&self) -> io::Result<()> {
        let json = serde_json::to_string(&self.entries)?;
        println!("Saving entries: {}", json);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.storage_path)?;

        file.write_all(json.as_bytes())?;
        Ok(())
    }

    fn load_entries(&mut self) -> io::Result<()> {
        if !Path::new(&self.storage_path).exists() {
            println!("No existing entries file found");
            return Ok(());
        }

        let mut file = File::open(&self.storage_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        println!("Loaded entries JSON: {}", contents);

        self.entries = serde_json::from_str(&contents)?;

        println!("Number of entries loaded: {}", self.entries.len());
        Ok(())
    }
}

fn main() -> io::Result<()> {
    let matches = Command::new("Password Manager")
        .version("1.0")
        .author("Remmy-Coder")
        .about("Secure CLI Password Manager")
        .subcommand(
            Command::new("add")
                .about("Add a new password")
                .arg(Arg::new("service").required(true))
                .arg(Arg::new("username").required(true))
                .arg(Arg::new("password").required(true)),
        )
        .subcommand(
            Command::new("get")
                .about("Retrieve a password")
                .arg(Arg::new("service").required(true)),
        )
        .get_matches();

    let storage_path = "passwords.json";

    let mut password_manager = PasswordManager::new(storage_path);

    print!("Enter master password: ");
    io::stdout().flush()?;
    let mut master_password = String::new();
    io::stdin().read_line(&mut master_password)?;
    let master_password = master_password.trim();

    match password_manager.set_master_key(master_password) {
        Ok(()) => {
            password_manager.load_entries()?;
        }
        Err(e) => {
            eprintln!("Error setting master password: {}", e);
            return Err(e);
        }
    }

    match matches.subcommand() {
        Some(("add", add_matches)) => {
            let service = add_matches.get_one::<String>("service").unwrap();
            let username = add_matches.get_one::<String>("username").unwrap();
            let password = add_matches.get_one::<String>("password").unwrap();

            match password_manager.add_entry(service, username, password) {
                Ok(()) => println!("Password added successfully!"),
                Err(e) => {
                    eprintln!("Failed to add password: {}", e);
                    return Err(e);
                }
            }
        }
        Some(("get", get_matches)) => {
            let service = get_matches.get_one::<String>("service").unwrap();

            match password_manager.get_entry(service) {
                Some((username, password)) => {
                    println!("Service: {}", service);
                    println!("Username: {}", username);
                    println!("Password: {}", password);
                }
                None => println!("No entry found for {}", service),
            }
        }
        _ => {}
    }
    Ok(())
}
