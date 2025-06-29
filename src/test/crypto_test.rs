#[cfg(test)]
mod tests {
    use crate::{
        AppError,
        crypto::{generate_salt, hash_password, verify_password},
    };


    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        assert_ne!(salt1, salt2);

        assert!(!salt1.is_empty());
        assert!(salt1.len() > 10); 
    }

    #[test]
    fn test_hash_password_success() {
        let salt = generate_salt();
        let password = "test_password_123";

        let result = hash_password(password, &salt);
        assert!(result.is_ok());

        let hash = result.unwrap();
        assert!(!hash.is_empty());
        assert!(hash.starts_with("$argon2")); 
    }

    #[test]
    fn test_hash_password_invalid_salt() {
        let invalid_salt = "invalid_salt";
        let password = "test_password";

        let result = hash_password(password, invalid_salt);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidSaltFormat));
    }

    #[test]
    fn test_verify_password_correct() {
        let salt = generate_salt();
        let password = "correct_password";

        let hash = hash_password(password, &salt).unwrap();
        let result = verify_password(&hash, password);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_verify_password_incorrect() {
        let salt = generate_salt();
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let hash = hash_password(password, &salt).unwrap();
        let result = verify_password(&hash, wrong_password);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_verify_password_invalid_hash() {
        let invalid_hash = "not_a_valid_hash";
        let password = "any_password";

        let result = verify_password(invalid_hash, password);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::VerificationFailed));
    }

    #[test]
    fn test_password_hash_consistency() {
        let salt = generate_salt();
        let password = "same_password";

        let hash1 = hash_password(password, &salt).unwrap();
        let hash2 = hash_password(password, &salt).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_salts_different_hashes() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let password = "same_password";

        let hash1 = hash_password(password, &salt1).unwrap();
        let hash2 = hash_password(password, &salt2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_empty_password() {
        let salt = generate_salt();
        let empty_password = "";

        let result = hash_password(empty_password, &salt);
        assert!(result.is_ok());

        let hash = result.unwrap();
        let verify_result = verify_password(&hash, empty_password);
        assert!(verify_result.is_ok());
        assert_eq!(verify_result.unwrap(), true);
    }

    #[test]
    fn test_unicode_password() {
        let salt = generate_salt();
        let unicode_password = "пароль🔐密码";

        let hash = hash_password(unicode_password, &salt).unwrap();
        let verify_result = verify_password(&hash, unicode_password);

        assert!(verify_result.is_ok());
        assert_eq!(verify_result.unwrap(), true);
    }
}
