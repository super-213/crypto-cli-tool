// Basic tests for key management module

use crypto_cli_tool::key_manager::*;

#[test]
fn test_pbkdf2_key_derivation() {
    let password = SecureString::from("test_password");
    let salt = [1u8; 32];
    let iterations = 100_000;
    let key_length = 32;
    
    let result = derive_key_pbkdf2(&password, &salt, iterations, key_length);
    assert!(result.is_ok());
    
    let key = result.unwrap();
    assert_eq!(key.len(), key_length);
}

#[test]
fn test_pbkdf2_determinism() {
    let password = SecureString::from("test_password");
    let salt = [1u8; 32];
    let iterations = 100_000;
    let key_length = 32;
    
    let key1 = derive_key_pbkdf2(&password, &salt, iterations, key_length).unwrap();
    let key2 = derive_key_pbkdf2(&password, &salt, iterations, key_length).unwrap();
    
    assert_eq!(key1.as_slice(), key2.as_slice());
}

#[test]
fn test_argon2id_key_derivation() {
    let password = SecureString::from("test_password");
    let salt = [1u8; 32];
    let memory_cost = 19456; // 19 MiB
    let time_cost = 2;
    let key_length = 32;
    
    let result = derive_key_argon2id(&password, &salt, memory_cost, time_cost, key_length);
    assert!(result.is_ok());
    
    let key = result.unwrap();
    assert_eq!(key.len(), key_length);
}

#[test]
fn test_argon2id_determinism() {
    let password = SecureString::from("test_password");
    let salt = [1u8; 32];
    let memory_cost = 19456;
    let time_cost = 2;
    let key_length = 32;
    
    let key1 = derive_key_argon2id(&password, &salt, memory_cost, time_cost, key_length).unwrap();
    let key2 = derive_key_argon2id(&password, &salt, memory_cost, time_cost, key_length).unwrap();
    
    assert_eq!(key1.as_slice(), key2.as_slice());
}

#[test]
fn test_salt_generation() {
    let salt1 = generate_salt().unwrap();
    let salt2 = generate_salt().unwrap();
    
    // Salts should be different
    assert_ne!(salt1, salt2);
    
    // Salts should be 32 bytes
    assert_eq!(salt1.len(), 32);
    assert_eq!(salt2.len(), 32);
}

#[test]
fn test_symmetric_key_generation() {
    let key = generate_symmetric_key(Algorithm::Aes256Gcm).unwrap();
    assert_eq!(key.len(), 32);
    
    let key2 = generate_symmetric_key(Algorithm::ChaCha20Poly1305).unwrap();
    assert_eq!(key2.len(), 32);
    
    // Keys should be different
    assert_ne!(key.as_slice(), key2.as_slice());
}

#[test]
fn test_rsa_key_pair_generation() {
    let key_pair = generate_key_pair(AsymmetricAlgorithm::RsaOaep2048).unwrap();
    
    // Keys should not be empty
    assert!(!key_pair.public_key.is_empty());
    assert!(!key_pair.private_key.is_empty());
}

#[test]
fn test_ecies_key_pair_generation() {
    let key_pair = generate_key_pair(AsymmetricAlgorithm::EciesP256).unwrap();
    
    // Keys should not be empty
    assert!(!key_pair.public_key.is_empty());
    assert!(!key_pair.private_key.is_empty());
}
