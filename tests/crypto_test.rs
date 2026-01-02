// Basic tests for crypto module

use crypto_cli_tool::crypto::*;
use crypto_cli_tool::key_manager::SecureBytes;

#[test]
fn test_aes_256_gcm_round_trip() {
    let plaintext = b"Hello, World! This is a test message.";
    let key = SecureBytes::from(vec![0u8; 32]);
    
    let enc_context = EncryptionContext {
        key: key.clone(),
        iv: None,
        aad: None,
    };
    
    let result = encrypt_aes_256_gcm(plaintext, &enc_context).unwrap();
    
    let dec_context = DecryptionContext {
        key: key.clone(),
        iv: result.iv.clone(),
        tag: result.tag.clone(),
        mac: None,
    };
    
    let decrypted = decrypt_aes_256_gcm(&result.ciphertext, &dec_context).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_chacha20_poly1305_round_trip() {
    let plaintext = b"Hello, World! This is a test message.";
    let key = SecureBytes::from(vec![1u8; 32]);
    
    let enc_context = EncryptionContext {
        key: key.clone(),
        iv: None,
        aad: None,
    };
    
    let result = encrypt_chacha20_poly1305(plaintext, &enc_context).unwrap();
    
    let dec_context = DecryptionContext {
        key: key.clone(),
        iv: result.iv.clone(),
        tag: result.tag.clone(),
        mac: None,
    };
    
    let decrypted = decrypt_chacha20_poly1305(&result.ciphertext, &dec_context).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_aes_256_cbc_hmac_round_trip() {
    let plaintext = b"Hello, World! This is a test message.";
    let key = SecureBytes::from(vec![2u8; 32]);
    
    let enc_context = EncryptionContext {
        key: key.clone(),
        iv: None,
        aad: None,
    };
    
    let result = encrypt_aes_256_cbc_hmac(plaintext, &enc_context).unwrap();
    
    let dec_context = DecryptionContext {
        key: key.clone(),
        iv: result.iv.clone(),
        tag: None,
        mac: result.mac.clone(),
    };
    
    let decrypted = decrypt_aes_256_cbc_hmac(&result.ciphertext, &dec_context).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_authentication_failure_aes_gcm() {
    let plaintext = b"Hello, World!";
    let key = SecureBytes::from(vec![3u8; 32]);
    
    let enc_context = EncryptionContext {
        key: key.clone(),
        iv: None,
        aad: None,
    };
    
    let mut result = encrypt_aes_256_gcm(plaintext, &enc_context).unwrap();
    
    // Tamper with ciphertext
    result.ciphertext[0] ^= 1;
    
    let dec_context = DecryptionContext {
        key: key.clone(),
        iv: result.iv.clone(),
        tag: result.tag.clone(),
        mac: None,
    };
    
    let decrypted = decrypt_aes_256_gcm(&result.ciphertext, &dec_context);
    
    assert!(decrypted.is_err());
}

#[test]
fn test_authentication_failure_cbc_hmac() {
    let plaintext = b"Hello, World!";
    let key = SecureBytes::from(vec![4u8; 32]);
    
    let enc_context = EncryptionContext {
        key: key.clone(),
        iv: None,
        aad: None,
    };
    
    let mut result = encrypt_aes_256_cbc_hmac(plaintext, &enc_context).unwrap();
    
    // Tamper with ciphertext
    result.ciphertext[0] ^= 1;
    
    let dec_context = DecryptionContext {
        key: key.clone(),
        iv: result.iv.clone(),
        tag: None,
        mac: result.mac.clone(),
    };
    
    let decrypted = decrypt_aes_256_cbc_hmac(&result.ciphertext, &dec_context);
    
    assert!(decrypted.is_err());
}


#[test]
fn test_rsa_oaep_2048_round_trip() {
    use crypto_cli_tool::key_manager::{generate_key_pair, AsymmetricAlgorithm};
    
    let plaintext = b"Hello, RSA-OAEP!";
    
    // Generate RSA-2048 key pair
    let key_pair = generate_key_pair(AsymmetricAlgorithm::RsaOaep2048).unwrap();
    
    // Encrypt with public key
    let ciphertext = encrypt_rsa_oaep(plaintext, &key_pair.public_key).unwrap();
    
    // Decrypt with private key
    let decrypted = decrypt_rsa_oaep(&ciphertext, key_pair.private_key.as_ref()).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_rsa_oaep_4096_round_trip() {
    use crypto_cli_tool::key_manager::{generate_key_pair, AsymmetricAlgorithm};
    
    let plaintext = b"Hello, RSA-OAEP-4096!";
    
    // Generate RSA-4096 key pair
    let key_pair = generate_key_pair(AsymmetricAlgorithm::RsaOaep4096).unwrap();
    
    // Encrypt with public key
    let ciphertext = encrypt_rsa_oaep(plaintext, &key_pair.public_key).unwrap();
    
    // Decrypt with private key
    let decrypted = decrypt_rsa_oaep(&ciphertext, key_pair.private_key.as_ref()).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_ecies_p256_round_trip() {
    use crypto_cli_tool::key_manager::{generate_key_pair, AsymmetricAlgorithm};
    
    let plaintext = b"Hello, ECIES-P256! This is a longer message to test ECIES encryption.";
    
    // Generate ECIES P-256 key pair
    let key_pair = generate_key_pair(AsymmetricAlgorithm::EciesP256).unwrap();
    
    // Encrypt with public key
    let ciphertext = encrypt_ecies_p256(plaintext, &key_pair.public_key).unwrap();
    
    // Decrypt with private key
    let decrypted = decrypt_ecies_p256(&ciphertext, key_pair.private_key.as_ref()).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_hybrid_encryption_rsa_2048() {
    use crypto_cli_tool::key_manager::{generate_key_pair, AsymmetricAlgorithm};
    
    let plaintext = b"Hello, Hybrid Encryption with RSA-2048! This is a much longer message that would be inefficient to encrypt directly with RSA.";
    
    // Generate RSA-2048 key pair
    let key_pair = generate_key_pair(AsymmetricAlgorithm::RsaOaep2048).unwrap();
    
    // Encrypt with hybrid encryption
    let result = encrypt_hybrid(
        plaintext,
        &key_pair.public_key,
        HybridAlgorithm::RsaOaep2048Aes256Gcm,
    ).unwrap();
    
    // Decrypt with hybrid decryption
    let decrypted = decrypt_hybrid(&result, key_pair.private_key.as_ref()).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_hybrid_encryption_rsa_4096() {
    use crypto_cli_tool::key_manager::{generate_key_pair, AsymmetricAlgorithm};
    
    let plaintext = b"Hello, Hybrid Encryption with RSA-4096!";
    
    // Generate RSA-4096 key pair
    let key_pair = generate_key_pair(AsymmetricAlgorithm::RsaOaep4096).unwrap();
    
    // Encrypt with hybrid encryption
    let result = encrypt_hybrid(
        plaintext,
        &key_pair.public_key,
        HybridAlgorithm::RsaOaep4096Aes256Gcm,
    ).unwrap();
    
    // Decrypt with hybrid decryption
    let decrypted = decrypt_hybrid(&result, key_pair.private_key.as_ref()).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_hybrid_encryption_ecies_p256() {
    use crypto_cli_tool::key_manager::{generate_key_pair, AsymmetricAlgorithm};
    
    let plaintext = b"Hello, Hybrid Encryption with ECIES-P256! This combines the efficiency of symmetric encryption with the key distribution benefits of elliptic curve cryptography.";
    
    // Generate ECIES P-256 key pair
    let key_pair = generate_key_pair(AsymmetricAlgorithm::EciesP256).unwrap();
    
    // Encrypt with hybrid encryption
    let result = encrypt_hybrid(
        plaintext,
        &key_pair.public_key,
        HybridAlgorithm::EciesP256Aes256Gcm,
    ).unwrap();
    
    // Decrypt with hybrid decryption
    let decrypted = decrypt_hybrid(&result, key_pair.private_key.as_ref()).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}
