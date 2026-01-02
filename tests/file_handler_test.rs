// Tests for file handler module - encrypted file format

use crypto_cli_tool::file_handler::{EncryptedFileHeader, Algorithm, MAGIC_BYTES, CURRENT_VERSION};
use crypto_cli_tool::key_manager::KdfAlgorithm;
use crypto_cli_tool::compression::CompressionAlgorithm;
use std::io::Cursor;

#[test]
fn test_header_serialization_deserialization_basic() {
    // Create a basic header
    let iv = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let header = EncryptedFileHeader::new(Algorithm::Aes256Gcm, iv.clone(), 1024);
    
    // Serialize to bytes
    let mut buffer = Vec::new();
    header.write_to(&mut buffer).expect("Failed to serialize header");
    
    // Deserialize from bytes
    let mut cursor = Cursor::new(buffer);
    let deserialized = EncryptedFileHeader::read_from(&mut cursor)
        .expect("Failed to deserialize header");
    
    // Verify fields
    assert_eq!(deserialized.magic, MAGIC_BYTES);
    assert_eq!(deserialized.version, CURRENT_VERSION);
    assert_eq!(deserialized.algorithm, Algorithm::Aes256Gcm);
    assert_eq!(deserialized.iv, iv);
    assert_eq!(deserialized.original_size, 1024);
    assert_eq!(deserialized.compressed, false);
    assert_eq!(deserialized.kdf, None);
}

#[test]
fn test_header_with_kdf_parameters() {
    // Create a header with KDF parameters
    let iv = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let salt = vec![0u8; 32];
    let header = EncryptedFileHeader::new(Algorithm::ChaCha20Poly1305, iv.clone(), 2048)
        .with_kdf(KdfAlgorithm::Argon2id, 100000, salt.clone());
    
    // Serialize and deserialize
    let mut buffer = Vec::new();
    header.write_to(&mut buffer).expect("Failed to serialize header");
    
    let mut cursor = Cursor::new(buffer);
    let deserialized = EncryptedFileHeader::read_from(&mut cursor)
        .expect("Failed to deserialize header");
    
    // Verify KDF fields
    assert_eq!(deserialized.kdf, Some(KdfAlgorithm::Argon2id));
    assert_eq!(deserialized.kdf_iterations, Some(100000));
    assert_eq!(deserialized.salt, Some(salt));
}

#[test]
fn test_header_with_compression() {
    // Create a header with compression
    let iv = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let header = EncryptedFileHeader::new(Algorithm::Aes256Cbc, iv.clone(), 4096)
        .with_compression(CompressionAlgorithm::Zstd);
    
    // Serialize and deserialize
    let mut buffer = Vec::new();
    header.write_to(&mut buffer).expect("Failed to serialize header");
    
    let mut cursor = Cursor::new(buffer);
    let deserialized = EncryptedFileHeader::read_from(&mut cursor)
        .expect("Failed to deserialize header");
    
    // Verify compression flag
    assert_eq!(deserialized.compressed, true);
}

#[test]
fn test_header_with_metadata() {
    // Create a header with metadata
    let iv = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let metadata = b"{\"filename\":\"test.txt\"}".to_vec();
    let header = EncryptedFileHeader::new(Algorithm::Aes256Gcm, iv.clone(), 512)
        .with_metadata(metadata.clone());
    
    // Serialize and deserialize
    let mut buffer = Vec::new();
    header.write_to(&mut buffer).expect("Failed to serialize header");
    
    let mut cursor = Cursor::new(buffer);
    let deserialized = EncryptedFileHeader::read_from(&mut cursor)
        .expect("Failed to deserialize header");
    
    // Verify metadata
    assert_eq!(deserialized.metadata, metadata);
}

#[test]
fn test_header_checksum_verification() {
    // Create a header
    let iv = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let header = EncryptedFileHeader::new(Algorithm::Aes256Gcm, iv.clone(), 1024);
    
    // Serialize to bytes
    let mut buffer = Vec::new();
    header.write_to(&mut buffer).expect("Failed to serialize header");
    
    // Corrupt the checksum (last 32 bytes)
    let len = buffer.len();
    buffer[len - 1] ^= 0xFF;
    
    // Try to deserialize - should fail due to checksum mismatch
    let mut cursor = Cursor::new(buffer);
    let result = EncryptedFileHeader::read_from(&mut cursor);
    
    assert!(result.is_err());
}

#[test]
fn test_header_invalid_magic_bytes() {
    // Create invalid data with wrong magic bytes
    let mut buffer = vec![0u8; 100];
    buffer[0..8].copy_from_slice(b"WRONGMAG");
    
    // Try to deserialize - should fail
    let mut cursor = Cursor::new(buffer);
    let result = EncryptedFileHeader::read_from(&mut cursor);
    
    assert!(result.is_err());
}

#[test]
fn test_header_all_algorithms() {
    // Test all algorithm types
    let algorithms = vec![
        Algorithm::Aes256Gcm,
        Algorithm::Aes256Cbc,
        Algorithm::ChaCha20Poly1305,
        Algorithm::RsaOaep2048,
        Algorithm::RsaOaep4096,
        Algorithm::EciesP256,
    ];
    
    for algo in algorithms {
        let iv = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let header = EncryptedFileHeader::new(algo, iv.clone(), 1024);
        
        // Serialize and deserialize
        let mut buffer = Vec::new();
        header.write_to(&mut buffer).expect("Failed to serialize header");
        
        let mut cursor = Cursor::new(buffer);
        let deserialized = EncryptedFileHeader::read_from(&mut cursor)
            .expect("Failed to deserialize header");
        
        assert_eq!(deserialized.algorithm, algo);
    }
}

#[test]
fn test_file_encryption_decryption_workflow() {
    use crypto_cli_tool::file_handler::{encrypt_file, decrypt_file};
    use crypto_cli_tool::key_manager::SecureBytes;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;
    
    // Create a temporary directory for test files
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let input_path = temp_dir.path().join("plaintext.txt");
    let encrypted_path = temp_dir.path().join("encrypted.bin");
    let decrypted_path = temp_dir.path().join("decrypted.txt");
    
    // Create test plaintext file
    let plaintext = b"Hello, World! This is a test file for encryption and decryption.";
    fs::write(&input_path, plaintext).expect("Failed to write plaintext file");
    
    // Generate a test key
    let key = SecureBytes::from(&[0u8; 32][..]);
    
    // Encrypt the file
    encrypt_file(
        &input_path,
        &encrypted_path,
        &key,
        Algorithm::Aes256Gcm,
        None, // No compression
        None, // No KDF params
    ).expect("Failed to encrypt file");
    
    // Verify encrypted file exists and is different from plaintext
    assert!(encrypted_path.exists());
    let encrypted_data = fs::read(&encrypted_path).expect("Failed to read encrypted file");
    assert_ne!(&encrypted_data[..], plaintext);
    
    // Decrypt the file
    decrypt_file(
        &encrypted_path,
        &decrypted_path,
        &key,
    ).expect("Failed to decrypt file");
    
    // Verify decrypted file matches original
    let decrypted_data = fs::read(&decrypted_path).expect("Failed to read decrypted file");
    assert_eq!(&decrypted_data[..], plaintext);
}

#[test]
fn test_file_encryption_with_compression() {
    use crypto_cli_tool::file_handler::{encrypt_file, decrypt_file};
    use crypto_cli_tool::key_manager::SecureBytes;
    use std::fs;
    use tempfile::TempDir;
    
    // Create a temporary directory for test files
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let input_path = temp_dir.path().join("plaintext.txt");
    let encrypted_path = temp_dir.path().join("encrypted.bin");
    let decrypted_path = temp_dir.path().join("decrypted.txt");
    
    // Create test plaintext file with repetitive data (compresses well)
    let plaintext = b"AAAAAAAAAA".repeat(100);
    fs::write(&input_path, &plaintext).expect("Failed to write plaintext file");
    
    // Generate a test key
    let key = SecureBytes::from(&[0u8; 32][..]);
    
    // Encrypt the file with compression
    encrypt_file(
        &input_path,
        &encrypted_path,
        &key,
        Algorithm::ChaCha20Poly1305,
        Some(CompressionAlgorithm::Gzip),
        None,
    ).expect("Failed to encrypt file");
    
    // Decrypt the file
    decrypt_file(
        &encrypted_path,
        &decrypted_path,
        &key,
    ).expect("Failed to decrypt file");
    
    // Verify decrypted file matches original
    let decrypted_data = fs::read(&decrypted_path).expect("Failed to read decrypted file");
    assert_eq!(&decrypted_data[..], &plaintext[..]);
}

#[test]
fn test_file_decryption_wrong_key() {
    use crypto_cli_tool::file_handler::{encrypt_file, decrypt_file};
    use crypto_cli_tool::key_manager::SecureBytes;
    use std::fs;
    use tempfile::TempDir;
    
    // Create a temporary directory for test files
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let input_path = temp_dir.path().join("plaintext.txt");
    let encrypted_path = temp_dir.path().join("encrypted.bin");
    let decrypted_path = temp_dir.path().join("decrypted.txt");
    
    // Create test plaintext file
    let plaintext = b"Secret message";
    fs::write(&input_path, plaintext).expect("Failed to write plaintext file");
    
    // Generate a test key
    let key = SecureBytes::from(&[0u8; 32][..]);
    
    // Encrypt the file
    encrypt_file(
        &input_path,
        &encrypted_path,
        &key,
        Algorithm::Aes256Gcm,
        None,
        None,
    ).expect("Failed to encrypt file");
    
    // Try to decrypt with wrong key
    let wrong_key = SecureBytes::from(&[1u8; 32][..]);
    let result = decrypt_file(
        &encrypted_path,
        &decrypted_path,
        &wrong_key,
    );
    
    // Should fail due to authentication error
    assert!(result.is_err());
}
