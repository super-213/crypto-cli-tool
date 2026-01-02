// Tests for streaming encryption/decryption

use crypto_cli_tool::crypto::*;
use crypto_cli_tool::key_manager::SecureBytes;
use std::io::Cursor;

#[test]
fn test_streaming_aes_gcm_round_trip() {
    // Create test data larger than one chunk (64KB)
    let plaintext = vec![0x42u8; 128 * 1024]; // 128KB
    let key = SecureBytes::from(&[0x01u8; 32][..]);
    
    // Encrypt
    let mut encrypted_data = Vec::new();
    let encrypt_result = encrypt_stream_aes_256_gcm(
        Cursor::new(&plaintext),
        &mut encrypted_data,
        &key,
    ).expect("Encryption should succeed");
    
    // Verify we got multiple chunks
    assert!(encrypt_result.total_chunks > 1, "Should have multiple chunks");
    
    // Decrypt
    let mut decrypted_data = Vec::new();
    decrypt_stream_aes_256_gcm(
        Cursor::new(&encrypted_data),
        &mut decrypted_data,
        &key,
        &encrypt_result.iv,
        encrypt_result.total_chunks,
    ).expect("Decryption should succeed");
    
    // Verify round trip
    assert_eq!(plaintext, decrypted_data, "Decrypted data should match original");
}

#[test]
fn test_streaming_chacha20_round_trip() {
    // Create test data larger than one chunk (64KB)
    let plaintext = vec![0x42u8; 128 * 1024]; // 128KB
    let key = SecureBytes::from(&[0x01u8; 32][..]);
    
    // Encrypt
    let mut encrypted_data = Vec::new();
    let encrypt_result = encrypt_stream_chacha20_poly1305(
        Cursor::new(&plaintext),
        &mut encrypted_data,
        &key,
    ).expect("Encryption should succeed");
    
    // Verify we got multiple chunks
    assert!(encrypt_result.total_chunks > 1, "Should have multiple chunks");
    
    // Decrypt
    let mut decrypted_data = Vec::new();
    decrypt_stream_chacha20_poly1305(
        Cursor::new(&encrypted_data),
        &mut decrypted_data,
        &key,
        &encrypt_result.iv,
        encrypt_result.total_chunks,
    ).expect("Decryption should succeed");
    
    // Verify round trip
    assert_eq!(plaintext, decrypted_data, "Decrypted data should match original");
}

#[test]
fn test_streaming_small_data() {
    // Test with data smaller than one chunk
    let plaintext = vec![0x42u8; 1024]; // 1KB
    let key = SecureBytes::from(&[0x01u8; 32][..]);
    
    // Encrypt
    let mut encrypted_data = Vec::new();
    let encrypt_result = encrypt_stream_aes_256_gcm(
        Cursor::new(&plaintext),
        &mut encrypted_data,
        &key,
    ).expect("Encryption should succeed");
    
    // Verify we got exactly one chunk
    assert_eq!(encrypt_result.total_chunks, 1, "Should have exactly one chunk");
    
    // Decrypt
    let mut decrypted_data = Vec::new();
    decrypt_stream_aes_256_gcm(
        Cursor::new(&encrypted_data),
        &mut decrypted_data,
        &key,
        &encrypt_result.iv,
        encrypt_result.total_chunks,
    ).expect("Decryption should succeed");
    
    // Verify round trip
    assert_eq!(plaintext, decrypted_data, "Decrypted data should match original");
}

#[test]
fn test_streaming_authentication_failure() {
    // Create test data
    let plaintext = vec![0x42u8; 128 * 1024];
    let key = SecureBytes::from(&[0x01u8; 32][..]);
    
    // Encrypt
    let mut encrypted_data = Vec::new();
    let encrypt_result = encrypt_stream_aes_256_gcm(
        Cursor::new(&plaintext),
        &mut encrypted_data,
        &key,
    ).expect("Encryption should succeed");
    
    // Tamper with encrypted data
    if !encrypted_data.is_empty() {
        let mid = encrypted_data.len() / 2;
        encrypted_data[mid] ^= 0xFF;
    }
    
    // Attempt to decrypt - should fail
    let mut decrypted_data = Vec::new();
    let result = decrypt_stream_aes_256_gcm(
        Cursor::new(&encrypted_data),
        &mut decrypted_data,
        &key,
        &encrypt_result.iv,
        encrypt_result.total_chunks,
    );
    
    assert!(result.is_err(), "Decryption should fail with tampered data");
}

#[test]
fn test_streaming_empty_data() {
    // Test with empty data
    let plaintext: Vec<u8> = vec![];
    let key = SecureBytes::from(&[0x01u8; 32][..]);
    
    // Encrypt
    let mut encrypted_data = Vec::new();
    let encrypt_result = encrypt_stream_aes_256_gcm(
        Cursor::new(&plaintext),
        &mut encrypted_data,
        &key,
    ).expect("Encryption should succeed");
    
    // Verify we got zero chunks
    assert_eq!(encrypt_result.total_chunks, 0, "Should have zero chunks for empty data");
    
    // Decrypt
    let mut decrypted_data = Vec::new();
    decrypt_stream_aes_256_gcm(
        Cursor::new(&encrypted_data),
        &mut decrypted_data,
        &key,
        &encrypt_result.iv,
        encrypt_result.total_chunks,
    ).expect("Decryption should succeed");
    
    // Verify round trip
    assert_eq!(plaintext, decrypted_data, "Decrypted data should match original (empty)");
}
