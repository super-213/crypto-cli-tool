# Implementation Plan: Cryptographic CLI Tool

## Overview

This implementation plan breaks down the cryptographic CLI tool into discrete, incremental tasks. Each task builds on previous work, with property-based tests integrated throughout to catch errors early. The implementation follows a bottom-up approach: core cryptographic primitives first, then file handling, then CLI integration.

## Tasks

- [x] 1. Project setup and core infrastructure
  - Initialize Rust project with Cargo
  - Add dependencies: ring, RustCrypto crates (aes-gcm, chacha20poly1305), clap, tokio, proptest, flate2, zstd
  - Create module structure: cli, crypto, key_manager, file_handler, compression, app
  - Set up error types and Result aliases
  - Configure proptest with 100 iterations minimum
  - _Requirements: All_

- [x] 2. Implement secure memory types
  - [x] 2.1 Create SecureBytes type with zero-on-drop
    - Implement Drop trait to zero memory
    - Implement Deref and DerefMut for convenient access
    - Add constructor and conversion methods
    - _Requirements: 11.2_

  - [x] 2.2 Create SecureString type with zero-on-drop
    - Implement Drop trait to zero memory
    - Implement Deref for string access
    - Add constructor and conversion methods
    - _Requirements: 11.2_

  - [ ]* 2.3 Write property test for secure memory zeroing
    - **Property: Memory is zeroed after SecureBytes/SecureString is dropped**
    - **Validates: Requirements 11.2**

- [x] 3. Implement key management module
  - [x] 3.1 Implement PBKDF2-SHA256 key derivation
    - Use ring's pbkdf2 implementation
    - Accept password, salt, iterations, output length
    - Return SecureBytes containing derived key
    - _Requirements: 3.1_

  - [x] 3.2 Implement Argon2id key derivation
    - Use argon2 crate
    - Accept password, salt, memory cost, time cost
    - Return SecureBytes containing derived key
    - _Requirements: 3.2_

  - [ ]* 3.3 Write property test for key derivation determinism
    - **Property 4: Key Derivation Determinism**
    - **Validates: Requirements 3.1, 3.2, 3.5**

  - [x] 3.4 Implement cryptographically secure salt generation
    - Use ring's SystemRandom
    - Generate 32-byte salts
    - _Requirements: 3.3_

  - [ ]* 3.5 Write property test for salt uniqueness
    - **Property 5: Salt Uniqueness**
    - **Validates: Requirements 3.3**

  - [x] 3.6 Implement symmetric key generation
    - Generate keys of appropriate length for algorithm
    - Use SystemRandom for cryptographic security
    - _Requirements: 3.4, 14.2_

  - [x] 3.7 Implement asymmetric key pair generation
    - Support RSA-2048, RSA-4096, ECIES-P256
    - Return KeyPair with public and private keys
    - _Requirements: 14.3_


- [x] 4. Implement encryption engine core
  - [x] 4.1 Implement AES-256-GCM encryption and decryption
    - Use aes-gcm crate
    - Generate random 12-byte nonces
    - Return ciphertext with authentication tag
    - _Requirements: 1.1, 1.4, 1.5_

  - [x] 4.2 Implement ChaCha20-Poly1305 encryption and decryption
    - Use chacha20poly1305 crate
    - Generate random 12-byte nonces
    - Return ciphertext with authentication tag
    - _Requirements: 1.3, 1.4, 1.5_

  - [x] 4.3 Implement AES-256-CBC with HMAC-SHA256
    - Use aes crate for CBC mode
    - Generate random 16-byte IVs
    - Compute HMAC-SHA256 over ciphertext
    - _Requirements: 1.2, 1.4, 16.2_

  - [ ]* 4.4 Write property test for encryption-decryption round trip
    - **Property 1: Encryption-Decryption Round Trip**
    - **Validates: Requirements 1.1, 1.2, 1.3, 5.1, 5.4**

  - [ ]* 4.5 Write property test for IV uniqueness
    - **Property 3: IV Uniqueness**
    - **Validates: Requirements 1.4**

  - [ ]* 4.6 Write property test for authentication tag verification
    - **Property 2: Authentication Tag Verification**
    - **Validates: Requirements 1.5, 5.2, 5.3, 16.3, 16.4**

  - [ ]* 4.7 Write property test for tamper detection
    - **Property 14: Tamper Detection**
    - **Validates: Requirements 5.3, 11.5, 16.4**

- [x] 5. Implement asymmetric encryption
  - [x] 5.1 Implement RSA-OAEP encryption and decryption
    - Use rsa crate with OAEP padding
    - Support 2048-bit and 4096-bit keys
    - _Requirements: 2.1, 2.2_

  - [x] 5.2 Implement ECIES-P256 encryption and decryption
    - Use ecies crate
    - Support P-256 curve
    - _Requirements: 2.3_

  - [x] 5.3 Implement hybrid encryption
    - Generate random symmetric key
    - Encrypt data with symmetric algorithm
    - Encrypt symmetric key with public key
    - Package both in result structure
    - _Requirements: 2.4, 2.5_

  - [ ]* 5.4 Write property test for hybrid encryption correctness
    - **Property 11: Hybrid Encryption Correctness**
    - **Validates: Requirements 2.4, 2.5**

- [x] 6. Implement streaming encryption
  - [x] 6.1 Create streaming encryption for large files
    - Process files in 64KB chunks
    - Maintain constant memory usage
    - Use AEAD for each chunk with chunk counter as AAD
    - _Requirements: 12.1, 12.2_

  - [x] 6.2 Create streaming decryption for large files
    - Process files in 64KB chunks
    - Verify authentication for each chunk
    - _Requirements: 12.1, 12.2_

  - [ ]* 6.3 Write property test for streaming consistency
    - **Property 10: Streaming Consistency**
    - **Validates: Requirements 12.1, 12.2**

- [x] 7. Checkpoint - Ensure all cryptographic tests pass
  - Ensure all tests pass, ask the user if questions arise.


- [x] 8. Implement compression engine
  - [x] 8.1 Implement gzip compression and decompression
    - Use flate2 crate
    - Support compression levels 1-9
    - _Requirements: 15.2, 15.3_

  - [x] 8.2 Implement zstd compression and decompression
    - Use zstd crate
    - Support compression levels 1-22
    - _Requirements: 15.2, 15.3_

  - [ ]* 8.3 Write property test for compression round trip
    - **Property 9: Compression Round Trip**
    - **Validates: Requirements 15.2, 15.4**

- [x] 9. Implement encrypted file format
  - [x] 9.1 Define EncryptedFileHeader structure
    - Include all fields: magic, version, algorithm, KDF params, IV, etc.
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

  - [x] 9.2 Implement header serialization
    - Write header to binary format
    - Include SHA-256 checksum of header
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

  - [x] 9.3 Implement header deserialization
    - Read and parse header from binary
    - Verify header checksum
    - Validate version and algorithm IDs
    - _Requirements: 10.5_

  - [ ]* 9.4 Write property test for encrypted file format validity
    - **Property 7: Encrypted File Format Validity**
    - **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5**

  - [ ]* 9.5 Write unit tests for header edge cases
    - Test invalid magic bytes
    - Test unsupported versions
    - Test corrupted checksums
    - _Requirements: 10.5, 11.5_

- [x] 10. Implement file handler module
  - [x] 10.1 Implement file encryption workflow
    - Read plaintext file
    - Optionally compress
    - Encrypt with chosen algorithm
    - Write encrypted file with header
    - _Requirements: 4.1, 4.3_

  - [x] 10.2 Implement file decryption workflow
    - Read and parse encrypted file header
    - Verify authentication tag
    - Decrypt ciphertext
    - Optionally decompress
    - Write plaintext file
    - _Requirements: 5.1, 5.4_

  - [ ]* 10.3 Write property test for file encryption preserves original
    - **Property 6: File Encryption Preserves Original**
    - **Validates: Requirements 4.2, 4.5**

  - [ ]* 10.4 Write unit tests for file operation errors
    - Test file not found
    - Test permission denied
    - Test disk full scenarios
    - _Requirements: 4.5, 11.3_

- [x] 11. Implement directory archive format
  - [x] 11.1 Define directory archive structure
    - Create archive header with entry count
    - Define entry header with path, size, permissions, mtime
    - _Requirements: 6.2, 7.2_

  - [x] 11.2 Implement directory archiving
    - Traverse directory recursively
    - Collect all files with metadata
    - Serialize to archive format
    - _Requirements: 6.1, 6.2_

  - [x] 11.3 Implement directory extraction
    - Parse archive format
    - Create directory structure
    - Extract files with original metadata
    - _Requirements: 7.1, 7.2_

  - [ ]* 11.4 Write property test for directory structure preservation
    - **Property 8: Directory Structure Preservation**
    - **Validates: Requirements 6.2, 7.2**


- [-] 12. Implement directory encryption and decryption
  - [ ] 12.1 Implement directory encryption workflow
    - Traverse directory and collect files
    - Create archive from files
    - Optionally compress archive
    - Encrypt archive
    - Write encrypted archive file
    - _Requirements: 6.1, 6.2, 6.3_

  - [ ] 12.2 Implement directory decryption workflow
    - Read and decrypt encrypted archive
    - Optionally decompress
    - Extract archive to directory
    - Restore file metadata
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

  - [ ] 12.3 Add support for file pattern exclusion
    - Accept regex patterns for files to exclude
    - Filter files during directory traversal
    - _Requirements: 6.4_

  - [ ]* 12.4 Write unit tests for directory operations
    - Test nested directories
    - Test symbolic links handling
    - Test file exclusion patterns
    - Test partial failure scenarios
    - _Requirements: 6.5, 7.5_

- [x] 13. Checkpoint - Ensure all file and directory tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 14. Implement CLI layer
  - [x] 14.1 Define command-line argument structure with clap
    - Define main command with subcommands: encrypt, decrypt, keygen, list-algorithms, info
    - Define arguments for each subcommand
    - Add help text and examples
    - _Requirements: 8.1, 8.2, 8.3_

  - [x] 14.2 Implement password prompting
    - Use rpassword crate for secure password input
    - Hide password from terminal display
    - Support password confirmation for encryption
    - _Requirements: 9.1, 9.5_

  - [ ]* 14.3 Write property test for password input security
    - **Property 12: Password Input Security**
    - **Validates: Requirements 9.5**

  - [x] 14.4 Implement password input from environment variable
    - Read password from specified env var
    - Clear env var after reading (if possible)
    - _Requirements: 9.2_

  - [x] 14.5 Implement key file loading
    - Read raw key bytes from file
    - Support PEM format for asymmetric keys
    - _Requirements: 9.3, 9.4_

  - [x] 14.6 Implement progress indicators
    - Show progress bar for large file operations
    - Display current file during directory operations
    - Support verbose mode for detailed logging
    - _Requirements: 8.4, 12.3_

  - [ ]* 14.7 Write unit tests for CLI argument parsing
    - Test valid argument combinations
    - Test invalid arguments
    - Test missing required arguments
    - _Requirements: 8.2, 8.3_

- [-] 15. Implement application orchestrator
  - [x] 15.1 Create Config structure with defaults
    - Set default algorithm to AES-256-GCM
    - Set default KDF to Argon2id with 100,000 iterations
    - Set buffer size to 64KB
    - _Requirements: All_

  - [x] 15.2 Implement encrypt command handler
    - Parse arguments
    - Obtain key from specified source
    - Determine if input is file or directory
    - Call appropriate encryption function
    - Display results and errors
    - _Requirements: 4.1, 6.1_

  - [x] 15.3 Implement decrypt command handler
    - Parse arguments
    - Obtain key from specified source
    - Read encrypted file header to determine type
    - Call appropriate decryption function
    - Display results and errors
    - _Requirements: 5.1, 7.1_

  - [x] 15.4 Implement keygen command handler
    - Generate keys based on algorithm
    - Write keys to specified output files
    - Support PEM format export
    - _Requirements: 14.1, 14.3, 14.4, 14.5_

  - [x] 15.5 Implement list-algorithms command handler
    - Display all supported algorithms
    - Show key sizes and security levels
    - Indicate AEAD support
    - Provide recommendations
    - _Requirements: 13.1, 13.2, 13.3, 13.4_

  - [x] 15.6 Implement info command handler
    - Read encrypted file header
    - Display algorithm, KDF, compression info
    - Do not decrypt the file
    - _Requirements: 13.5_

  - [ ]* 15.7 Write property test for algorithm information accuracy
    - **Property 15: Algorithm Information Accuracy**
    - **Validates: Requirements 13.5**


- [x] 16. Implement error handling and security
  - [x] 16.1 Implement comprehensive error types
    - Define CryptoError enum with all error variants
    - Implement Display and Error traits
    - Add context to errors (file paths, operation types)
    - _Requirements: 11.1, 11.3_

  - [x] 16.2 Implement error message sanitization
    - Ensure no key material in error messages
    - Ensure no passwords in error messages
    - Ensure no plaintext in error messages
    - _Requirements: 11.1_

  - [ ]* 16.3 Write property test for error message safety
    - **Property 13: Error Message Safety**
    - **Validates: Requirements 11.1**

  - [x] 16.4 Implement input validation
    - Validate file paths
    - Validate algorithm selections
    - Validate key sizes
    - Validate iteration counts
    - _Requirements: 11.4_

  - [x] 16.5 Implement atomic file operations
    - Write to temporary file first
    - Rename to final destination on success
    - Clean up temporary files on error
    - _Requirements: 4.5, 11.3_

  - [ ]* 16.6 Write unit tests for error conditions
    - Test wrong password
    - Test corrupted ciphertext
    - Test invalid file format
    - Test permission errors
    - _Requirements: 11.3, 11.5_

- [ ] 17. Integration and main entry point
  - [x] 17.1 Implement main function
    - Parse command-line arguments
    - Route to appropriate command handler
    - Handle top-level errors
    - Set exit codes appropriately
    - _Requirements: 8.1_

  - [x] 17.2 Wire all components together
    - Connect CLI layer to application layer
    - Connect application layer to crypto, file, and key modules
    - Ensure proper error propagation
    - _Requirements: All_

  - [ ]* 17.3 Write integration tests for complete workflows
    - Test encrypt then decrypt file
    - Test encrypt then decrypt directory
    - Test key generation and usage
    - Test algorithm listing
    - Test file info query
    - _Requirements: All_

- [x] 18. Final checkpoint - Ensure all tests pass
  - Run full test suite including all property tests
  - Verify all 15 correctness properties pass
  - Ensure all unit tests pass
  - Ensure all integration tests pass
  - Ask the user if questions arise.

- [ ]* 19. Documentation and examples
  - Write README with installation instructions
  - Add usage examples for each command
  - Document supported algorithms and their properties
  - Add security considerations section
  - Create man page

- [ ]* 20. Performance optimization
  - Profile encryption/decryption performance
  - Optimize buffer sizes for macOS
  - Implement parallel directory processing with tokio
  - Benchmark against target performance requirements

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at key milestones
- Property tests validate universal correctness properties
- Unit tests validate specific examples and edge cases
- The implementation follows a bottom-up approach: crypto primitives → file handling → CLI
- All cryptographic operations use well-vetted libraries (ring, RustCrypto)
- Security is prioritized throughout: secure memory, authentication, error handling
