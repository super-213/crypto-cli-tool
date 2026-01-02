# Requirements Document

## Introduction

This document specifies the requirements for a professional-grade cryptographic CLI tool for macOS Terminal. The tool provides multiple encryption algorithms for encrypting and decrypting both individual files and entire directories, designed from the perspective of an advanced cryptography engineer.

## Glossary

- **CLI_Tool**: The command-line interface application for cryptographic operations
- **Encryption_Engine**: The core component that performs cryptographic operations
- **Key_Manager**: The component responsible for key generation, storage, and retrieval
- **File_Handler**: The component that manages file and directory operations
- **Algorithm**: A specific cryptographic cipher (e.g., AES-256, ChaCha20, RSA)
- **Plaintext**: Unencrypted data
- **Ciphertext**: Encrypted data
- **Key**: The secret value used for encryption and decryption
- **IV**: Initialization Vector used in certain encryption modes
- **Salt**: Random data used in key derivation

## Requirements

### Requirement 1: Symmetric Encryption Support

**User Story:** As a security engineer, I want to encrypt files using industry-standard symmetric algorithms, so that I can protect sensitive data at rest.

#### Acceptance Criteria

1. THE Encryption_Engine SHALL support AES-256 in GCM mode
2. THE Encryption_Engine SHALL support AES-256 in CBC mode
3. THE Encryption_Engine SHALL support ChaCha20-Poly1305
4. WHEN encrypting with symmetric algorithms, THE Encryption_Engine SHALL generate cryptographically secure random IVs
5. WHEN encrypting with symmetric algorithms, THE Encryption_Engine SHALL authenticate ciphertext using AEAD or HMAC

### Requirement 2: Asymmetric Encryption Support

**User Story:** As a security engineer, I want to encrypt files using public-key cryptography, so that I can securely share encrypted data without sharing symmetric keys.

#### Acceptance Criteria

1. THE Encryption_Engine SHALL support RSA-OAEP with 2048-bit keys
2. THE Encryption_Engine SHALL support RSA-OAEP with 4096-bit keys
3. THE Encryption_Engine SHALL support Elliptic Curve Integrated Encryption Scheme (ECIES) with P-256
4. WHEN encrypting with asymmetric algorithms, THE Encryption_Engine SHALL use hybrid encryption for large files
5. WHEN using hybrid encryption, THE Encryption_Engine SHALL encrypt data with a symmetric key and encrypt the symmetric key with the public key

### Requirement 3: Key Derivation and Management

**User Story:** As a security engineer, I want to derive encryption keys from passwords securely, so that users can encrypt files without managing raw key material.

#### Acceptance Criteria

1. WHEN deriving keys from passwords, THE Key_Manager SHALL use PBKDF2 with at least 100,000 iterations
2. WHEN deriving keys from passwords, THE Key_Manager SHALL support Argon2id as an alternative KDF
3. WHEN deriving keys, THE Key_Manager SHALL generate cryptographically secure random salts
4. THE Key_Manager SHALL support key generation from secure random sources
5. WHEN storing derived key parameters, THE Key_Manager SHALL include salt and iteration count in the encrypted file metadata

### Requirement 4: File Encryption Operations

**User Story:** As a user, I want to encrypt individual files, so that I can protect specific sensitive documents.

#### Acceptance Criteria

1. WHEN a user specifies a file path and encryption algorithm, THE CLI_Tool SHALL encrypt the file
2. WHEN encrypting a file, THE File_Handler SHALL preserve the original file unless explicitly overwritten
3. WHEN encrypting a file, THE CLI_Tool SHALL create an encrypted output file with appropriate metadata
4. THE CLI_Tool SHALL support specifying output file paths for encrypted files
5. WHEN encryption fails, THE CLI_Tool SHALL return a descriptive error message and leave the original file unchanged

### Requirement 5: File Decryption Operations

**User Story:** As a user, I want to decrypt encrypted files, so that I can access my protected data when needed.

#### Acceptance Criteria

1. WHEN a user specifies an encrypted file and correct key, THE CLI_Tool SHALL decrypt the file
2. WHEN decrypting a file, THE Encryption_Engine SHALL verify authentication tags before decryption
3. IF authentication verification fails, THEN THE CLI_Tool SHALL reject the decryption and report tampering
4. WHEN decrypting a file, THE CLI_Tool SHALL restore the original file format and content
5. THE CLI_Tool SHALL support specifying output file paths for decrypted files

### Requirement 6: Directory Encryption Operations

**User Story:** As a user, I want to encrypt entire directories recursively, so that I can protect multiple files efficiently.

#### Acceptance Criteria

1. WHEN a user specifies a directory path, THE CLI_Tool SHALL encrypt all files within the directory recursively
2. WHEN encrypting a directory, THE File_Handler SHALL preserve the directory structure
3. WHEN encrypting a directory, THE CLI_Tool SHALL create an encrypted archive or encrypted file tree
4. THE CLI_Tool SHALL support excluding specific file patterns during directory encryption
5. WHEN directory encryption fails for any file, THE CLI_Tool SHALL report which files failed and continue with remaining files

### Requirement 7: Directory Decryption Operations

**User Story:** As a user, I want to decrypt encrypted directories, so that I can restore entire folder structures.

#### Acceptance Criteria

1. WHEN a user specifies an encrypted directory archive, THE CLI_Tool SHALL decrypt all files and restore the directory structure
2. WHEN decrypting a directory, THE File_Handler SHALL create the necessary subdirectories
3. WHEN decrypting a directory, THE CLI_Tool SHALL verify integrity of all encrypted files
4. THE CLI_Tool SHALL support specifying output directory paths for decrypted content
5. IF any file fails integrity verification, THEN THE CLI_Tool SHALL report the failure and skip that file

### Requirement 8: Command-Line Interface Design

**User Story:** As a user, I want an intuitive command-line interface, so that I can easily perform encryption operations.

#### Acceptance Criteria

1. THE CLI_Tool SHALL provide a main command with subcommands for encrypt, decrypt, keygen, and list-algorithms
2. WHEN a user runs the tool without arguments, THE CLI_Tool SHALL display usage information
3. THE CLI_Tool SHALL support command-line flags for algorithm selection, key input, and output paths
4. THE CLI_Tool SHALL provide verbose mode for detailed operation logging
5. THE CLI_Tool SHALL support reading passwords from stdin for scripting scenarios

### Requirement 9: Key Input Methods

**User Story:** As a user, I want multiple ways to provide encryption keys, so that I can choose the most secure method for my use case.

#### Acceptance Criteria

1. THE CLI_Tool SHALL support password-based encryption via interactive prompt
2. THE CLI_Tool SHALL support reading passwords from environment variables
3. THE CLI_Tool SHALL support reading raw keys from key files
4. THE CLI_Tool SHALL support using SSH keys for asymmetric operations
5. WHEN prompting for passwords, THE CLI_Tool SHALL hide password input from terminal display

### Requirement 10: Encrypted File Format

**User Story:** As a security engineer, I want a well-defined encrypted file format, so that encrypted files are portable and verifiable.

#### Acceptance Criteria

1. THE CLI_Tool SHALL use a structured file format with magic bytes for identification
2. WHEN creating encrypted files, THE File_Handler SHALL include version information in the header
3. WHEN creating encrypted files, THE File_Handler SHALL include algorithm identifiers in the header
4. WHEN creating encrypted files, THE File_Handler SHALL include all necessary parameters (IV, salt, iterations) in the header
5. THE CLI_Tool SHALL validate file format and version before attempting decryption

### Requirement 11: Error Handling and Security

**User Story:** As a security engineer, I want robust error handling and security practices, so that the tool fails safely and doesn't leak sensitive information.

#### Acceptance Criteria

1. WHEN cryptographic operations fail, THE CLI_Tool SHALL provide error messages without revealing key material
2. THE CLI_Tool SHALL clear sensitive data from memory after use
3. IF insufficient permissions exist for file operations, THEN THE CLI_Tool SHALL report permission errors clearly
4. THE CLI_Tool SHALL validate all user inputs before processing
5. WHEN encountering corrupted encrypted files, THE CLI_Tool SHALL detect and report corruption without crashing

### Requirement 12: Performance and Streaming

**User Story:** As a user, I want efficient encryption of large files, so that I can encrypt multi-gigabyte files without excessive memory usage.

#### Acceptance Criteria

1. WHEN encrypting files larger than 100MB, THE File_Handler SHALL use streaming encryption
2. THE CLI_Tool SHALL process files in chunks to maintain constant memory usage
3. THE CLI_Tool SHALL display progress indicators for operations on large files
4. WHEN encrypting directories, THE CLI_Tool SHALL process files in parallel where safe
5. THE Encryption_Engine SHALL optimize buffer sizes for macOS filesystem characteristics

### Requirement 13: Algorithm Information and Listing

**User Story:** As a user, I want to see available encryption algorithms and their properties, so that I can make informed choices.

#### Acceptance Criteria

1. THE CLI_Tool SHALL provide a command to list all supported algorithms
2. WHEN listing algorithms, THE CLI_Tool SHALL display algorithm names, key sizes, and security levels
3. THE CLI_Tool SHALL provide recommendations for algorithm selection based on use case
4. THE CLI_Tool SHALL display which algorithms support AEAD
5. WHEN querying an encrypted file, THE CLI_Tool SHALL display the algorithm used without decrypting

### Requirement 14: Key Generation Utilities

**User Story:** As a user, I want to generate cryptographic keys, so that I can use strong keys for encryption operations.

#### Acceptance Criteria

1. THE CLI_Tool SHALL provide a keygen subcommand for generating keys
2. WHEN generating symmetric keys, THE Key_Manager SHALL create keys of appropriate length for the specified algorithm
3. WHEN generating asymmetric key pairs, THE Key_Manager SHALL create both public and private keys
4. THE CLI_Tool SHALL support exporting generated keys in PEM format
5. WHEN generating keys, THE Key_Manager SHALL use cryptographically secure random number generators

### Requirement 15: Compression Integration

**User Story:** As a user, I want optional compression before encryption, so that I can reduce the size of encrypted files.

#### Acceptance Criteria

1. THE CLI_Tool SHALL support optional compression before encryption
2. WHERE compression is enabled, THE File_Handler SHALL compress data before encryption
3. THE CLI_Tool SHALL support multiple compression algorithms (gzip, zstd)
4. WHEN decrypting compressed files, THE File_Handler SHALL automatically decompress after decryption
5. THE CLI_Tool SHALL include compression metadata in the encrypted file header

### Requirement 16: Integrity and Authentication

**User Story:** As a security engineer, I want authenticated encryption, so that I can detect tampering or corruption.

#### Acceptance Criteria

1. THE Encryption_Engine SHALL use AEAD modes by default for symmetric encryption
2. WHERE AEAD is not available, THE Encryption_Engine SHALL use Encrypt-then-MAC with HMAC-SHA256
3. WHEN decrypting files, THE Encryption_Engine SHALL verify authentication tags before returning plaintext
4. IF authentication fails, THEN THE CLI_Tool SHALL refuse to decrypt and report potential tampering
5. THE CLI_Tool SHALL support additional file-level checksums (SHA-256) for plaintext verification
