# Design Document: Cryptographic CLI Tool

## Overview

This document describes the design of a professional-grade cryptographic CLI tool for macOS. The tool provides a secure, efficient, and user-friendly interface for encrypting and decrypting files and directories using multiple industry-standard algorithms.

### Design Philosophy

The design follows these core principles:

1. **Security First**: Use only well-vetted cryptographic libraries and algorithms. Default to the most secure options (AEAD modes, strong KDFs).
2. **Defense in Depth**: Multiple layers of protection including authentication, integrity verification, and secure key handling.
3. **Fail Safely**: All error conditions should fail in a secure manner without leaking sensitive information.
4. **Performance**: Streaming operations for large files, parallel processing where safe, optimized for macOS.
5. **Usability**: Clear CLI interface with sensible defaults while allowing expert control.

### Technology Stack

- **Language**: Rust (for memory safety, performance, and excellent cryptography ecosystem)
- **Cryptography Library**: `ring` (for core primitives) and `RustCrypto` crates (for additional algorithms)
- **CLI Framework**: `clap` (for argument parsing and help generation)
- **Async Runtime**: `tokio` (for parallel directory processing)
- **Compression**: `flate2` (gzip) and `zstd` (Zstandard)

## Architecture

The system follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                     CLI Layer                           │
│  (Command parsing, user interaction, output formatting) │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                 Application Layer                       │
│     (Orchestration, workflow management, validation)    │
└──┬──────────────┬──────────────┬──────────────┬────────┘
   │              │              │              │
   ▼              ▼              ▼              ▼
┌──────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ Key  │   │Encryption│   │  File    │   │Compress  │
│ Mgmt │   │ Engine   │   │ Handler  │   │ Engine   │
└──────┘   └──────────┘   └──────────┘   └──────────┘
```

### Component Responsibilities

1. **CLI Layer**: Handles command-line argument parsing, user prompts, and output formatting
2. **Application Layer**: Orchestrates operations, validates inputs, manages workflows
3. **Key Management**: Key derivation, generation, loading, and secure storage in memory
4. **Encryption Engine**: Core cryptographic operations (encrypt/decrypt with various algorithms)
5. **File Handler**: File I/O, streaming, directory traversal, metadata management
6. **Compression Engine**: Optional compression/decompression before/after encryption


## Components and Interfaces

### 1. CLI Layer

**Module**: `cli.rs`

**Responsibilities**:
- Parse command-line arguments using `clap`
- Provide interactive password prompts
- Display progress indicators and status messages
- Format and display error messages

**Key Types**:
```rust
enum Command {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    KeyGen(KeyGenArgs),
    ListAlgorithms,
    Info(InfoArgs),
}

struct EncryptArgs {
    input: PathBuf,
    output: Option<PathBuf>,
    algorithm: Algorithm,
    key_source: KeySource,
    compress: Option<CompressionAlgorithm>,
    recursive: bool,
    verbose: bool,
}

struct DecryptArgs {
    input: PathBuf,
    output: Option<PathBuf>,
    key_source: KeySource,
    verbose: bool,
}
```

**Interface**:
- `parse_args() -> Result<Command>`: Parse command-line arguments
- `prompt_password(prompt: &str) -> Result<SecureString>`: Securely prompt for password
- `display_progress(current: u64, total: u64)`: Show progress bar
- `display_error(error: &Error)`: Format and display errors

### 2. Key Management Module

**Module**: `key_manager.rs`

**Responsibilities**:
- Derive keys from passwords using KDFs
- Generate random keys and key pairs
- Load keys from files
- Securely zero memory when keys are dropped

**Key Types**:
```rust
enum KeySource {
    Password(SecureString),
    PasswordEnv(String),
    KeyFile(PathBuf),
    Generated,
}

struct DerivedKey {
    key: SecureBytes,
    salt: [u8; 32],
    kdf: KdfAlgorithm,
    iterations: u32,
}

enum KdfAlgorithm {
    Pbkdf2Sha256,
    Argon2id,
}

struct KeyPair {
    public_key: Vec<u8>,
    private_key: SecureBytes,
}
```

**Interface**:
- `derive_key(password: &SecureString, salt: &[u8], kdf: KdfAlgorithm, iterations: u32) -> Result<SecureBytes>`
- `generate_random_key(size: usize) -> Result<SecureBytes>`
- `generate_key_pair(algorithm: AsymmetricAlgorithm) -> Result<KeyPair>`
- `load_key_from_file(path: &Path) -> Result<SecureBytes>`


### 3. Encryption Engine

**Module**: `crypto.rs`

**Responsibilities**:
- Perform encryption and decryption operations
- Generate and validate IVs/nonces
- Compute and verify authentication tags
- Support multiple algorithms

**Key Types**:
```rust
enum Algorithm {
    Aes256Gcm,
    Aes256Cbc,
    ChaCha20Poly1305,
    RsaOaep2048,
    RsaOaep4096,
    EciesP256,
}

struct EncryptionContext {
    algorithm: Algorithm,
    key: SecureBytes,
    iv: Vec<u8>,
    aad: Option<Vec<u8>>, // Additional authenticated data
}

struct EncryptionResult {
    ciphertext: Vec<u8>,
    iv: Vec<u8>,
    tag: Option<Vec<u8>>, // For AEAD modes
    mac: Option<Vec<u8>>, // For non-AEAD modes
}

struct DecryptionContext {
    algorithm: Algorithm,
    key: SecureBytes,
    iv: Vec<u8>,
    tag: Option<Vec<u8>>,
    mac: Option<Vec<u8>>,
}
```

**Interface**:
- `encrypt(plaintext: &[u8], context: &EncryptionContext) -> Result<EncryptionResult>`
- `decrypt(ciphertext: &[u8], context: &DecryptionContext) -> Result<Vec<u8>>`
- `encrypt_stream(reader: impl Read, writer: impl Write, context: &EncryptionContext) -> Result<EncryptionResult>`
- `decrypt_stream(reader: impl Read, writer: impl Write, context: &DecryptionContext) -> Result<()>`
- `generate_iv(algorithm: Algorithm) -> Vec<u8>`

### 4. File Handler

**Module**: `file_handler.rs`

**Responsibilities**:
- Read and write files with streaming support
- Traverse directories recursively
- Create and parse encrypted file format
- Manage temporary files safely

**Key Types**:
```rust
struct EncryptedFileHeader {
    magic: [u8; 8],           // "CRYPTOOL"
    version: u16,
    algorithm: Algorithm,
    kdf: Option<KdfAlgorithm>,
    kdf_iterations: Option<u32>,
    salt: Option<[u8; 32]>,
    iv: Vec<u8>,
    compressed: bool,
    compression_algo: Option<CompressionAlgorithm>,
    original_size: u64,
    metadata_size: u16,
}

struct FileOperation {
    input_path: PathBuf,
    output_path: PathBuf,
    operation_type: OperationType,
}

enum OperationType {
    EncryptFile,
    DecryptFile,
    EncryptDirectory,
    DecryptDirectory,
}
```

**Interface**:
- `read_file_streaming(path: &Path) -> Result<impl Read>`
- `write_file_streaming(path: &Path) -> Result<impl Write>`
- `traverse_directory(path: &Path, filter: Option<&Regex>) -> Result<Vec<PathBuf>>`
- `write_encrypted_header(writer: &mut impl Write, header: &EncryptedFileHeader) -> Result<()>`
- `read_encrypted_header(reader: &mut impl Read) -> Result<EncryptedFileHeader>`
- `create_archive(files: &[PathBuf], base_path: &Path) -> Result<Vec<u8>>`
- `extract_archive(data: &[u8], output_path: &Path) -> Result<()>`


### 5. Compression Engine

**Module**: `compression.rs`

**Responsibilities**:
- Compress data before encryption
- Decompress data after decryption
- Support multiple compression algorithms

**Key Types**:
```rust
enum CompressionAlgorithm {
    Gzip,
    Zstd,
}

struct CompressionContext {
    algorithm: CompressionAlgorithm,
    level: u32,
}
```

**Interface**:
- `compress(data: &[u8], context: &CompressionContext) -> Result<Vec<u8>>`
- `decompress(data: &[u8], algorithm: CompressionAlgorithm) -> Result<Vec<u8>>`
- `compress_stream(reader: impl Read, writer: impl Write, context: &CompressionContext) -> Result<()>`
- `decompress_stream(reader: impl Read, writer: impl Write, algorithm: CompressionAlgorithm) -> Result<()>`

### 6. Application Orchestrator

**Module**: `app.rs`

**Responsibilities**:
- Coordinate between all modules
- Implement high-level workflows (encrypt file, decrypt directory, etc.)
- Handle error propagation and recovery
- Manage operation state

**Key Types**:
```rust
struct Application {
    config: Config,
}

struct Config {
    default_algorithm: Algorithm,
    default_kdf: KdfAlgorithm,
    kdf_iterations: u32,
    buffer_size: usize,
    parallel_workers: usize,
}

struct OperationResult {
    success: bool,
    files_processed: usize,
    bytes_processed: u64,
    errors: Vec<OperationError>,
}
```

**Interface**:
- `encrypt_file(input: &Path, output: &Path, key: &SecureBytes, algorithm: Algorithm, compress: Option<CompressionAlgorithm>) -> Result<()>`
- `decrypt_file(input: &Path, output: &Path, key: &SecureBytes) -> Result<()>`
- `encrypt_directory(input: &Path, output: &Path, key: &SecureBytes, algorithm: Algorithm, recursive: bool) -> Result<OperationResult>`
- `decrypt_directory(input: &Path, output: &Path, key: &SecureBytes) -> Result<OperationResult>`
- `generate_keys(algorithm: AsymmetricAlgorithm, output_path: &Path) -> Result<()>`
- `list_algorithms() -> Vec<AlgorithmInfo>`
- `get_file_info(path: &Path) -> Result<FileInfo>`

## Data Models

### Encrypted File Format

The encrypted file format is designed to be self-describing and forward-compatible:

```
┌─────────────────────────────────────────────────────────┐
│                    File Header                          │
├─────────────────────────────────────────────────────────┤
│ Magic Bytes (8 bytes): "CRYPTOOL"                       │
│ Version (2 bytes): 0x0001                               │
│ Algorithm ID (1 byte)                                   │
│ Flags (1 byte): [compressed|reserved|reserved|...]      │
│ KDF Algorithm (1 byte, 0x00 if not used)               │
│ KDF Iterations (4 bytes, 0 if not used)                │
│ Salt Length (1 byte)                                    │
│ Salt (variable, 0-255 bytes)                           │
│ IV Length (1 byte)                                      │
│ IV (variable, typically 12-16 bytes)                   │
│ Original Size (8 bytes)                                 │
│ Metadata Length (2 bytes)                               │
│ Metadata (variable, JSON format)                        │
│ Header Checksum (32 bytes, SHA-256)                    │
├─────────────────────────────────────────────────────────┤
│                   Encrypted Data                        │
│              (variable length)                          │
├─────────────────────────────────────────────────────────┤
│            Authentication Tag/MAC                       │
│         (16-32 bytes, algorithm dependent)              │
└─────────────────────────────────────────────────────────┘
```

**Algorithm IDs**:
- 0x01: AES-256-GCM
- 0x02: AES-256-CBC (with HMAC-SHA256)
- 0x03: ChaCha20-Poly1305
- 0x04: RSA-OAEP-2048 (hybrid)
- 0x05: RSA-OAEP-4096 (hybrid)
- 0x06: ECIES-P256

**Metadata Format** (JSON):
```json
{
  "filename": "original_filename.txt",
  "compression": "zstd",
  "timestamp": 1704067200,
  "checksum": "sha256:abcdef...",
  "custom": {}
}
```


### Directory Archive Format

When encrypting directories, files are archived using a TAR-like format before encryption:

```
┌─────────────────────────────────────────────────────────┐
│                  Archive Header                         │
├─────────────────────────────────────────────────────────┤
│ Magic: "CRYTAR"                                         │
│ Version: 1                                              │
│ Entry Count: N                                          │
├─────────────────────────────────────────────────────────┤
│                  Entry 1 Header                         │
├─────────────────────────────────────────────────────────┤
│ Path Length (2 bytes)                                   │
│ Path (UTF-8)                                            │
│ File Size (8 bytes)                                     │
│ Permissions (4 bytes)                                   │
│ Modified Time (8 bytes)                                 │
├─────────────────────────────────────────────────────────┤
│                  Entry 1 Data                           │
├─────────────────────────────────────────────────────────┤
│                  Entry 2 Header                         │
│                       ...                               │
└─────────────────────────────────────────────────────────┘
```

This entire archive is then compressed (if requested) and encrypted as a single file.

### Secure Memory Types

**SecureBytes**: A wrapper around `Vec<u8>` that zeros memory on drop
```rust
struct SecureBytes {
    data: Vec<u8>,
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        // Zero memory before deallocation
        self.data.iter_mut().for_each(|b| *b = 0);
    }
}
```

**SecureString**: A wrapper around `String` that zeros memory on drop
```rust
struct SecureString {
    data: String,
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Zero memory before deallocation
        unsafe {
            self.data.as_bytes_mut().iter_mut().for_each(|b| *b = 0);
        }
    }
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*


### Property 1: Encryption-Decryption Round Trip

*For any* plaintext data and valid encryption key, encrypting then immediately decrypting with the same key should produce data identical to the original plaintext.

**Validates: Requirements 1.1, 1.2, 1.3, 5.1, 5.4**

### Property 2: Authentication Tag Verification

*For any* encrypted file with authentication tag, if the ciphertext or tag is modified, decryption should fail with an authentication error before returning any plaintext.

**Validates: Requirements 1.5, 5.2, 5.3, 16.3, 16.4**

### Property 3: IV Uniqueness

*For any* two encryption operations with the same key, the generated IVs should be different with overwhelming probability (collision probability < 2^-128).

**Validates: Requirements 1.4**

### Property 4: Key Derivation Determinism

*For any* password, salt, KDF algorithm, and iteration count, deriving a key multiple times with the same parameters should always produce the same key.

**Validates: Requirements 3.1, 3.2, 3.5**

### Property 5: Salt Uniqueness

*For any* two key derivation operations, the generated salts should be different with overwhelming probability.

**Validates: Requirements 3.3**

### Property 6: File Encryption Preserves Original

*For any* file encryption operation that does not specify overwrite, the original file should remain unchanged after encryption completes or fails.

**Validates: Requirements 4.2, 4.5**

### Property 7: Encrypted File Format Validity

*For any* successfully encrypted file, reading the file header should succeed and return valid algorithm, IV, and metadata information.

**Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5**

### Property 8: Directory Structure Preservation

*For any* directory encryption operation, the decrypted output should contain the same directory structure and file paths as the original input.

**Validates: Requirements 6.2, 7.2**

### Property 9: Compression Round Trip

*For any* data and compression algorithm, compressing then decompressing should produce data identical to the original.

**Validates: Requirements 15.2, 15.4**

### Property 10: Streaming Consistency

*For any* file larger than the buffer size, encrypting via streaming should produce the same ciphertext as encrypting the entire file in memory (given the same IV and key).

**Validates: Requirements 12.1, 12.2**

### Property 11: Hybrid Encryption Correctness

*For any* plaintext and asymmetric key pair, hybrid encryption (encrypt data with symmetric key, encrypt symmetric key with public key) followed by hybrid decryption (decrypt symmetric key with private key, decrypt data with symmetric key) should recover the original plaintext.

**Validates: Requirements 2.4, 2.5**

### Property 12: Password Input Security

*For any* password prompt operation, the password characters should not be echoed to the terminal display.

**Validates: Requirements 9.5**

### Property 13: Error Message Safety

*For any* cryptographic operation failure, the error message should not contain key material, passwords, or plaintext data.

**Validates: Requirements 11.1**

### Property 14: Tamper Detection

*For any* encrypted file, if any byte in the ciphertext or authentication tag is modified, decryption should detect the tampering and fail.

**Validates: Requirements 5.3, 11.5, 16.4**

### Property 15: Algorithm Information Accuracy

*For any* encrypted file, querying its algorithm information should return the same algorithm that was used during encryption, without requiring decryption.

**Validates: Requirements 13.5**


## Error Handling

### Error Types

The system defines a comprehensive error hierarchy:

```rust
enum CryptoError {
    // Cryptographic errors
    EncryptionFailed(String),
    DecryptionFailed(String),
    AuthenticationFailed,
    InvalidKey,
    InvalidIV,
    
    // File I/O errors
    FileNotFound(PathBuf),
    FileReadError(PathBuf, io::Error),
    FileWriteError(PathBuf, io::Error),
    PermissionDenied(PathBuf),
    
    // Format errors
    InvalidFileFormat,
    UnsupportedVersion(u16),
    CorruptedHeader,
    InvalidMetadata,
    
    // Key management errors
    KeyDerivationFailed,
    InvalidPassword,
    KeyGenerationFailed,
    
    // User input errors
    InvalidArguments(String),
    MissingRequiredArgument(String),
    
    // System errors
    InsufficientMemory,
    SystemError(String),
}
```

### Error Handling Strategy

1. **Fail Fast**: Validate inputs early and return errors before performing expensive operations
2. **Contextual Errors**: Include relevant context (file paths, operation type) in error messages
3. **No Sensitive Data**: Never include keys, passwords, or plaintext in error messages
4. **Cleanup on Error**: Ensure temporary files are deleted and resources are freed on error
5. **Atomic Operations**: File operations should be atomic where possible (write to temp, then rename)

### Recovery Mechanisms

- **Partial Directory Encryption**: If some files fail during directory encryption, continue with remaining files and report failures at the end
- **Temporary File Cleanup**: Use RAII patterns to ensure temporary files are cleaned up even on panic
- **Transaction Log**: For directory operations, maintain a log of completed operations to enable resume on failure



## Testing Strategy

### Dual Testing Approach

This project will use both unit tests and property-based tests to ensure comprehensive correctness:

- **Unit Tests**: Verify specific examples, edge cases, and error conditions
- **Property Tests**: Verify universal properties across all inputs using randomized testing

Both testing approaches are complementary and necessary for high confidence in correctness.

### Property-Based Testing

We will use the `proptest` crate for property-based testing in Rust. Each correctness property defined above will be implemented as a property test.

**Configuration**:
- Minimum 100 test cases per property (due to randomization)
- Each property test must reference its design document property number
- Tag format: `// Feature: crypto-cli-tool, Property N: [property description]`

**Test Generators**:
- Random byte arrays of varying sizes (0 bytes to 10MB)
- Random passwords (ASCII, UTF-8, special characters)
- Random file paths and directory structures
- Random algorithm selections
- Random keys of appropriate sizes for each algorithm

**Example Property Test Structure**:
```rust
proptest! {
    #[test]
    // Feature: crypto-cli-tool, Property 1: Encryption-Decryption Round Trip
    fn test_encryption_round_trip(
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        password in "[a-zA-Z0-9]{8,32}",
        algorithm in prop_oneof![
            Just(Algorithm::Aes256Gcm),
            Just(Algorithm::ChaCha20Poly1305),
        ]
    ) {
        let key = derive_key(&password, &random_salt(), KdfAlgorithm::Pbkdf2Sha256, 100000)?;
        let encrypted = encrypt(&plaintext, &key, algorithm)?;
        let decrypted = decrypt(&encrypted, &key)?;
        prop_assert_eq!(plaintext, decrypted);
    }
}
```

### Unit Testing

Unit tests will focus on:

1. **Specific Examples**: Known test vectors for each algorithm (NIST test vectors, RFC examples)
2. **Edge Cases**:
   - Empty files
   - Very large files (streaming behavior)
   - Files with special characters in names
   - Deeply nested directory structures
   - Symbolic links and special files
3. **Error Conditions**:
   - Wrong password
   - Corrupted ciphertext
   - Missing files
   - Permission errors
   - Invalid algorithm IDs
4. **Integration Points**:
   - CLI argument parsing
   - File format serialization/deserialization
   - Key derivation with known parameters

### Test Organization

```
tests/
├── unit/
│   ├── crypto_test.rs          # Encryption engine unit tests
│   ├── key_manager_test.rs     # Key management unit tests
│   ├── file_handler_test.rs    # File operations unit tests
│   └── cli_test.rs             # CLI parsing unit tests
├── property/
│   ├── crypto_properties.rs    # Cryptographic properties
│   ├── file_properties.rs      # File operation properties
│   └── integration_properties.rs # End-to-end properties
└── integration/
    ├── encrypt_decrypt_test.rs # Full workflow tests
    └── directory_test.rs       # Directory encryption tests
```

### Test Data

- Use temporary directories for all file operations
- Generate test files programmatically
- Clean up test artifacts after each test
- Use known test vectors from standards (NIST, RFC)

### Performance Testing

While not part of correctness testing, we should benchmark:
- Encryption/decryption throughput for various file sizes
- Memory usage during streaming operations
- Directory encryption with many files
- Key derivation time with different iteration counts

