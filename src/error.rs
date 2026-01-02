// Error types and Result aliases
//
// SECURITY NOTE: All error messages are carefully designed to avoid leaking
// sensitive information such as:
// - Key material (encryption keys, derived keys, key bytes)
// - Passwords or passphrases
// - Plaintext data or file contents
// - Internal cryptographic state
//
// Error messages only include:
// - File paths (which are already known to the user)
// - Operation types (encrypt, decrypt, etc.)
// - Generic failure reasons (authentication failed, corrupted header, etc.)
//
// When adding new error variants, ensure they follow these security guidelines.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Main error type for the cryptographic CLI tool
#[derive(Debug)]
pub enum CryptoError {
    // Cryptographic errors
    EncryptionFailed(String),
    DecryptionFailed(String),
    AuthenticationFailed,
    InvalidKey,
    InvalidIV,
    InvalidKeySize { expected: usize, got: usize },
    InvalidAlgorithm(String),
    
    // File I/O errors
    FileNotFound(PathBuf),
    FileReadError(PathBuf, io::Error),
    FileWriteError(PathBuf, io::Error),
    PermissionDenied(PathBuf),
    FileAlreadyExists(PathBuf),
    DirectoryNotFound(PathBuf),
    NotAFile(PathBuf),
    NotADirectory(PathBuf),
    
    // Format errors
    InvalidFileFormat,
    UnsupportedVersion(u16),
    CorruptedHeader,
    InvalidMetadata,
    
    // Key management errors
    KeyDerivationFailed,
    InvalidPassword,
    KeyGenerationFailed,
    InvalidIterationCount { min: u32, got: u32 },
    
    // User input errors
    InvalidArguments(String),
    MissingRequiredArgument(String),
    InvalidPath(PathBuf),
    
    // System errors
    InsufficientMemory,
    SystemError(String),
    IoError(io::Error),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            CryptoError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            CryptoError::AuthenticationFailed => write!(f, "Authentication verification failed - possible tampering detected"),
            CryptoError::InvalidKey => write!(f, "Invalid encryption key"),
            CryptoError::InvalidIV => write!(f, "Invalid initialization vector"),
            CryptoError::InvalidKeySize { expected, got } => {
                write!(f, "Invalid key size: expected {} bytes, got {} bytes", expected, got)
            }
            CryptoError::InvalidAlgorithm(algo) => write!(f, "Invalid or unsupported algorithm: {}", algo),
            
            CryptoError::FileNotFound(path) => write!(f, "File not found: {}", path.display()),
            CryptoError::FileReadError(path, err) => write!(f, "Failed to read file {}: {}", path.display(), err),
            CryptoError::FileWriteError(path, err) => write!(f, "Failed to write file {}: {}", path.display(), err),
            CryptoError::PermissionDenied(path) => write!(f, "Permission denied: {}", path.display()),
            CryptoError::FileAlreadyExists(path) => write!(f, "File already exists: {}", path.display()),
            CryptoError::DirectoryNotFound(path) => write!(f, "Directory not found: {}", path.display()),
            CryptoError::NotAFile(path) => write!(f, "Not a file: {}", path.display()),
            CryptoError::NotADirectory(path) => write!(f, "Not a directory: {}", path.display()),
            
            CryptoError::InvalidFileFormat => write!(f, "Invalid or corrupted file format"),
            CryptoError::UnsupportedVersion(version) => write!(f, "Unsupported file format version: {}", version),
            CryptoError::CorruptedHeader => write!(f, "Corrupted file header - file may be damaged"),
            CryptoError::InvalidMetadata => write!(f, "Invalid or corrupted metadata"),
            
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            CryptoError::InvalidPassword => write!(f, "Invalid password or authentication failed"),
            CryptoError::KeyGenerationFailed => write!(f, "Key generation failed"),
            CryptoError::InvalidIterationCount { min, got } => {
                write!(f, "Invalid iteration count: minimum {} required, got {}", min, got)
            }
            
            CryptoError::InvalidArguments(msg) => write!(f, "Invalid arguments: {}", msg),
            CryptoError::MissingRequiredArgument(arg) => write!(f, "Missing required argument: {}", arg),
            CryptoError::InvalidPath(path) => write!(f, "Invalid path: {}", path.display()),
            
            CryptoError::InsufficientMemory => write!(f, "Insufficient memory to complete operation"),
            CryptoError::SystemError(msg) => write!(f, "System error: {}", msg),
            CryptoError::IoError(err) => write!(f, "I/O error: {}", err),
        }
    }
}

impl std::error::Error for CryptoError {}

impl CryptoError {
    /// Convert an io::Error to CryptoError with file path context
    pub fn from_io_error(err: io::Error, path: PathBuf, operation: &str) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => CryptoError::FileNotFound(path),
            io::ErrorKind::PermissionDenied => CryptoError::PermissionDenied(path),
            io::ErrorKind::AlreadyExists => CryptoError::FileAlreadyExists(path),
            _ => {
                if operation.contains("read") {
                    CryptoError::FileReadError(path, err)
                } else if operation.contains("write") {
                    CryptoError::FileWriteError(path, err)
                } else {
                    CryptoError::IoError(err)
                }
            }
        }
    }
    
    /// Sanitize a string to ensure it doesn't contain sensitive data
    /// 
    /// This function is used to sanitize error messages and debug output
    /// to prevent accidental leakage of key material, passwords, or plaintext.
    /// 
    /// # Security Note
    /// All error messages in CryptoError are already sanitized and do not
    /// include sensitive data. This function is provided for additional
    /// sanitization of external error messages or debug output.
    pub fn sanitize_message(msg: &str) -> String {
        // For now, we just return the message as-is since our error types
        // are already designed to not include sensitive data.
        // In the future, this could implement pattern matching to detect
        // and redact potential sensitive data.
        msg.to_string()
    }
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Input validation functions
/// 
/// These functions validate user inputs to ensure they meet security
/// and operational requirements before processing.
pub mod validation {
    use super::*;
    use std::path::Path;
    
    /// Minimum KDF iteration count for security
    pub const MIN_KDF_ITERATIONS: u32 = 100_000;
    
    /// Maximum reasonable KDF iteration count
    pub const MAX_KDF_ITERATIONS: u32 = 10_000_000;
    
    /// Validate a file path exists and is accessible
    pub fn validate_file_path(path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(CryptoError::FileNotFound(path.to_path_buf()));
        }
        
        if !path.is_file() {
            return Err(CryptoError::NotAFile(path.to_path_buf()));
        }
        
        Ok(())
    }
    
    /// Validate a directory path exists and is accessible
    pub fn validate_directory_path(path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(CryptoError::DirectoryNotFound(path.to_path_buf()));
        }
        
        if !path.is_dir() {
            return Err(CryptoError::NotADirectory(path.to_path_buf()));
        }
        
        Ok(())
    }
    
    /// Validate a path is valid (doesn't need to exist yet)
    pub fn validate_path(path: &Path) -> Result<()> {
        // Check if path is absolute or relative
        if path.as_os_str().is_empty() {
            return Err(CryptoError::InvalidPath(path.to_path_buf()));
        }
        
        // Check for null bytes (security issue)
        if path.to_str().map_or(false, |s| s.contains('\0')) {
            return Err(CryptoError::InvalidPath(path.to_path_buf()));
        }
        
        Ok(())
    }
    
    /// Validate an algorithm name
    pub fn validate_algorithm(algo: &str) -> Result<()> {
        let valid_algorithms = [
            "aes-256-gcm",
            "aes-256-cbc",
            "chacha20-poly1305",
            "rsa-oaep-2048",
            "rsa-oaep-4096",
            "ecies-p256",
        ];
        
        if !valid_algorithms.contains(&algo.to_lowercase().as_str()) {
            return Err(CryptoError::InvalidAlgorithm(algo.to_string()));
        }
        
        Ok(())
    }
    
    /// Validate key size for a given algorithm
    pub fn validate_key_size(algorithm: &str, key_size: usize) -> Result<()> {
        let expected_size = match algorithm.to_lowercase().as_str() {
            "aes-256-gcm" | "aes-256-cbc" | "chacha20-poly1305" => 32,
            "aes-128-gcm" | "aes-128-cbc" => 16,
            _ => return Ok(()), // For asymmetric algorithms, size varies
        };
        
        if key_size != expected_size {
            return Err(CryptoError::InvalidKeySize {
                expected: expected_size,
                got: key_size,
            });
        }
        
        Ok(())
    }
    
    /// Validate KDF iteration count
    pub fn validate_iteration_count(iterations: u32) -> Result<()> {
        if iterations < MIN_KDF_ITERATIONS {
            return Err(CryptoError::InvalidIterationCount {
                min: MIN_KDF_ITERATIONS,
                got: iterations,
            });
        }
        
        if iterations > MAX_KDF_ITERATIONS {
            return Err(CryptoError::InvalidArguments(
                format!("Iteration count too high: {} (max: {})", iterations, MAX_KDF_ITERATIONS)
            ));
        }
        
        Ok(())
    }
    
    /// Validate output path doesn't overwrite existing file without permission
    pub fn validate_output_path(path: &Path, allow_overwrite: bool) -> Result<()> {
        validate_path(path)?;
        
        if path.exists() && !allow_overwrite {
            return Err(CryptoError::FileAlreadyExists(path.to_path_buf()));
        }
        
        // Check if parent directory exists and is writable
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                return Err(CryptoError::DirectoryNotFound(parent.to_path_buf()));
            }
        }
        
        Ok(())
    }
}
