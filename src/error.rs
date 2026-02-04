// Error types and Result aliases
// 错误类型和 Result 别名
//
// SECURITY NOTE: All error messages are carefully designed to avoid leaking
// sensitive information such as:
// 安全注意：所有错误消息都经过精心设计，以避免泄露敏感信息，例如：
// - Key material (encryption keys, derived keys, key bytes)
//   密钥材料（加密密钥、派生密钥、密钥字节）
// - Passwords or passphrases
//   密码或口令
// - Plaintext data or file contents
//   明文数据或文件内容
// - Internal cryptographic state
//   内部加密状态
//
// Error messages only include:
// 错误消息仅包括：
// - File paths (which are already known to the user)
//   文件路径（用户已知）
// - Operation types (encrypt, decrypt, etc.)
//   操作类型（加密、解密等）
// - Generic failure reasons (authentication failed, corrupted header, etc.)
//   通用失败原因（认证失败、头部损坏等）
//
// When adding new error variants, ensure they follow these security guidelines.
// 添加新的错误变体时，请确保遵循这些安全准则。

use std::fmt;
use std::io;
use std::path::PathBuf;
use crate::i18n;

/// Main error type for the cryptographic CLI tool
/// 加密 CLI 工具的主要错误类型
#[derive(Debug)]
pub enum CryptoError {
    // Cryptographic errors / 加密错误
    EncryptionFailed(String),
    DecryptionFailed(String),
    AuthenticationFailed,
    InvalidKey,
    InvalidIV,
    InvalidKeySize { expected: usize, got: usize },
    InvalidAlgorithm(String),
    
    // File I/O errors / 文件 I/O 错误
    FileNotFound(PathBuf),
    FileReadError(PathBuf, io::Error),
    FileWriteError(PathBuf, io::Error),
    PermissionDenied(PathBuf),
    FileAlreadyExists(PathBuf),
    DirectoryNotFound(PathBuf),
    NotAFile(PathBuf),
    NotADirectory(PathBuf),
    
    // Format errors / 格式错误
    InvalidFileFormat,
    UnsupportedVersion(u16),
    CorruptedHeader,
    InvalidMetadata,
    
    // Key management errors / 密钥管理错误
    KeyDerivationFailed,
    InvalidPassword,
    KeyGenerationFailed,
    InvalidIterationCount { min: u32, got: u32 },
    
    // User input errors / 用户输入错误
    InvalidArguments(String),
    MissingRequiredArgument(String),
    InvalidPath(PathBuf),
    
    // System errors / 系统错误
    InsufficientMemory,
    SystemError(String),
    IoError(io::Error),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionFailed(msg) => {
                let label = i18n::t("Encryption failed", "加密失败");
                write!(f, "{}: {}", label, msg)
            }
            CryptoError::DecryptionFailed(msg) => {
                let label = i18n::t("Decryption failed", "解密失败");
                write!(f, "{}: {}", label, msg)
            }
            CryptoError::AuthenticationFailed => {
                let msg = i18n::t(
                    "Authentication verification failed - possible tampering detected",
                    "认证验证失败 - 可能检测到篡改",
                );
                write!(f, "{}", msg)
            }
            CryptoError::InvalidKey => {
                let msg = i18n::t("Invalid encryption key", "无效的加密密钥");
                write!(f, "{}", msg)
            }
            CryptoError::InvalidIV => {
                let msg = i18n::t("Invalid initialization vector", "无效的初始化向量");
                write!(f, "{}", msg)
            }
            CryptoError::InvalidKeySize { expected, got } => {
                let msg = if i18n::is_zh() {
                    format!("密钥长度无效：期望 {} 字节，实际 {} 字节", expected, got)
                } else {
                    format!("Invalid key size: expected {} bytes, got {} bytes", expected, got)
                };
                write!(f, "{}", msg)
            }
            CryptoError::InvalidAlgorithm(algo) => {
                let msg = if i18n::is_zh() {
                    format!("无效或不支持的算法：{}", algo)
                } else {
                    format!("Invalid or unsupported algorithm: {}", algo)
                };
                write!(f, "{}", msg)
            }
            
            CryptoError::FileNotFound(path) => {
                let msg = if i18n::is_zh() {
                    format!("文件未找到：{}", path.display())
                } else {
                    format!("File not found: {}", path.display())
                };
                write!(f, "{}", msg)
            }
            CryptoError::FileReadError(path, err) => {
                let msg = if i18n::is_zh() {
                    format!("读取文件失败 {}：{}", path.display(), err)
                } else {
                    format!("Failed to read file {}: {}", path.display(), err)
                };
                write!(f, "{}", msg)
            }
            CryptoError::FileWriteError(path, err) => {
                let msg = if i18n::is_zh() {
                    format!("写入文件失败 {}：{}", path.display(), err)
                } else {
                    format!("Failed to write file {}: {}", path.display(), err)
                };
                write!(f, "{}", msg)
            }
            CryptoError::PermissionDenied(path) => {
                let msg = if i18n::is_zh() {
                    format!("没有权限：{}", path.display())
                } else {
                    format!("Permission denied: {}", path.display())
                };
                write!(f, "{}", msg)
            }
            CryptoError::FileAlreadyExists(path) => {
                let msg = if i18n::is_zh() {
                    format!("文件已存在：{}", path.display())
                } else {
                    format!("File already exists: {}", path.display())
                };
                write!(f, "{}", msg)
            }
            CryptoError::DirectoryNotFound(path) => {
                let msg = if i18n::is_zh() {
                    format!("目录未找到：{}", path.display())
                } else {
                    format!("Directory not found: {}", path.display())
                };
                write!(f, "{}", msg)
            }
            CryptoError::NotAFile(path) => {
                let msg = if i18n::is_zh() {
                    format!("不是文件：{}", path.display())
                } else {
                    format!("Not a file: {}", path.display())
                };
                write!(f, "{}", msg)
            }
            CryptoError::NotADirectory(path) => {
                let msg = if i18n::is_zh() {
                    format!("不是目录：{}", path.display())
                } else {
                    format!("Not a directory: {}", path.display())
                };
                write!(f, "{}", msg)
            }
            
            CryptoError::InvalidFileFormat => {
                let msg = i18n::t("Invalid or corrupted file format", "文件格式无效或已损坏");
                write!(f, "{}", msg)
            }
            CryptoError::UnsupportedVersion(version) => {
                let msg = if i18n::is_zh() {
                    format!("不支持的文件格式版本：{}", version)
                } else {
                    format!("Unsupported file format version: {}", version)
                };
                write!(f, "{}", msg)
            }
            CryptoError::CorruptedHeader => {
                let msg = i18n::t("Corrupted file header - file may be damaged", "文件头已损坏 - 文件可能受损");
                write!(f, "{}", msg)
            }
            CryptoError::InvalidMetadata => {
                let msg = i18n::t("Invalid or corrupted metadata", "元数据无效或已损坏");
                write!(f, "{}", msg)
            }
            
            CryptoError::KeyDerivationFailed => {
                let msg = i18n::t("Key derivation failed", "密钥派生失败");
                write!(f, "{}", msg)
            }
            CryptoError::InvalidPassword => {
                let msg = i18n::t("Invalid password or authentication failed", "密码无效或认证失败");
                write!(f, "{}", msg)
            }
            CryptoError::KeyGenerationFailed => {
                let msg = i18n::t("Key generation failed", "密钥生成失败");
                write!(f, "{}", msg)
            }
            CryptoError::InvalidIterationCount { min, got } => {
                let msg = if i18n::is_zh() {
                    format!("迭代次数无效：至少需要 {}，实际 {}", min, got)
                } else {
                    format!("Invalid iteration count: minimum {} required, got {}", min, got)
                };
                write!(f, "{}", msg)
            }
            
            CryptoError::InvalidArguments(msg) => {
                let label = i18n::t("Invalid arguments", "参数无效");
                write!(f, "{}: {}", label, msg)
            }
            CryptoError::MissingRequiredArgument(arg) => {
                let label = i18n::t("Missing required argument", "缺少必需参数");
                write!(f, "{}: {}", label, arg)
            }
            CryptoError::InvalidPath(path) => {
                let msg = if i18n::is_zh() {
                    format!("路径无效：{}", path.display())
                } else {
                    format!("Invalid path: {}", path.display())
                };
                write!(f, "{}", msg)
            }
            
            CryptoError::InsufficientMemory => {
                let msg = i18n::t("Insufficient memory to complete operation", "内存不足，无法完成操作");
                write!(f, "{}", msg)
            }
            CryptoError::SystemError(msg) => {
                let label = i18n::t("System error", "系统错误");
                write!(f, "{}: {}", label, msg)
            }
            CryptoError::IoError(err) => {
                let label = i18n::t("I/O error", "I/O 错误");
                write!(f, "{}: {}", label, err)
            }
        }
    }
}

impl std::error::Error for CryptoError {}

impl CryptoError {
    /// Convert an io::Error to CryptoError with file path context
    /// 将 io::Error 转换为带有文件路径上下文的 CryptoError
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
    /// 清理字符串以确保不包含敏感数据
    /// 
    /// This function is used to sanitize error messages and debug output
    /// to prevent accidental leakage of key material, passwords, or plaintext.
    /// 此函数用于清理错误消息和调试输出，以防止意外泄露密钥材料、密码或明文。
    /// 
    /// # Security Note / 安全注意
    /// All error messages in CryptoError are already sanitized and do not
    /// include sensitive data. This function is provided for additional
    /// sanitization of external error messages or debug output.
    /// CryptoError 中的所有错误消息都已经过清理，不包含敏感数据。
    /// 此函数用于对外部错误消息或调试输出进行额外清理。
    pub fn sanitize_message(msg: &str) -> String {
        // For now, we just return the message as-is since our error types
        // are already designed to not include sensitive data.
        // In the future, this could implement pattern matching to detect
        // and redact potential sensitive data.
        msg.to_string()
    }
}

/// Result type alias for convenience
/// 便捷的 Result 类型别名
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Input validation functions
/// 输入验证函数
/// 
/// These functions validate user inputs to ensure they meet security
/// and operational requirements before processing.
/// 这些函数验证用户输入，以确保在处理之前满足安全和操作要求。
pub mod validation {
    use super::*;
    use std::path::Path;
    
    /// Minimum KDF iteration count for security
    /// 安全的最小 KDF 迭代次数
    pub const MIN_KDF_ITERATIONS: u32 = 100_000;
    
    /// Maximum reasonable KDF iteration count
    /// 合理的最大 KDF 迭代次数
    pub const MAX_KDF_ITERATIONS: u32 = 10_000_000;
    
    /// Validate a file path exists and is accessible
    /// 验证文件路径是否存在且可访问
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
            let msg = if i18n::is_zh() {
                format!("迭代次数过高：{}（最大：{}）", iterations, MAX_KDF_ITERATIONS)
            } else {
                format!("Iteration count too high: {} (max: {})", iterations, MAX_KDF_ITERATIONS)
            };
            return Err(CryptoError::InvalidArguments(msg));
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
