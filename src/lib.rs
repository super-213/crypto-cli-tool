// Cryptographic CLI Tool Library
// 加密 CLI 工具库
// Core library modules for the crypto-cli-tool
// crypto-cli-tool 的核心库模块

pub mod app;
pub mod archive;
pub mod cli;
pub mod compression;
pub mod crypto;
pub mod error;
pub mod file_handler;
pub mod i18n;
pub mod interactive;
pub mod key_manager;

// Re-export commonly used types
// 重新导出常用类型
pub use error::{CryptoError, Result};
pub use key_manager::{SecureBytes, SecureString};
