// Cryptographic CLI Tool Library
// Core library modules for the crypto-cli-tool

pub mod app;
pub mod archive;
pub mod cli;
pub mod compression;
pub mod crypto;
pub mod error;
pub mod file_handler;
pub mod key_manager;

// Re-export commonly used types
pub use error::{CryptoError, Result};
pub use key_manager::{SecureBytes, SecureString};
