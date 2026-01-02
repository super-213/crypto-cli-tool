// CLI module - command-line interface and argument parsing

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Cryptographic CLI Tool - Encrypt and decrypt files and directories
#[derive(Parser, Debug)]
#[command(name = "crypto-cli-tool")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Encrypt a file or directory
    Encrypt(EncryptArgs),
    
    /// Decrypt a file or directory
    Decrypt(DecryptArgs),
    
    /// Generate cryptographic keys
    Keygen(KeygenArgs),
    
    /// List all supported encryption algorithms
    ListAlgorithms,
    
    /// Display information about an encrypted file
    Info(InfoArgs),
}

/// Arguments for the encrypt command
#[derive(Parser, Debug)]
pub struct EncryptArgs {
    /// Input file or directory to encrypt
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,
    
    /// Output file or directory (defaults to input + .enc)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    
    /// Encryption algorithm to use
    #[arg(short, long, value_name = "ALGORITHM", default_value = "aes-256-gcm")]
    pub algorithm: String,
    
    /// Key source: password, env, or keyfile
    #[arg(short, long, value_name = "SOURCE", default_value = "password")]
    pub key_source: String,
    
    /// Environment variable name for password (when key-source=env)
    #[arg(long, value_name = "VAR")]
    pub password_env: Option<String>,
    
    /// Key file path (when key-source=keyfile)
    #[arg(long, value_name = "FILE")]
    pub keyfile: Option<PathBuf>,
    
    /// Compression algorithm (gzip or zstd)
    #[arg(short, long, value_name = "ALGORITHM")]
    pub compress: Option<String>,
    
    /// Compression level (1-9 for gzip, 1-22 for zstd)
    #[arg(long, value_name = "LEVEL")]
    pub compression_level: Option<u32>,
    
    /// Recursively encrypt directories
    #[arg(short, long)]
    pub recursive: bool,
    
    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

/// Arguments for the decrypt command
#[derive(Parser, Debug)]
pub struct DecryptArgs {
    /// Input encrypted file or directory
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,
    
    /// Output file or directory (defaults to input without .enc)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    
    /// Key source: password, env, or keyfile
    #[arg(short, long, value_name = "SOURCE", default_value = "password")]
    pub key_source: String,
    
    /// Environment variable name for password (when key-source=env)
    #[arg(long, value_name = "VAR")]
    pub password_env: Option<String>,
    
    /// Key file path (when key-source=keyfile)
    #[arg(long, value_name = "FILE")]
    pub keyfile: Option<PathBuf>,
    
    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

/// Arguments for the keygen command
#[derive(Parser, Debug)]
pub struct KeygenArgs {
    /// Algorithm to generate keys for
    #[arg(short, long, value_name = "ALGORITHM")]
    pub algorithm: String,
    
    /// Output file for the key (or key pair)
    #[arg(short, long, value_name = "FILE")]
    pub output: PathBuf,
    
    /// Export format (raw or pem)
    #[arg(short, long, value_name = "FORMAT", default_value = "pem")]
    pub format: String,
    
    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

/// Arguments for the info command
#[derive(Parser, Debug)]
pub struct InfoArgs {
    /// Encrypted file to inspect
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,
    
    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

/// Parse command-line arguments
pub fn parse_args() -> Cli {
    Cli::parse()
}

use crate::key_manager::SecureString;
use crate::error::{CryptoError, Result};
use std::io::{self, Write};

/// Prompt the user for a password securely
///
/// The password is hidden from terminal display and returned as a SecureString
/// that will be zeroed when dropped.
///
/// # Arguments
/// * `prompt` - The prompt message to display
///
/// # Returns
/// A SecureString containing the password
pub fn prompt_password(prompt: &str) -> Result<SecureString> {
    print!("{}", prompt);
    io::stdout().flush()
        .map_err(|e| CryptoError::SystemError(format!("Failed to flush stdout: {}", e)))?;
    
    let password = rpassword::read_password()
        .map_err(|e| CryptoError::SystemError(format!("Failed to read password: {}", e)))?;
    
    Ok(SecureString::from(password))
}

/// Prompt the user for a password with confirmation
///
/// This is used for encryption operations to ensure the user didn't mistype.
/// The password is hidden from terminal display.
///
/// # Arguments
/// * `prompt` - The initial prompt message
/// * `confirm_prompt` - The confirmation prompt message
///
/// # Returns
/// A SecureString containing the password if both entries match
pub fn prompt_password_with_confirmation(
    prompt: &str,
    confirm_prompt: &str,
) -> Result<SecureString> {
    let password = prompt_password(prompt)?;
    let confirm = prompt_password(confirm_prompt)?;
    
    if password.as_str() != confirm.as_str() {
        return Err(CryptoError::InvalidPassword);
    }
    
    Ok(password)
}

use std::env;

/// Read password from an environment variable
///
/// This function reads a password from the specified environment variable.
/// Note: Clearing the environment variable after reading is not reliably
/// possible in Rust due to OS limitations, so users should be aware that
/// the password may remain in the environment.
///
/// # Arguments
/// * `var_name` - The name of the environment variable
///
/// # Returns
/// A SecureString containing the password
pub fn read_password_from_env(var_name: &str) -> Result<SecureString> {
    let password = env::var(var_name)
        .map_err(|_| CryptoError::MissingRequiredArgument(
            format!("Environment variable {} not found", var_name)
        ))?;
    
    if password.is_empty() {
        return Err(CryptoError::InvalidPassword);
    }
    
    // Note: We cannot reliably clear the environment variable across all platforms
    // Users should be aware that the password remains in the environment
    
    Ok(SecureString::from(password))
}

use crate::key_manager::SecureBytes;
use std::fs;

/// Load a raw key from a file
///
/// This function reads raw key bytes from a file. The file should contain
/// the key material in binary format.
///
/// # Arguments
/// * `path` - Path to the key file
///
/// # Returns
/// A SecureBytes containing the key material
pub fn load_key_from_file(path: &PathBuf) -> Result<SecureBytes> {
    let key_bytes = fs::read(path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                CryptoError::FileNotFound(path.clone())
            } else if e.kind() == io::ErrorKind::PermissionDenied {
                CryptoError::PermissionDenied(path.clone())
            } else {
                CryptoError::FileReadError(path.clone(), e)
            }
        })?;
    
    if key_bytes.is_empty() {
        return Err(CryptoError::InvalidKey);
    }
    
    Ok(SecureBytes::from(key_bytes))
}

/// Load a PEM-encoded key from a file
///
/// This function reads a PEM-encoded key file and extracts the key material.
/// It supports both public and private keys in PEM format.
///
/// # Arguments
/// * `path` - Path to the PEM key file
///
/// # Returns
/// A SecureBytes containing the DER-encoded key material
pub fn load_pem_key_from_file(path: &PathBuf) -> Result<SecureBytes> {
    let pem_content = fs::read_to_string(path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                CryptoError::FileNotFound(path.clone())
            } else if e.kind() == io::ErrorKind::PermissionDenied {
                CryptoError::PermissionDenied(path.clone())
            } else {
                CryptoError::FileReadError(path.clone(), e)
            }
        })?;
    
    // Parse PEM format - look for BEGIN/END markers
    let begin_marker = "-----BEGIN";
    let end_marker = "-----END";
    
    let begin_pos = pem_content.find(begin_marker)
        .ok_or(CryptoError::InvalidKey)?;
    let end_pos = pem_content.find(end_marker)
        .ok_or(CryptoError::InvalidKey)?;
    
    // Extract the base64 content between markers
    let first_newline = pem_content[begin_pos..].find('\n')
        .ok_or(CryptoError::InvalidKey)?;
    let base64_start = begin_pos + first_newline + 1;
    
    if base64_start >= end_pos {
        return Err(CryptoError::InvalidKey);
    }
    
    let base64_content = &pem_content[base64_start..end_pos];
    
    // Remove whitespace and decode base64
    let base64_clean: String = base64_content
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    
    // Decode base64
    use base64::{Engine as _, engine::general_purpose};
    let der_bytes = general_purpose::STANDARD
        .decode(base64_clean.as_bytes())
        .map_err(|_| CryptoError::InvalidKey)?;
    
    Ok(SecureBytes::from(der_bytes))
}



/// Display a progress bar for file operations
///
/// # Arguments
/// * `current` - Current number of bytes processed
/// * `total` - Total number of bytes to process
pub fn display_progress(current: u64, total: u64) {
    if total == 0 {
        return;
    }
    
    let percentage = (current as f64 / total as f64 * 100.0) as u32;
    let bar_width = 50;
    let filled = (current as f64 / total as f64 * bar_width as f64) as usize;
    let empty = bar_width - filled;
    
    print!("\r[");
    print!("{}", "=".repeat(filled));
    print!("{}", " ".repeat(empty));
    print!("] {}% ({}/{} bytes)", percentage, current, total);
    
    io::stdout().flush().ok();
    
    if current >= total {
        println!(); // New line when complete
    }
}

/// Display current file being processed in directory operations
///
/// # Arguments
/// * `file_path` - Path to the file being processed
/// * `current` - Current file number
/// * `total` - Total number of files
pub fn display_file_progress(file_path: &PathBuf, current: usize, total: usize) {
    println!("[{}/{}] Processing: {}", current, total, file_path.display());
}

/// Print verbose log message
///
/// # Arguments
/// * `verbose` - Whether verbose mode is enabled
/// * `message` - The message to print
pub fn log_verbose(verbose: bool, message: &str) {
    if verbose {
        println!("[VERBOSE] {}", message);
    }
}

/// Print an error message
///
/// # Arguments
/// * `message` - The error message to print
pub fn print_error(message: &str) {
    eprintln!("Error: {}", message);
}

/// Print a success message
///
/// # Arguments
/// * `message` - The success message to print
pub fn print_success(message: &str) {
    println!("✓ {}", message);
}

/// Print an info message
///
/// # Arguments
/// * `message` - The info message to print
pub fn print_info(message: &str) {
    println!("ℹ {}", message);
}

