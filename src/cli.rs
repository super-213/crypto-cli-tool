// CLI module - command-line interface and argument parsing
// CLI 模块 - 命令行接口和参数解析

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use crate::i18n;

/// Cryptographic CLI Tool - Encrypt and decrypt files and directories
/// 加密 CLI 工具 - 加密和解密文件及目录
#[derive(Parser, Debug)]
#[command(name = "crypto-cli-tool")]
#[command(author, version, about, long_about = None)]
#[command(arg_required_else_help = true)]
pub struct Cli {
    /// Output language (en or zh)
    /// 输出语言（en 或 zh）
    #[arg(long, short = 'l', value_name = "LANG", default_value = "en", global = true, allow_hyphen_values = true)]
    pub language: String,

    /// Start interactive encryption/decryption wizard
    /// 启动交互式加密/解密向导
    #[arg(short = 'w', long, global = true)]
    pub wizard: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Available subcommands
/// 可用的子命令
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Encrypt a file or directory
    /// 加密文件或目录
    #[command(aliases = ["e", "enc"])]
    Encrypt(EncryptArgs),
    
    /// Decrypt a file or directory
    /// 解密文件或目录
    #[command(aliases = ["d", "dec"])]
    Decrypt(DecryptArgs),
    
    /// Generate cryptographic keys
    /// 生成加密密钥
    #[command(aliases = ["k", "kg"])]
    Keygen(KeygenArgs),
    
    /// List all supported encryption algorithms
    /// 列出所有支持的加密算法
    #[command(aliases = ["ls", "list", "algos"])]
    ListAlgorithms,
    
    /// Display information about an encrypted file
    /// 显示加密文件的信息
    #[command(aliases = ["i"])]
    Info(InfoArgs),

    /// Start interactive encryption/decryption wizard
    /// 启动交互式加密/解密向导
    Wizard,
}

/// Arguments for the encrypt command
/// 加密命令的参数
#[derive(Parser, Debug)]
pub struct EncryptArgs {
    /// Input file or directory to encrypt
    /// 要加密的输入文件或目录
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,
    
    /// Output file or directory (defaults to input + .enc)
    /// 输出文件或目录（默认为输入文件名 + .enc）
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    
    /// Encryption algorithm to use
    /// 使用的加密算法
    #[arg(short, long, value_name = "ALGORITHM", default_value = "aes-256-gcm")]
    pub algorithm: String,
    
    /// Key source: password, env, or keyfile
    /// 密钥来源：password（密码）、env（环境变量）或 keyfile（密钥文件）
    #[arg(short, long, value_name = "SOURCE", default_value = "password")]
    pub key_source: String,
    
    /// Environment variable name for password (when key-source=env)
    /// 密码的环境变量名（当 key-source=env 时）
    #[arg(long, short = 'p', value_name = "VAR", alias = "pass-env")]
    pub password_env: Option<String>,
    
    /// Key file path (when key-source=keyfile)
    /// 密钥文件路径（当 key-source=keyfile 时）
    #[arg(long, value_name = "FILE")]
    pub keyfile: Option<PathBuf>,
    
    /// Compression algorithm (gzip or zstd)
    /// 压缩算法（gzip 或 zstd）
    #[arg(short, long, value_name = "ALGORITHM")]
    pub compress: Option<String>,
    
    /// Compression level (1-9 for gzip, 1-22 for zstd)
    /// 压缩级别（gzip: 1-9，zstd: 1-22）
    #[arg(long, value_name = "LEVEL")]
    pub compression_level: Option<u32>,
    
    /// Recursively encrypt directories
    /// 递归加密目录
    #[arg(short, long)]
    pub recursive: bool,
    
    /// Verbose output
    /// 详细输出
    #[arg(short, long)]
    pub verbose: bool,
}

/// Arguments for the decrypt command
/// 解密命令的参数
#[derive(Parser, Debug)]
pub struct DecryptArgs {
    /// Input encrypted file or directory
    /// 输入的加密文件或目录
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,
    
    /// Output file or directory (defaults to input without .enc)
    /// 输出文件或目录（默认为移除 .enc 扩展名的输入文件名）
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    
    /// Key source: password, env, or keyfile
    /// 密钥来源：password（密码）、env（环境变量）或 keyfile（密钥文件）
    #[arg(short, long, value_name = "SOURCE", default_value = "password")]
    pub key_source: String,
    
    /// Environment variable name for password (when key-source=env)
    /// 密码的环境变量名（当 key-source=env 时）
    #[arg(long, short = 'p', value_name = "VAR", alias = "pass-env")]
    pub password_env: Option<String>,
    
    /// Key file path (when key-source=keyfile)
    /// 密钥文件路径（当 key-source=keyfile 时）
    #[arg(long, value_name = "FILE")]
    pub keyfile: Option<PathBuf>,
    
    /// Verbose output
    /// 详细输出
    #[arg(short, long)]
    pub verbose: bool,
}

/// Arguments for the keygen command
/// 密钥生成命令的参数
#[derive(Parser, Debug)]
pub struct KeygenArgs {
    /// Algorithm to generate keys for
    /// 要生成密钥的算法
    #[arg(short, long, value_name = "ALGORITHM")]
    pub algorithm: String,
    
    /// Output file for the key (or key pair)
    /// 密钥（或密钥对）的输出文件
    #[arg(short, long, value_name = "FILE")]
    pub output: PathBuf,
    
    /// Export format (raw or pem)
    /// 导出格式（raw 或 pem）
    #[arg(short, long, value_name = "FORMAT", default_value = "pem")]
    pub format: String,
    
    /// Verbose output
    /// 详细输出
    #[arg(short, long)]
    pub verbose: bool,
}

/// Arguments for the info command
/// 信息命令的参数
#[derive(Parser, Debug)]
pub struct InfoArgs {
    /// Encrypted file to inspect
    /// 要检查的加密文件
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,
    
    /// Verbose output
    /// 详细输出
    #[arg(short, long)]
    pub verbose: bool,
}

/// Parse command-line arguments
/// 解析命令行参数
pub fn parse_args() -> Cli {
    Cli::parse()
}

use crate::key_manager::SecureString;
use crate::error::{CryptoError, Result};
use std::io::{self, Write};

/// Prompt the user for a password securely
/// 安全地提示用户输入密码
///
/// The password is hidden from terminal display and returned as a SecureString
/// that will be zeroed when dropped.
/// 密码在终端显示中被隐藏，并作为 SecureString 返回，在销毁时会被清零。
///
/// # Arguments / 参数
/// * `prompt` - The prompt message to display / 要显示的提示消息
///
/// # Returns / 返回值
/// A SecureString containing the password / 包含密码的 SecureString
pub fn prompt_password(prompt: &str) -> Result<SecureString> {
    print!("{}", prompt);
    io::stdout().flush()
        .map_err(|e| {
            let msg = if i18n::is_zh() {
                format!("刷新标准输出失败：{}", e)
            } else {
                format!("Failed to flush stdout: {}", e)
            };
            CryptoError::SystemError(msg)
        })?;
    
    let password = rpassword::read_password()
        .map_err(|e| {
            let msg = if i18n::is_zh() {
                format!("读取密码失败：{}", e)
            } else {
                format!("Failed to read password: {}", e)
            };
            CryptoError::SystemError(msg)
        })?;
    
    Ok(SecureString::from(password))
}

/// Prompt the user for a password with confirmation
/// 提示用户输入密码并确认
///
/// This is used for encryption operations to ensure the user didn't mistype.
/// The password is hidden from terminal display.
/// 用于加密操作，以确保用户没有输入错误。密码在终端显示中被隐藏。
///
/// # Arguments / 参数
/// * `prompt` - The initial prompt message / 初始提示消息
/// * `confirm_prompt` - The confirmation prompt message / 确认提示消息
///
/// # Returns / 返回值
/// A SecureString containing the password if both entries match / 如果两次输入匹配，返回包含密码的 SecureString
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
/// 从环境变量读取密码
///
/// This function reads a password from the specified environment variable.
/// Note: Clearing the environment variable after reading is not reliably
/// possible in Rust due to OS limitations, so users should be aware that
/// the password may remain in the environment.
/// 此函数从指定的环境变量读取密码。
/// 注意：由于操作系统限制，在 Rust 中无法可靠地清除读取后的环境变量，
/// 因此用户应该知道密码可能会保留在环境中。
///
/// # Arguments / 参数
/// * `var_name` - The name of the environment variable / 环境变量的名称
///
/// # Returns / 返回值
/// A SecureString containing the password / 包含密码的 SecureString
pub fn read_password_from_env(var_name: &str) -> Result<SecureString> {
    let password = env::var(var_name)
        .map_err(|_| {
            let msg = if i18n::is_zh() {
                format!("未找到环境变量 {}", var_name)
            } else {
                format!("Environment variable {} not found", var_name)
            };
            CryptoError::MissingRequiredArgument(msg)
        })?;
    
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
/// 从文件加载原始密钥
///
/// This function reads raw key bytes from a file. The file should contain
/// the key material in binary format.
/// 此函数从文件读取原始密钥字节。文件应包含二进制格式的密钥材料。
///
/// # Arguments / 参数
/// * `path` - Path to the key file / 密钥文件的路径
///
/// # Returns / 返回值
/// A SecureBytes containing the key material / 包含密钥材料的 SecureBytes
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
/// 从文件加载 PEM 编码的密钥
///
/// This function reads a PEM-encoded key file and extracts the key material.
/// It supports both public and private keys in PEM format.
/// 此函数读取 PEM 编码的密钥文件并提取密钥材料。
/// 它支持 PEM 格式的公钥和私钥。
///
/// # Arguments / 参数
/// * `path` - Path to the PEM key file / PEM 密钥文件的路径
///
/// # Returns / 返回值
/// A SecureBytes containing the DER-encoded key material / 包含 DER 编码密钥材料的 SecureBytes
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
/// 显示文件操作的进度条
///
/// # Arguments / 参数
/// * `current` - Current number of bytes processed / 已处理的字节数
/// * `total` - Total number of bytes to process / 要处理的总字节数
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
    let unit = i18n::t("bytes", "字节");
    print!("] {}% ({}/{} {})", percentage, current, total, unit);
    
    io::stdout().flush().ok();
    
    if current >= total {
        println!(); // New line when complete
    }
}

/// Display current file being processed in directory operations
/// 显示目录操作中正在处理的当前文件
///
/// # Arguments / 参数
/// * `file_path` - Path to the file being processed / 正在处理的文件路径
/// * `current` - Current file number / 当前文件编号
/// * `total` - Total number of files / 文件总数
pub fn display_file_progress(file_path: &PathBuf, current: usize, total: usize) {
    let label = i18n::t("Processing", "正在处理");
    println!("[{}/{}] {}: {}", current, total, label, file_path.display());
}

/// Print verbose log message
/// 打印详细日志消息
///
/// # Arguments / 参数
/// * `verbose` - Whether verbose mode is enabled / 是否启用详细模式
/// * `message` - The message to print / 要打印的消息
pub fn log_verbose(verbose: bool, message: &str) {
    if verbose {
        let prefix = i18n::t("VERBOSE", "详细");
        println!("[{}] {}", prefix, message);
    }
}

/// Print an error message
/// 打印错误消息
///
/// # Arguments / 参数
/// * `message` - The error message to print / 要打印的错误消息
pub fn print_error(message: &str) {
    let label = i18n::t("Error", "错误");
    eprintln!("{}: {}", label, message);
}

/// Print a success message
/// 打印成功消息
///
/// # Arguments / 参数
/// * `message` - The success message to print / 要打印的成功消息
pub fn print_success(message: &str) {
    println!("✓ {}", message);
}

/// Print an info message
/// 打印信息消息
///
/// # Arguments / 参数
/// * `message` - The info message to print / 要打印的信息消息
pub fn print_info(message: &str) {
    println!("ℹ {}", message);
}
