// Application orchestrator - coordinates all modules and implements command handlers
// 应用程序协调器 - 协调所有模块并实现命令处理器

use crate::cli::{Command, EncryptArgs, DecryptArgs, KeygenArgs, InfoArgs};
use crate::error::{CryptoError, Result};
use crate::key_manager::{SecureBytes, KdfAlgorithm, AsymmetricAlgorithm};
use crate::file_handler::Algorithm as FileAlgorithm;
use crate::compression::CompressionAlgorithm;
use std::path::Path;

/// Parse algorithm string to FileAlgorithm enum
/// 将算法字符串解析为 FileAlgorithm 枚举
fn parse_algorithm(algo_str: &str) -> Result<FileAlgorithm> {
    match algo_str.to_lowercase().as_str() {
        "aes-256-gcm" | "aes256gcm" => Ok(FileAlgorithm::Aes256Gcm),
        "aes-256-cbc" | "aes256cbc" => Ok(FileAlgorithm::Aes256Cbc),
        "chacha20-poly1305" | "chacha20poly1305" => Ok(FileAlgorithm::ChaCha20Poly1305),
        "rsa-oaep-2048" | "rsa2048" => Ok(FileAlgorithm::RsaOaep2048),
        "rsa-oaep-4096" | "rsa4096" => Ok(FileAlgorithm::RsaOaep4096),
        "ecies-p256" | "ecies" => Ok(FileAlgorithm::EciesP256),
        _ => Err(CryptoError::InvalidArguments(format!("Unknown algorithm: {}", algo_str))),
    }
}

/// Parse compression string to CompressionAlgorithm
/// 将压缩字符串解析为 CompressionAlgorithm
fn parse_compression(comp_str: &str, level: Option<u32>) -> Result<CompressionAlgorithm> {
    match comp_str.to_lowercase().as_str() {
        "gzip" => {
            if let Some(lvl) = level {
                if lvl < 1 || lvl > 9 {
                    return Err(CryptoError::InvalidArguments(
                        "Gzip compression level must be between 1 and 9".to_string()
                    ));
                }
            }
            Ok(CompressionAlgorithm::Gzip)
        }
        "zstd" => {
            if let Some(lvl) = level {
                if lvl < 1 || lvl > 22 {
                    return Err(CryptoError::InvalidArguments(
                        "Zstd compression level must be between 1 and 22".to_string()
                    ));
                }
            }
            Ok(CompressionAlgorithm::Zstd)
        }
        _ => Err(CryptoError::InvalidArguments(format!("Unknown compression algorithm: {}", comp_str))),
    }
}

/// Algorithm type for key generation
/// 密钥生成的算法类型
#[derive(Debug)]
enum KeygenAlgorithm {
    Symmetric(crate::key_manager::Algorithm),
    Asymmetric(AsymmetricAlgorithm),
}

/// Parse keygen algorithm string
/// 解析密钥生成算法字符串
fn parse_keygen_algorithm(algo_str: &str) -> Result<KeygenAlgorithm> {
    use crate::key_manager::Algorithm;
    
    match algo_str.to_lowercase().as_str() {
        "aes-256-gcm" | "aes256gcm" | "aes-256" | "aes256" => {
            Ok(KeygenAlgorithm::Symmetric(Algorithm::Aes256Gcm))
        }
        "aes-256-cbc" | "aes256cbc" => {
            Ok(KeygenAlgorithm::Symmetric(Algorithm::Aes256Cbc))
        }
        "chacha20-poly1305" | "chacha20poly1305" | "chacha20" => {
            Ok(KeygenAlgorithm::Symmetric(Algorithm::ChaCha20Poly1305))
        }
        "rsa-oaep-2048" | "rsa2048" | "rsa-2048" => {
            Ok(KeygenAlgorithm::Asymmetric(AsymmetricAlgorithm::RsaOaep2048))
        }
        "rsa-oaep-4096" | "rsa4096" | "rsa-4096" => {
            Ok(KeygenAlgorithm::Asymmetric(AsymmetricAlgorithm::RsaOaep4096))
        }
        "ecies-p256" | "ecies" | "p256" => {
            Ok(KeygenAlgorithm::Asymmetric(AsymmetricAlgorithm::EciesP256))
        }
        _ => Err(CryptoError::InvalidArguments(format!("Unknown algorithm: {}", algo_str))),
    }
}

/// Application configuration with sensible defaults
/// 具有合理默认值的应用程序配置
#[derive(Debug, Clone)]
pub struct Config {
    /// Default encryption algorithm (AES-256-GCM)
    /// 默认加密算法（AES-256-GCM）
    pub default_algorithm: FileAlgorithm,
    
    /// Default key derivation function (Argon2id)
    /// 默认密钥派生函数（Argon2id）
    pub default_kdf: KdfAlgorithm,
    
    /// Default KDF iterations (100,000)
    /// 默认 KDF 迭代次数（100,000）
    pub kdf_iterations: u32,
    
    /// Buffer size for streaming operations (64KB)
    /// 流式操作的缓冲区大小（64KB）
    pub buffer_size: usize,
    
    /// Number of parallel workers for directory operations
    /// 目录操作的并行工作线程数
    pub parallel_workers: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_algorithm: FileAlgorithm::Aes256Gcm,
            default_kdf: KdfAlgorithm::Argon2id,
            kdf_iterations: 100_000,
            buffer_size: 64 * 1024, // 64KB
            parallel_workers: 4,
        }
    }
}

impl Config {
    /// Create a new Config with default values
    /// 使用默认值创建新的 Config
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Create a Config with custom values
    /// 使用自定义值创建 Config
    pub fn with_values(
        algorithm: FileAlgorithm,
        kdf: KdfAlgorithm,
        iterations: u32,
        buffer_size: usize,
    ) -> Self {
        Self {
            default_algorithm: algorithm,
            default_kdf: kdf,
            kdf_iterations: iterations,
            buffer_size,
            parallel_workers: 4,
        }
    }
}

/// Application structure that holds configuration and orchestrates operations
/// 保存配置并协调操作的应用程序结构
pub struct Application {
    config: Config,
}

impl Application {
    /// Create a new Application with default configuration
    /// 使用默认配置创建新的 Application
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }
    
    /// Create a new Application with custom configuration
    /// 使用自定义配置创建新的 Application
    pub fn with_config(config: Config) -> Self {
        Self { config }
    }
    
    /// Get a reference to the application configuration
    /// 获取应用程序配置的引用
    pub fn config(&self) -> &Config {
        &self.config
    }
    
    /// Execute a command
    /// 执行命令
    pub fn execute(&self, command: Command) -> Result<()> {
        match command {
            Command::Encrypt(args) => self.handle_encrypt(args),
            Command::Decrypt(args) => self.handle_decrypt(args),
            Command::Keygen(args) => self.handle_keygen(args),
            Command::ListAlgorithms => self.handle_list_algorithms(),
            Command::Info(args) => self.handle_info(args),
        }
    }
    
    /// Handle the encrypt command
    /// 处理加密命令
    fn handle_encrypt(&self, args: EncryptArgs) -> Result<()> {
        use crate::cli;
        
        // Log verbose information
        cli::log_verbose(args.verbose, "Starting encryption operation");
        
        // Parse algorithm from string
        let algorithm = parse_algorithm(&args.algorithm)?;
        cli::log_verbose(args.verbose, &format!("Using algorithm: {:?}", algorithm));
        
        // Obtain key from specified source
        let (key, kdf_params) = self.obtain_key_for_encryption(&args)?;
        cli::log_verbose(args.verbose, "Key obtained successfully");
        
        // Parse compression if specified
        let compression = if let Some(comp_str) = &args.compress {
            Some(parse_compression(comp_str, args.compression_level)?)
        } else {
            None
        };
        
        if let Some(comp) = compression {
            cli::log_verbose(args.verbose, &format!("Using compression: {:?}", comp));
        }
        
        // Determine output path
        let output_path = args.output.clone().unwrap_or_else(|| {
            let mut path = args.input.clone();
            path.set_extension("enc");
            path
        });
        
        cli::log_verbose(args.verbose, &format!("Input: {}", args.input.display()));
        cli::log_verbose(args.verbose, &format!("Output: {}", output_path.display()));
        
        // Determine if input is file or directory
        if args.input.is_file() {
            // Encrypt single file
            cli::log_verbose(args.verbose, "Encrypting file...");
            self.encrypt_file(&args.input, &output_path, &key, algorithm, compression, kdf_params)?;
            cli::print_success(&format!("File encrypted successfully: {}", output_path.display()));
        } else if args.input.is_dir() {
            // Encrypt directory
            if !args.recursive {
                return Err(CryptoError::InvalidArguments(
                    format!(
                        "The input path '{}' is a directory. Use --recursive (or -r) flag to encrypt directories.\n\
                        Example: crypto-cli-tool encrypt -i {} --recursive",
                        args.input.display(),
                        args.input.display()
                    )
                ));
            }
            cli::log_verbose(args.verbose, "Encrypting directory...");
            self.encrypt_directory(&args.input, &output_path, &key, algorithm, compression, kdf_params)?;
            cli::print_success(&format!("Directory encrypted successfully: {}", output_path.display()));
        } else {
            return Err(CryptoError::FileNotFound(args.input.clone()));
        }
        
        Ok(())
    }
    
    /// Obtain encryption key from the specified source
    /// 从指定来源获取加密密钥
    /// Returns (key, optional_kdf_params)
    /// 返回 (密钥, 可选的_kdf_参数)
    fn obtain_key_for_encryption(&self, args: &EncryptArgs) -> Result<(SecureBytes, Option<(KdfAlgorithm, u32, Vec<u8>)>)> {
        use crate::cli;
        use crate::key_manager;
        
        match args.key_source.as_str() {
            "password" => {
                // Prompt for password with confirmation
                let password = cli::prompt_password_with_confirmation(
                    "Enter password: ",
                    "Confirm password: "
                )?;
                
                // Generate salt
                let salt = key_manager::generate_salt()?;
                
                // Derive key using configured KDF
                let key = match self.config.default_kdf {
                    KdfAlgorithm::Pbkdf2Sha256 => {
                        key_manager::derive_key_pbkdf2(
                            &password,
                            &salt,
                            self.config.kdf_iterations,
                            32, // 256 bits
                        )?
                    }
                    KdfAlgorithm::Argon2id => {
                        key_manager::derive_key_argon2id(
                            &password,
                            &salt,
                            19456, // 19 MiB memory
                            2,     // 2 iterations
                            32,    // 256 bits
                        )?
                    }
                };
                
                let kdf_params = (self.config.default_kdf, self.config.kdf_iterations, salt.to_vec());
                Ok((key, Some(kdf_params)))
            }
            "env" => {
                // Read password from environment variable
                let var_name = args.password_env.as_ref()
                    .ok_or_else(|| CryptoError::MissingRequiredArgument(
                        "--password-env required when using key-source=env".to_string()
                    ))?;
                
                let password = cli::read_password_from_env(var_name)?;
                
                // Generate salt
                let salt = key_manager::generate_salt()?;
                
                // Derive key
                let key = match self.config.default_kdf {
                    KdfAlgorithm::Pbkdf2Sha256 => {
                        key_manager::derive_key_pbkdf2(
                            &password,
                            &salt,
                            self.config.kdf_iterations,
                            32,
                        )?
                    }
                    KdfAlgorithm::Argon2id => {
                        key_manager::derive_key_argon2id(
                            &password,
                            &salt,
                            19456,
                            2,
                            32,
                        )?
                    }
                };
                
                let kdf_params = (self.config.default_kdf, self.config.kdf_iterations, salt.to_vec());
                Ok((key, Some(kdf_params)))
            }
            "keyfile" => {
                // Load key from file
                let keyfile_path = args.keyfile.as_ref()
                    .ok_or_else(|| CryptoError::MissingRequiredArgument(
                        "--keyfile required when using key-source=keyfile".to_string()
                    ))?;
                
                let key = cli::load_key_from_file(keyfile_path)?;
                
                // Validate key size (must be 32 bytes for symmetric algorithms)
                if key.len() != 32 {
                    return Err(CryptoError::InvalidKey);
                }
                
                Ok((key, None))
            }
            _ => Err(CryptoError::InvalidArguments(
                format!("Unknown key source: {}", args.key_source)
            )),
        }
    }
    
    /// Encrypt a single file
    /// 加密单个文件
    fn encrypt_file(
        &self,
        input_path: &Path,
        output_path: &Path,
        key: &SecureBytes,
        algorithm: FileAlgorithm,
        compression: Option<CompressionAlgorithm>,
        kdf_params: Option<(KdfAlgorithm, u32, Vec<u8>)>,
    ) -> Result<()> {
        use crate::file_handler;
        
        file_handler::encrypt_file(
            input_path,
            output_path,
            key,
            algorithm,
            compression,
            kdf_params,
        )
    }
    
    /// Encrypt a directory
    /// 加密目录
    fn encrypt_directory(
        &self,
        input_path: &Path,
        output_path: &Path,
        key: &SecureBytes,
        algorithm: FileAlgorithm,
        compression: Option<CompressionAlgorithm>,
        kdf_params: Option<(KdfAlgorithm, u32, Vec<u8>)>,
    ) -> Result<()> {
        use crate::archive;
        use crate::file_handler;
        
        // Create archive from directory
        let archive_data = archive::create_archive(input_path)?;
        
        // Write archive to temporary file
        let temp_archive_path = std::env::temp_dir().join("crypto_cli_archive.tmp");
        std::fs::write(&temp_archive_path, &archive_data)
            .map_err(|e| CryptoError::FileWriteError(temp_archive_path.clone(), e))?;
        
        // Encrypt the archive file
        let result = file_handler::encrypt_file(
            &temp_archive_path,
            output_path,
            key,
            algorithm,
            compression,
            kdf_params,
        );
        
        // Clean up temporary file
        let _ = std::fs::remove_file(&temp_archive_path);
        
        result
    }
    
    /// Handle the decrypt command
    /// 处理解密命令
    fn handle_decrypt(&self, args: DecryptArgs) -> Result<()> {
        use crate::cli;
        use crate::file_handler;
        
        // Log verbose information
        cli::log_verbose(args.verbose, "Starting decryption operation");
        
        // Read encrypted file header to determine type
        let input_file = std::fs::File::open(&args.input)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    CryptoError::FileNotFound(args.input.clone())
                } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                    CryptoError::PermissionDenied(args.input.clone())
                } else {
                    CryptoError::FileReadError(args.input.clone(), e)
                }
            })?;
        
        let mut reader = std::io::BufReader::new(input_file);
        let header = file_handler::EncryptedFileHeader::read_from(&mut reader)?;
        
        cli::log_verbose(args.verbose, &format!("Algorithm: {:?}", header.algorithm));
        cli::log_verbose(args.verbose, &format!("Compressed: {}", header.compressed));
        
        // Obtain key from specified source
        let key = self.obtain_key_for_decryption(&args, &header)?;
        cli::log_verbose(args.verbose, "Key obtained successfully");
        
        // Determine output path
        let output_path = args.output.clone().unwrap_or_else(|| {
            let mut path = args.input.clone();
            // Remove .enc extension if present
            if let Some(ext) = path.extension() {
                if ext == "enc" {
                    path.set_extension("");
                } else {
                    path.set_extension(format!("{}.dec", ext.to_string_lossy()));
                }
            } else {
                path.set_extension("dec");
            }
            path
        });
        
        cli::log_verbose(args.verbose, &format!("Input: {}", args.input.display()));
        cli::log_verbose(args.verbose, &format!("Output: {}", output_path.display()));
        
        // Check if this is a directory archive by trying to detect archive magic
        // We'll decrypt first, then check if it's an archive
        let temp_decrypted = std::env::temp_dir().join("crypto_cli_decrypted.tmp");
        
        cli::log_verbose(args.verbose, "Decrypting file...");
        file_handler::decrypt_file(&args.input, &temp_decrypted, &key)?;
        
        // Try to read as archive
        let decrypted_data = std::fs::read(&temp_decrypted)
            .map_err(|e| CryptoError::FileReadError(temp_decrypted.clone(), e))?;
        
        let is_archive = decrypted_data.len() >= 6 && &decrypted_data[0..6] == b"CRYTAR";
        
        if is_archive {
            cli::log_verbose(args.verbose, "Detected directory archive, extracting...");
            
            // Extract archive to output directory
            use crate::archive;
            archive::extract_archive(&decrypted_data, &output_path)?;
            
            cli::print_success(&format!("Directory decrypted successfully: {}", output_path.display()));
        } else {
            // It's a regular file, just move the temp file to output
            std::fs::rename(&temp_decrypted, &output_path)
                .map_err(|e| CryptoError::FileWriteError(output_path.clone(), e))?;
            
            cli::print_success(&format!("File decrypted successfully: {}", output_path.display()));
        }
        
        // Clean up temp file if it still exists
        let _ = std::fs::remove_file(&temp_decrypted);
        
        Ok(())
    }
    
    /// Obtain decryption key from the specified source
    /// 从指定来源获取解密密钥
    fn obtain_key_for_decryption(
        &self,
        args: &DecryptArgs,
        header: &crate::file_handler::EncryptedFileHeader,
    ) -> Result<SecureBytes> {
        use crate::cli;
        use crate::key_manager;
        
        match args.key_source.as_str() {
            "password" => {
                // Prompt for password
                let password = cli::prompt_password("Enter password: ")?;
                
                // Check if KDF was used
                if let (Some(kdf), Some(iterations), Some(salt)) = 
                    (header.kdf, header.kdf_iterations, &header.salt) {
                    // Derive key using same KDF parameters
                    let key = match kdf {
                        KdfAlgorithm::Pbkdf2Sha256 => {
                            key_manager::derive_key_pbkdf2(
                                &password,
                                salt,
                                iterations,
                                32,
                            )?
                        }
                        KdfAlgorithm::Argon2id => {
                            key_manager::derive_key_argon2id(
                                &password,
                                salt,
                                19456,
                                2,
                                32,
                            )?
                        }
                    };
                    Ok(key)
                } else {
                    Err(CryptoError::InvalidArguments(
                        "File was not encrypted with password-based encryption".to_string()
                    ))
                }
            }
            "env" => {
                // Read password from environment variable
                let var_name = args.password_env.as_ref()
                    .ok_or_else(|| CryptoError::MissingRequiredArgument(
                        "--password-env required when using key-source=env".to_string()
                    ))?;
                
                let password = cli::read_password_from_env(var_name)?;
                
                // Check if KDF was used
                if let (Some(kdf), Some(iterations), Some(salt)) = 
                    (header.kdf, header.kdf_iterations, &header.salt) {
                    // Derive key using same KDF parameters
                    let key = match kdf {
                        KdfAlgorithm::Pbkdf2Sha256 => {
                            key_manager::derive_key_pbkdf2(
                                &password,
                                salt,
                                iterations,
                                32,
                            )?
                        }
                        KdfAlgorithm::Argon2id => {
                            key_manager::derive_key_argon2id(
                                &password,
                                salt,
                                19456,
                                2,
                                32,
                            )?
                        }
                    };
                    Ok(key)
                } else {
                    Err(CryptoError::InvalidArguments(
                        "File was not encrypted with password-based encryption".to_string()
                    ))
                }
            }
            "keyfile" => {
                // Load key from file
                let keyfile_path = args.keyfile.as_ref()
                    .ok_or_else(|| CryptoError::MissingRequiredArgument(
                        "--keyfile required when using key-source=keyfile".to_string()
                    ))?;
                
                let key = cli::load_key_from_file(keyfile_path)?;
                
                // Validate key size
                if key.len() != 32 {
                    return Err(CryptoError::InvalidKey);
                }
                
                Ok(key)
            }
            _ => Err(CryptoError::InvalidArguments(
                format!("Unknown key source: {}", args.key_source)
            )),
        }
    }
    
    /// Handle the keygen command
    /// 处理密钥生成命令
    fn handle_keygen(&self, args: KeygenArgs) -> Result<()> {
        use crate::cli;
        use crate::key_manager;
        
        cli::log_verbose(args.verbose, "Starting key generation");
        
        // Parse algorithm
        let algorithm = parse_keygen_algorithm(&args.algorithm)?;
        cli::log_verbose(args.verbose, &format!("Generating keys for: {:?}", algorithm));
        
        match algorithm {
            KeygenAlgorithm::Symmetric(sym_algo) => {
                // Generate symmetric key
                let key = key_manager::generate_symmetric_key(sym_algo)?;
                
                // Write key to file
                let key_path = &args.output;
                
                match args.format.as_str() {
                    "raw" => {
                        std::fs::write(key_path, key.as_ref())
                            .map_err(|e| CryptoError::FileWriteError(key_path.clone(), e))?;
                        
                        cli::print_success(&format!("Symmetric key generated: {}", key_path.display()));
                        cli::print_info("⚠ Keep this key file secure!");
                    }
                    "pem" => {
                        return Err(CryptoError::InvalidArguments(
                            "PEM format not supported for symmetric keys, use 'raw'".to_string()
                        ));
                    }
                    _ => {
                        return Err(CryptoError::InvalidArguments(
                            format!("Unknown format: {}", args.format)
                        ));
                    }
                }
            }
            KeygenAlgorithm::Asymmetric(asym_algo) => {
                // Generate asymmetric key pair
                let key_pair = key_manager::generate_key_pair(asym_algo)?;
                
                // Determine output paths
                let private_key_path = &args.output;
                let public_key_path = {
                    let mut path = args.output.clone();
                    let filename = path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("key");
                    path.set_file_name(format!("{}.pub", filename));
                    path
                };
                
                match args.format.as_str() {
                    "pem" => {
                        // Write private key in PEM format
                        let private_pem = format!(
                            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_pair.private_key.as_ref())
                        );
                        std::fs::write(private_key_path, private_pem)
                            .map_err(|e| CryptoError::FileWriteError(private_key_path.clone(), e))?;
                        
                        // Write public key in PEM format
                        let public_pem = format!(
                            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key_pair.public_key)
                        );
                        std::fs::write(&public_key_path, public_pem)
                            .map_err(|e| CryptoError::FileWriteError(public_key_path.clone(), e))?;
                        
                        cli::print_success(&format!("Key pair generated:"));
                        cli::print_info(&format!("  Private key: {}", private_key_path.display()));
                        cli::print_info(&format!("  Public key: {}", public_key_path.display()));
                        cli::print_info("⚠ Keep the private key secure!");
                    }
                    "raw" => {
                        // Write keys in raw DER format
                        std::fs::write(private_key_path, key_pair.private_key.as_ref())
                            .map_err(|e| CryptoError::FileWriteError(private_key_path.clone(), e))?;
                        
                        std::fs::write(&public_key_path, &key_pair.public_key)
                            .map_err(|e| CryptoError::FileWriteError(public_key_path.clone(), e))?;
                        
                        cli::print_success(&format!("Key pair generated:"));
                        cli::print_info(&format!("  Private key: {}", private_key_path.display()));
                        cli::print_info(&format!("  Public key: {}", public_key_path.display()));
                        cli::print_info("⚠ Keep the private key secure!");
                    }
                    _ => {
                        return Err(CryptoError::InvalidArguments(
                            format!("Unknown format: {}", args.format)
                        ));
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle the list-algorithms command
    /// 处理列出算法命令
    fn handle_list_algorithms(&self) -> Result<()> {
        println!("\n=== Supported Encryption Algorithms ===\n");
        
        println!("Symmetric Algorithms (AEAD):");
        println!("  • AES-256-GCM");
        println!("    - Key size: 256 bits");
        println!("    - Security: High");
        println!("    - AEAD: Yes (Authenticated Encryption with Associated Data)");
        println!("    - Recommendation: Recommended for most use cases");
        println!("    - Usage: --algorithm aes-256-gcm\n");
        
        println!("  • ChaCha20-Poly1305");
        println!("    - Key size: 256 bits");
        println!("    - Security: High");
        println!("    - AEAD: Yes");
        println!("    - Recommendation: Recommended, especially for mobile/embedded");
        println!("    - Usage: --algorithm chacha20-poly1305\n");
        
        println!("Symmetric Algorithms (Non-AEAD):");
        println!("  • AES-256-CBC (with HMAC-SHA256)");
        println!("    - Key size: 256 bits");
        println!("    - Security: High");
        println!("    - AEAD: No (uses Encrypt-then-MAC)");
        println!("    - Recommendation: Use only for compatibility");
        println!("    - Usage: --algorithm aes-256-cbc\n");
        
        println!("Asymmetric Algorithms:");
        println!("  • RSA-OAEP-2048");
        println!("    - Key size: 2048 bits");
        println!("    - Security: Medium-High");
        println!("    - AEAD: N/A (uses hybrid encryption with AES-256-GCM)");
        println!("    - Recommendation: Minimum for new applications");
        println!("    - Usage: --algorithm rsa-oaep-2048\n");
        
        println!("  • RSA-OAEP-4096");
        println!("    - Key size: 4096 bits");
        println!("    - Security: Very High");
        println!("    - AEAD: N/A (uses hybrid encryption with AES-256-GCM)");
        println!("    - Recommendation: Recommended for long-term security");
        println!("    - Usage: --algorithm rsa-oaep-4096\n");
        
        println!("  • ECIES-P256");
        println!("    - Curve: NIST P-256");
        println!("    - Security: High");
        println!("    - AEAD: N/A (uses hybrid encryption with AES-256-GCM)");
        println!("    - Recommendation: Recommended for efficiency");
        println!("    - Usage: --algorithm ecies-p256\n");
        
        println!("=== Key Derivation Functions ===\n");
        println!("  • Argon2id (default)");
        println!("    - Memory-hard, resistant to GPU/ASIC attacks");
        println!("    - Recommendation: Recommended for password-based encryption\n");
        
        println!("  • PBKDF2-SHA256");
        println!("    - Standard KDF, widely supported");
        println!("    - Recommendation: Use only for compatibility\n");
        
        println!("=== Compression Algorithms ===\n");
        println!("  • Gzip (levels 1-9)");
        println!("    - Standard compression, good compatibility");
        println!("    - Usage: --compress gzip --compression-level 6\n");
        
        println!("  • Zstd (levels 1-22)");
        println!("    - Modern compression, better ratio and speed");
        println!("    - Recommendation: Recommended");
        println!("    - Usage: --compress zstd --compression-level 3\n");
        
        println!("=== General Recommendations ===\n");
        println!("  • For files: Use AES-256-GCM with password-based encryption");
        println!("  • For directories: Use AES-256-GCM with Zstd compression");
        println!("  • For public-key encryption: Use ECIES-P256 or RSA-OAEP-4096");
        println!("  • Always use strong, unique passwords (12+ characters)");
        println!("  • Store keys securely and never share private keys\n");
        
        Ok(())
    }
    
    /// Handle the info command
    /// 处理信息命令
    fn handle_info(&self, args: InfoArgs) -> Result<()> {
        use crate::cli;
        use crate::file_handler;
        
        cli::log_verbose(args.verbose, "Reading encrypted file header");
        
        // Open and read the encrypted file header
        let input_file = std::fs::File::open(&args.input)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    CryptoError::FileNotFound(args.input.clone())
                } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                    CryptoError::PermissionDenied(args.input.clone())
                } else {
                    CryptoError::FileReadError(args.input.clone(), e)
                }
            })?;
        
        let mut reader = std::io::BufReader::new(input_file);
        let header = file_handler::EncryptedFileHeader::read_from(&mut reader)?;
        
        // Display file information
        println!("\n=== Encrypted File Information ===\n");
        println!("File: {}", args.input.display());
        println!("Format Version: {}", header.version);
        
        // Display algorithm
        let algo_name = match header.algorithm {
            FileAlgorithm::Aes256Gcm => "AES-256-GCM",
            FileAlgorithm::Aes256Cbc => "AES-256-CBC (with HMAC-SHA256)",
            FileAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            FileAlgorithm::RsaOaep2048 => "RSA-OAEP-2048 (hybrid)",
            FileAlgorithm::RsaOaep4096 => "RSA-OAEP-4096 (hybrid)",
            FileAlgorithm::EciesP256 => "ECIES-P256 (hybrid)",
        };
        println!("Algorithm: {}", algo_name);
        
        // Display AEAD support
        let is_aead = matches!(
            header.algorithm,
            FileAlgorithm::Aes256Gcm | FileAlgorithm::ChaCha20Poly1305
        );
        println!("AEAD: {}", if is_aead { "Yes" } else { "No" });
        
        // Display KDF information
        if let Some(kdf) = header.kdf {
            let kdf_name = match kdf {
                KdfAlgorithm::Pbkdf2Sha256 => "PBKDF2-SHA256",
                KdfAlgorithm::Argon2id => "Argon2id",
            };
            println!("Key Derivation: {}", kdf_name);
            
            if let Some(iterations) = header.kdf_iterations {
                println!("KDF Iterations: {}", iterations);
            }
            
            if let Some(salt) = &header.salt {
                println!("Salt Length: {} bytes", salt.len());
            }
        } else {
            println!("Key Derivation: None (raw key used)");
        }
        
        // Display IV information
        println!("IV/Nonce Length: {} bytes", header.iv.len());
        
        // Display compression information
        if header.compressed {
            let comp_name = match header.compression_algo {
                Some(CompressionAlgorithm::Gzip) => "Gzip",
                Some(CompressionAlgorithm::Zstd) => "Zstd",
                None => "Unknown",
            };
            println!("Compression: {} (enabled)", comp_name);
        } else {
            println!("Compression: None");
        }
        
        // Display original size
        println!("Original Size: {} bytes", header.original_size);
        
        // Display metadata if present
        if !header.metadata.is_empty() {
            println!("Metadata Length: {} bytes", header.metadata.len());
            
            if args.verbose {
                // Try to parse metadata as JSON
                if let Ok(metadata_str) = String::from_utf8(header.metadata.clone()) {
                    println!("Metadata Content:");
                    println!("{}", metadata_str);
                }
            }
        } else {
            println!("Metadata: None");
        }
        
        println!();
        
        Ok(())
    }
}

