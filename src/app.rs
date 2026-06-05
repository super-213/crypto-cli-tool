// Application orchestrator - coordinates all modules and implements command handlers
// 应用程序协调器 - 协调所有模块并实现命令处理器

use crate::cli::{Command, DecryptArgs, EncryptArgs, InfoArgs, KeygenArgs};
use crate::compression::CompressionAlgorithm;
use crate::error::{CryptoError, Result};
use crate::file_handler::Algorithm as FileAlgorithm;
use crate::i18n;
use crate::key_manager::{AsymmetricAlgorithm, KdfAlgorithm, SecureBytes};
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
        _ => {
            let msg = if i18n::is_zh() {
                format!("未知算法：{}", algo_str)
            } else {
                format!("Unknown algorithm: {}", algo_str)
            };
            Err(CryptoError::InvalidArguments(msg))
        }
    }
}

/// Parse compression string to CompressionAlgorithm
/// 将压缩字符串解析为 CompressionAlgorithm
fn parse_compression(comp_str: &str, level: Option<u32>) -> Result<CompressionAlgorithm> {
    match comp_str.to_lowercase().as_str() {
        "gzip" => {
            if let Some(lvl) = level {
                if lvl < 1 || lvl > 9 {
                    let msg = if i18n::is_zh() {
                        "Gzip 压缩级别必须在 1 到 9 之间".to_string()
                    } else {
                        "Gzip compression level must be between 1 and 9".to_string()
                    };
                    return Err(CryptoError::InvalidArguments(msg));
                }
            }
            Ok(CompressionAlgorithm::Gzip)
        }
        "zstd" => {
            if let Some(lvl) = level {
                if lvl < 1 || lvl > 22 {
                    let msg = if i18n::is_zh() {
                        "Zstd 压缩级别必须在 1 到 22 之间".to_string()
                    } else {
                        "Zstd compression level must be between 1 and 22".to_string()
                    };
                    return Err(CryptoError::InvalidArguments(msg));
                }
            }
            Ok(CompressionAlgorithm::Zstd)
        }
        _ => {
            let msg = if i18n::is_zh() {
                format!("未知压缩算法：{}", comp_str)
            } else {
                format!("Unknown compression algorithm: {}", comp_str)
            };
            Err(CryptoError::InvalidArguments(msg))
        }
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
        "aes-256-cbc" | "aes256cbc" => Ok(KeygenAlgorithm::Symmetric(Algorithm::Aes256Cbc)),
        "chacha20-poly1305" | "chacha20poly1305" | "chacha20" => {
            Ok(KeygenAlgorithm::Symmetric(Algorithm::ChaCha20Poly1305))
        }
        "rsa-oaep-2048" | "rsa2048" | "rsa-2048" => Ok(KeygenAlgorithm::Asymmetric(
            AsymmetricAlgorithm::RsaOaep2048,
        )),
        "rsa-oaep-4096" | "rsa4096" | "rsa-4096" => Ok(KeygenAlgorithm::Asymmetric(
            AsymmetricAlgorithm::RsaOaep4096,
        )),
        "ecies-p256" | "ecies" | "p256" => {
            Ok(KeygenAlgorithm::Asymmetric(AsymmetricAlgorithm::EciesP256))
        }
        _ => {
            let msg = if i18n::is_zh() {
                format!("未知算法：{}", algo_str)
            } else {
                format!("Unknown algorithm: {}", algo_str)
            };
            Err(CryptoError::InvalidArguments(msg))
        }
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
            Command::Wizard => self.run_interactive_wizard(),
        }
    }

    /// Run the interactive encryption/decryption wizard.
    /// 运行交互式加密/解密向导。
    pub fn run_interactive_wizard(&self) -> Result<()> {
        crate::interactive::run(self)
    }

    /// Encrypt a file or directory with an already prepared key.
    /// 使用已准备好的密钥加密文件或目录。
    pub fn encrypt_with_key(
        &self,
        input_path: &Path,
        output_path: &Path,
        key: &SecureBytes,
        algorithm: FileAlgorithm,
        compression: Option<CompressionAlgorithm>,
        kdf_params: Option<(KdfAlgorithm, u32, Vec<u8>)>,
        recursive: bool,
    ) -> Result<()> {
        if input_path.is_file() {
            self.encrypt_file(
                input_path,
                output_path,
                key,
                algorithm,
                compression,
                kdf_params,
            )
        } else if input_path.is_dir() {
            if !recursive {
                let msg = if i18n::is_zh() {
                    "输入路径是目录，需要启用递归目录加密".to_string()
                } else {
                    "Input path is a directory; recursive directory encryption is required"
                        .to_string()
                };
                Err(CryptoError::InvalidArguments(msg))
            } else {
                self.encrypt_directory(
                    input_path,
                    output_path,
                    key,
                    algorithm,
                    compression,
                    kdf_params,
                )
            }
        } else {
            Err(CryptoError::FileNotFound(input_path.to_path_buf()))
        }
    }

    /// Decrypt a file with an already prepared key and extract directory archives when detected.
    /// 使用已准备好的密钥解密文件，并在检测到目录归档时自动解包。
    pub fn decrypt_with_key(
        &self,
        input_path: &Path,
        output_path: &Path,
        key: &SecureBytes,
    ) -> Result<()> {
        use crate::file_handler;

        let (temp_decrypted, temp_file) =
            file_handler::create_unique_temp_file("crypto_cli_decrypted")?;
        drop(temp_file);
        std::fs::remove_file(&temp_decrypted)
            .map_err(|e| CryptoError::FileWriteError(temp_decrypted.clone(), e))?;

        let result = (|| {
            let mut progress_bar = if crate::cli::should_show_progress() {
                let label = if i18n::is_zh() {
                    format!("正在解密 {}", input_path.display())
                } else {
                    format!("Decrypting {}", input_path.display())
                };
                Some(crate::cli::ProgressBar::new(label))
            } else {
                None
            };
            let mut progress = |current: u64, total: u64| {
                if let Some(bar) = progress_bar.as_mut() {
                    bar.update(current, total);
                }
            };

            file_handler::decrypt_file_with_progress(
                input_path,
                &temp_decrypted,
                key,
                Some(&mut progress),
            )?;
            if let Some(bar) = progress_bar.as_mut() {
                bar.finish();
            }

            if file_handler::is_directory_archive_file(&temp_decrypted)? {
                use crate::archive;
                // The archive extractor currently expects an in-memory archive buffer.
                // Keep magic detection streaming-friendly and leave extraction streaming as a future optimization.
                let decrypted_data = std::fs::read(&temp_decrypted)
                    .map_err(|e| CryptoError::FileReadError(temp_decrypted.clone(), e))?;
                archive::extract_archive(&decrypted_data, output_path)?;
            } else {
                std::fs::rename(&temp_decrypted, output_path)
                    .map_err(|e| CryptoError::FileWriteError(output_path.to_path_buf(), e))?;
            }

            Ok(())
        })();

        let _ = std::fs::remove_file(&temp_decrypted);
        result
    }

    /// Handle the encrypt command
    /// 处理加密命令
    fn handle_encrypt(&self, args: EncryptArgs) -> Result<()> {
        use crate::cli;

        // Log verbose information
        cli::log_verbose(
            args.verbose,
            i18n::t("Starting encryption operation", "开始加密操作"),
        );

        // Parse algorithm from string
        let algorithm = parse_algorithm(&args.algorithm)?;
        let algo_msg = if i18n::is_zh() {
            format!("使用算法：{:?}", algorithm)
        } else {
            format!("Using algorithm: {:?}", algorithm)
        };
        cli::log_verbose(args.verbose, &algo_msg);

        // Obtain key from specified source
        let (key, kdf_params) = self.obtain_key_for_encryption(&args)?;
        cli::log_verbose(
            args.verbose,
            i18n::t("Key obtained successfully", "密钥获取成功"),
        );

        // Parse compression if specified
        let compression = if let Some(comp_str) = &args.compress {
            Some(parse_compression(comp_str, args.compression_level)?)
        } else {
            None
        };

        if let Some(comp) = compression {
            let comp_msg = if i18n::is_zh() {
                format!("使用压缩：{:?}", comp)
            } else {
                format!("Using compression: {:?}", comp)
            };
            cli::log_verbose(args.verbose, &comp_msg);
        }

        // Determine output path
        let output_path = args.output.clone().unwrap_or_else(|| {
            let mut path = args.input.clone();
            path.set_extension("enc");
            path
        });

        let input_msg = if i18n::is_zh() {
            format!("输入：{}", args.input.display())
        } else {
            format!("Input: {}", args.input.display())
        };
        let output_msg = if i18n::is_zh() {
            format!("输出：{}", output_path.display())
        } else {
            format!("Output: {}", output_path.display())
        };
        cli::log_verbose(args.verbose, &input_msg);
        cli::log_verbose(args.verbose, &output_msg);

        // Determine if input is file or directory
        if args.input.is_file() {
            if args.verbose {
                let input_size = std::fs::metadata(&args.input)
                    .map_err(|e| CryptoError::FileReadError(args.input.clone(), e))?
                    .len();
                let streaming = input_size >= crate::file_handler::STREAMING_THRESHOLD
                    && algorithm.supports_streaming();
                let mode_msg = if i18n::is_zh() {
                    format!("处理模式：{}", if streaming { "流式" } else { "非流式" })
                } else {
                    format!(
                        "Mode: {}",
                        if streaming {
                            "streaming"
                        } else {
                            "non-streaming"
                        }
                    )
                };
                cli::log_verbose(args.verbose, &mode_msg);
                if streaming {
                    let chunk_msg = if i18n::is_zh() {
                        format!("分块大小：{} 字节", crate::crypto::CHUNK_SIZE)
                    } else {
                        format!("Chunk size: {} bytes", crate::crypto::CHUNK_SIZE)
                    };
                    let size_msg = if i18n::is_zh() {
                        format!("原始大小：{} 字节", input_size)
                    } else {
                        format!("Original size: {} bytes", input_size)
                    };
                    cli::log_verbose(args.verbose, &chunk_msg);
                    cli::log_verbose(args.verbose, &size_msg);
                }
            }
            // Encrypt single file
            cli::log_verbose(
                args.verbose,
                i18n::t("Encrypting file...", "正在加密文件..."),
            );
            self.encrypt_file(
                &args.input,
                &output_path,
                &key,
                algorithm,
                compression,
                kdf_params,
            )?;
            let success_msg = if i18n::is_zh() {
                format!("文件加密成功：{}", output_path.display())
            } else {
                format!("File encrypted successfully: {}", output_path.display())
            };
            cli::print_success(&success_msg);
        } else if args.input.is_dir() {
            // Encrypt directory
            if !args.recursive {
                let msg = if i18n::is_zh() {
                    format!(
                        "输入路径 '{}' 是目录。请使用 --recursive（或 -r）参数加密目录。\n\
                        示例：crypto-cli-tool encrypt -i {} --recursive",
                        args.input.display(),
                        args.input.display()
                    )
                } else {
                    format!(
                        "The input path '{}' is a directory. Use --recursive (or -r) flag to encrypt directories.\n\
                        Example: crypto-cli-tool encrypt -i {} --recursive",
                        args.input.display(),
                        args.input.display()
                    )
                };
                return Err(CryptoError::InvalidArguments(msg));
            }
            cli::log_verbose(
                args.verbose,
                i18n::t("Encrypting directory...", "正在加密目录..."),
            );
            self.encrypt_directory(
                &args.input,
                &output_path,
                &key,
                algorithm,
                compression,
                kdf_params,
            )?;
            let success_msg = if i18n::is_zh() {
                format!("目录加密成功：{}", output_path.display())
            } else {
                format!(
                    "Directory encrypted successfully: {}",
                    output_path.display()
                )
            };
            cli::print_success(&success_msg);
        } else {
            return Err(CryptoError::FileNotFound(args.input.clone()));
        }

        Ok(())
    }

    /// Obtain encryption key from the specified source
    /// 从指定来源获取加密密钥
    /// Returns (key, optional_kdf_params)
    /// 返回 (密钥, 可选的_kdf_参数)
    fn obtain_key_for_encryption(
        &self,
        args: &EncryptArgs,
    ) -> Result<(SecureBytes, Option<(KdfAlgorithm, u32, Vec<u8>)>)> {
        use crate::cli;
        use crate::key_manager;

        match args.key_source.as_str() {
            "password" => {
                // Prompt for password with confirmation
                let password = cli::prompt_password_with_confirmation(
                    i18n::t("Enter password: ", "请输入密码："),
                    i18n::t("Confirm password: ", "确认密码："),
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
                            &password, &salt, 19456, // 19 MiB memory
                            2,     // 2 iterations
                            32,    // 256 bits
                        )?
                    }
                };

                let kdf_params = (
                    self.config.default_kdf,
                    self.config.kdf_iterations,
                    salt.to_vec(),
                );
                Ok((key, Some(kdf_params)))
            }
            "env" => {
                // Read password from environment variable
                let var_name = args.password_env.as_ref().ok_or_else(|| {
                    let msg = if i18n::is_zh() {
                        "使用 key-source=env 时必须指定 --password-env".to_string()
                    } else {
                        "--password-env required when using key-source=env".to_string()
                    };
                    CryptoError::MissingRequiredArgument(msg)
                })?;

                let password = cli::read_password_from_env(var_name)?;

                // Generate salt
                let salt = key_manager::generate_salt()?;

                // Derive key
                let key = match self.config.default_kdf {
                    KdfAlgorithm::Pbkdf2Sha256 => key_manager::derive_key_pbkdf2(
                        &password,
                        &salt,
                        self.config.kdf_iterations,
                        32,
                    )?,
                    KdfAlgorithm::Argon2id => {
                        key_manager::derive_key_argon2id(&password, &salt, 19456, 2, 32)?
                    }
                };

                let kdf_params = (
                    self.config.default_kdf,
                    self.config.kdf_iterations,
                    salt.to_vec(),
                );
                Ok((key, Some(kdf_params)))
            }
            "keyfile" => {
                // Load key from file
                let keyfile_path = args.keyfile.as_ref().ok_or_else(|| {
                    let msg = if i18n::is_zh() {
                        "使用 key-source=keyfile 时必须指定 --keyfile".to_string()
                    } else {
                        "--keyfile required when using key-source=keyfile".to_string()
                    };
                    CryptoError::MissingRequiredArgument(msg)
                })?;

                let key = cli::load_key_from_file(keyfile_path)?;

                // Validate key size (must be 32 bytes for symmetric algorithms)
                if key.len() != 32 {
                    return Err(CryptoError::InvalidKey);
                }

                Ok((key, None))
            }
            _ => {
                let msg = if i18n::is_zh() {
                    format!("未知的密钥来源：{}", args.key_source)
                } else {
                    format!("Unknown key source: {}", args.key_source)
                };
                Err(CryptoError::InvalidArguments(msg))
            }
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

        let mut progress_bar = if crate::cli::should_show_progress() {
            let label = if i18n::is_zh() {
                format!("正在加密 {}", input_path.display())
            } else {
                format!("Encrypting {}", input_path.display())
            };
            Some(crate::cli::ProgressBar::new(label))
        } else {
            None
        };
        let mut progress = |current: u64, total: u64| {
            if let Some(bar) = progress_bar.as_mut() {
                bar.update(current, total);
            }
        };

        file_handler::encrypt_file_with_progress(
            input_path,
            output_path,
            key,
            algorithm,
            compression,
            kdf_params,
            Some(&mut progress),
        )?;
        if let Some(bar) = progress_bar.as_mut() {
            bar.finish();
        }
        Ok(())
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
        let (temp_archive_path, mut temp_file) =
            file_handler::create_unique_temp_file("crypto_cli_archive")?;
        use std::io::Write;
        temp_file
            .write_all(&archive_data)
            .map_err(|e| CryptoError::FileWriteError(temp_archive_path.clone(), e))?;
        temp_file
            .flush()
            .map_err(|e| CryptoError::FileWriteError(temp_archive_path.clone(), e))?;
        drop(temp_file);

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
        cli::log_verbose(
            args.verbose,
            i18n::t("Starting decryption operation", "开始解密操作"),
        );

        // Read encrypted file header to determine type
        let input_file = std::fs::File::open(&args.input).map_err(|e| {
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

        let algo_msg = if i18n::is_zh() {
            format!("算法：{:?}", header.algorithm)
        } else {
            format!("Algorithm: {:?}", header.algorithm)
        };
        let comp_msg = if i18n::is_zh() {
            format!("是否压缩：{}", header.compressed)
        } else {
            format!("Compressed: {}", header.compressed)
        };
        cli::log_verbose(args.verbose, &algo_msg);
        cli::log_verbose(args.verbose, &comp_msg);
        if let Some(stream_metadata) = file_handler::streaming_metadata_from_header(&header)? {
            let mode_msg = if i18n::is_zh() {
                "处理模式：流式".to_string()
            } else {
                "Mode: streaming".to_string()
            };
            let chunk_msg = if i18n::is_zh() {
                format!("分块大小：{} 字节", stream_metadata.chunk_size)
            } else {
                format!("Chunk size: {} bytes", stream_metadata.chunk_size)
            };
            cli::log_verbose(args.verbose, &mode_msg);
            cli::log_verbose(args.verbose, &chunk_msg);
        } else {
            cli::log_verbose(
                args.verbose,
                i18n::t("Mode: non-streaming", "处理模式：非流式"),
            );
        }

        // Obtain key from specified source
        let key = self.obtain_key_for_decryption(&args, &header)?;
        cli::log_verbose(
            args.verbose,
            i18n::t("Key obtained successfully", "密钥获取成功"),
        );

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

        let input_msg = if i18n::is_zh() {
            format!("输入：{}", args.input.display())
        } else {
            format!("Input: {}", args.input.display())
        };
        let output_msg = if i18n::is_zh() {
            format!("输出：{}", output_path.display())
        } else {
            format!("Output: {}", output_path.display())
        };
        cli::log_verbose(args.verbose, &input_msg);
        cli::log_verbose(args.verbose, &output_msg);

        // Decrypt first, then check the archive magic using only the prefix bytes.
        let (temp_decrypted, temp_file) =
            file_handler::create_unique_temp_file("crypto_cli_decrypted")?;
        drop(temp_file);
        std::fs::remove_file(&temp_decrypted)
            .map_err(|e| CryptoError::FileWriteError(temp_decrypted.clone(), e))?;

        cli::log_verbose(
            args.verbose,
            i18n::t("Decrypting file...", "正在解密文件..."),
        );
        let mut progress_bar = if cli::should_show_progress() {
            let label = if i18n::is_zh() {
                format!("正在解密 {}", args.input.display())
            } else {
                format!("Decrypting {}", args.input.display())
            };
            Some(cli::ProgressBar::new(label))
        } else {
            None
        };
        let mut progress = |current: u64, total: u64| {
            if let Some(bar) = progress_bar.as_mut() {
                bar.update(current, total);
            }
        };
        file_handler::decrypt_file_with_progress(
            &args.input,
            &temp_decrypted,
            &key,
            Some(&mut progress),
        )?;
        if let Some(bar) = progress_bar.as_mut() {
            bar.finish();
        }

        if file_handler::is_directory_archive_file(&temp_decrypted)? {
            cli::log_verbose(
                args.verbose,
                i18n::t(
                    "Detected directory archive, extracting...",
                    "检测到目录归档，正在解压...",
                ),
            );

            // Extract archive to output directory
            use crate::archive;
            // The archive extractor currently expects an in-memory archive buffer.
            // Keep magic detection streaming-friendly and leave extraction streaming as a future optimization.
            let decrypted_data = std::fs::read(&temp_decrypted)
                .map_err(|e| CryptoError::FileReadError(temp_decrypted.clone(), e))?;
            archive::extract_archive(&decrypted_data, &output_path)?;

            let success_msg = if i18n::is_zh() {
                format!("目录解密成功：{}", output_path.display())
            } else {
                format!(
                    "Directory decrypted successfully: {}",
                    output_path.display()
                )
            };
            cli::print_success(&success_msg);
        } else {
            // It's a regular file, just move the temp file to output
            std::fs::rename(&temp_decrypted, &output_path)
                .map_err(|e| CryptoError::FileWriteError(output_path.clone(), e))?;

            let success_msg = if i18n::is_zh() {
                format!("文件解密成功：{}", output_path.display())
            } else {
                format!("File decrypted successfully: {}", output_path.display())
            };
            cli::print_success(&success_msg);
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
                let password = cli::prompt_password(i18n::t("Enter password: ", "请输入密码："))?;

                // Check if KDF was used
                if let (Some(kdf), Some(iterations), Some(salt)) =
                    (header.kdf, header.kdf_iterations, &header.salt)
                {
                    // Derive key using same KDF parameters
                    let key = match kdf {
                        KdfAlgorithm::Pbkdf2Sha256 => {
                            key_manager::derive_key_pbkdf2(&password, salt, iterations, 32)?
                        }
                        KdfAlgorithm::Argon2id => {
                            key_manager::derive_key_argon2id(&password, salt, 19456, 2, 32)?
                        }
                    };
                    Ok(key)
                } else {
                    let msg = if i18n::is_zh() {
                        "文件未使用基于密码的加密方式".to_string()
                    } else {
                        "File was not encrypted with password-based encryption".to_string()
                    };
                    Err(CryptoError::InvalidArguments(msg))
                }
            }
            "env" => {
                // Read password from environment variable
                let var_name = args.password_env.as_ref().ok_or_else(|| {
                    let msg = if i18n::is_zh() {
                        "使用 key-source=env 时必须指定 --password-env".to_string()
                    } else {
                        "--password-env required when using key-source=env".to_string()
                    };
                    CryptoError::MissingRequiredArgument(msg)
                })?;

                let password = cli::read_password_from_env(var_name)?;

                // Check if KDF was used
                if let (Some(kdf), Some(iterations), Some(salt)) =
                    (header.kdf, header.kdf_iterations, &header.salt)
                {
                    // Derive key using same KDF parameters
                    let key = match kdf {
                        KdfAlgorithm::Pbkdf2Sha256 => {
                            key_manager::derive_key_pbkdf2(&password, salt, iterations, 32)?
                        }
                        KdfAlgorithm::Argon2id => {
                            key_manager::derive_key_argon2id(&password, salt, 19456, 2, 32)?
                        }
                    };
                    Ok(key)
                } else {
                    let msg = if i18n::is_zh() {
                        "文件未使用基于密码的加密方式".to_string()
                    } else {
                        "File was not encrypted with password-based encryption".to_string()
                    };
                    Err(CryptoError::InvalidArguments(msg))
                }
            }
            "keyfile" => {
                // Load key from file
                let keyfile_path = args.keyfile.as_ref().ok_or_else(|| {
                    let msg = if i18n::is_zh() {
                        "使用 key-source=keyfile 时必须指定 --keyfile".to_string()
                    } else {
                        "--keyfile required when using key-source=keyfile".to_string()
                    };
                    CryptoError::MissingRequiredArgument(msg)
                })?;

                let key = cli::load_key_from_file(keyfile_path)?;

                // Validate key size
                if key.len() != 32 {
                    return Err(CryptoError::InvalidKey);
                }

                Ok(key)
            }
            _ => {
                let msg = if i18n::is_zh() {
                    format!("未知的密钥来源：{}", args.key_source)
                } else {
                    format!("Unknown key source: {}", args.key_source)
                };
                Err(CryptoError::InvalidArguments(msg))
            }
        }
    }

    /// Handle the keygen command
    /// 处理密钥生成命令
    fn handle_keygen(&self, args: KeygenArgs) -> Result<()> {
        use crate::cli;
        use crate::key_manager;

        cli::log_verbose(
            args.verbose,
            i18n::t("Starting key generation", "开始生成密钥"),
        );

        // Parse algorithm
        let algorithm = parse_keygen_algorithm(&args.algorithm)?;
        let gen_msg = if i18n::is_zh() {
            format!("正在生成密钥：{:?}", algorithm)
        } else {
            format!("Generating keys for: {:?}", algorithm)
        };
        cli::log_verbose(args.verbose, &gen_msg);

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

                        let success_msg = if i18n::is_zh() {
                            format!("对称密钥已生成：{}", key_path.display())
                        } else {
                            format!("Symmetric key generated: {}", key_path.display())
                        };
                        cli::print_success(&success_msg);
                        cli::print_info(i18n::t(
                            "⚠ Keep this key file secure!",
                            "⚠ 请妥善保管此密钥文件！",
                        ));
                    }
                    "pem" => {
                        let msg = if i18n::is_zh() {
                            "对称密钥不支持 PEM 格式，请使用 'raw'".to_string()
                        } else {
                            "PEM format not supported for symmetric keys, use 'raw'".to_string()
                        };
                        return Err(CryptoError::InvalidArguments(msg));
                    }
                    _ => {
                        let msg = if i18n::is_zh() {
                            format!("未知格式：{}", args.format)
                        } else {
                            format!("Unknown format: {}", args.format)
                        };
                        return Err(CryptoError::InvalidArguments(msg));
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
                    let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("key");
                    path.set_file_name(format!("{}.pub", filename));
                    path
                };

                match args.format.as_str() {
                    "pem" => {
                        // Write private key in PEM format
                        let private_pem = format!(
                            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                            base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                key_pair.private_key.as_ref()
                            )
                        );
                        std::fs::write(private_key_path, private_pem).map_err(|e| {
                            CryptoError::FileWriteError(private_key_path.clone(), e)
                        })?;

                        // Write public key in PEM format
                        let public_pem = format!(
                            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                            base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &key_pair.public_key
                            )
                        );
                        std::fs::write(&public_key_path, public_pem)
                            .map_err(|e| CryptoError::FileWriteError(public_key_path.clone(), e))?;

                        cli::print_success(i18n::t("Key pair generated:", "密钥对已生成："));
                        let pri_msg = if i18n::is_zh() {
                            format!("  私钥：{}", private_key_path.display())
                        } else {
                            format!("  Private key: {}", private_key_path.display())
                        };
                        let pub_msg = if i18n::is_zh() {
                            format!("  公钥：{}", public_key_path.display())
                        } else {
                            format!("  Public key: {}", public_key_path.display())
                        };
                        cli::print_info(&pri_msg);
                        cli::print_info(&pub_msg);
                        cli::print_info(i18n::t(
                            "⚠ Keep the private key secure!",
                            "⚠ 请妥善保管私钥！",
                        ));
                    }
                    "raw" => {
                        // Write keys in raw DER format
                        std::fs::write(private_key_path, key_pair.private_key.as_ref()).map_err(
                            |e| CryptoError::FileWriteError(private_key_path.clone(), e),
                        )?;

                        std::fs::write(&public_key_path, &key_pair.public_key)
                            .map_err(|e| CryptoError::FileWriteError(public_key_path.clone(), e))?;

                        cli::print_success(i18n::t("Key pair generated:", "密钥对已生成："));
                        let pri_msg = if i18n::is_zh() {
                            format!("  私钥：{}", private_key_path.display())
                        } else {
                            format!("  Private key: {}", private_key_path.display())
                        };
                        let pub_msg = if i18n::is_zh() {
                            format!("  公钥：{}", public_key_path.display())
                        } else {
                            format!("  Public key: {}", public_key_path.display())
                        };
                        cli::print_info(&pri_msg);
                        cli::print_info(&pub_msg);
                        cli::print_info(i18n::t(
                            "⚠ Keep the private key secure!",
                            "⚠ 请妥善保管私钥！",
                        ));
                    }
                    _ => {
                        let msg = if i18n::is_zh() {
                            format!("未知格式：{}", args.format)
                        } else {
                            format!("Unknown format: {}", args.format)
                        };
                        return Err(CryptoError::InvalidArguments(msg));
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle the list-algorithms command
    /// 处理列出算法命令
    fn handle_list_algorithms(&self) -> Result<()> {
        if i18n::is_zh() {
            println!("\n=== 支持的加密算法 ===\n");

            println!("对称算法（AEAD）：");
            println!("  • AES-256-GCM");
            println!("    - 密钥长度：256 位");
            println!("    - 安全性：高");
            println!("    - AEAD：是（带关联数据的认证加密）");
            println!("    - 建议：适用于大多数场景");
            println!("    - 用法：--algorithm aes-256-gcm\n");

            println!("  • ChaCha20-Poly1305");
            println!("    - 密钥长度：256 位");
            println!("    - 安全性：高");
            println!("    - AEAD：是");
            println!("    - 建议：推荐，尤其适用于移动/嵌入式");
            println!("    - 用法：--algorithm chacha20-poly1305\n");

            println!("对称算法（非 AEAD）：");
            println!("  • AES-256-CBC（带 HMAC-SHA256）");
            println!("    - 密钥长度：256 位");
            println!("    - 安全性：高");
            println!("    - AEAD：否（使用 Encrypt-then-MAC）");
            println!("    - 建议：仅用于兼容性需求");
            println!("    - 用法：--algorithm aes-256-cbc\n");

            println!("非对称算法：");
            println!("  • RSA-OAEP-2048");
            println!("    - 密钥长度：2048 位");
            println!("    - 安全性：中-高");
            println!("    - AEAD：不适用（使用 AES-256-GCM 混合加密）");
            println!("    - 建议：新应用的最低推荐");
            println!("    - 用法：--algorithm rsa-oaep-2048\n");

            println!("  • RSA-OAEP-4096");
            println!("    - 密钥长度：4096 位");
            println!("    - 安全性：很高");
            println!("    - AEAD：不适用（使用 AES-256-GCM 混合加密）");
            println!("    - 建议：长期安全性推荐");
            println!("    - 用法：--algorithm rsa-oaep-4096\n");

            println!("  • ECIES-P256");
            println!("    - 曲线：NIST P-256");
            println!("    - 安全性：高");
            println!("    - AEAD：不适用（使用 AES-256-GCM 混合加密）");
            println!("    - 建议：效率优先推荐");
            println!("    - 用法：--algorithm ecies-p256\n");

            println!("=== 密钥派生函数 ===\n");
            println!("  • Argon2id（默认）");
            println!("    - 内存硬化，抗 GPU/ASIC 攻击");
            println!("    - 建议：推荐用于基于密码的加密\n");

            println!("  • PBKDF2-SHA256");
            println!("    - 标准 KDF，广泛支持");
            println!("    - 建议：仅用于兼容性需求\n");

            println!("=== 压缩算法 ===\n");
            println!("  • Gzip（级别 1-9）");
            println!("    - 标准压缩，兼容性好");
            println!("    - 用法：--compress gzip --compression-level 6\n");

            println!("  • Zstd（级别 1-22）");
            println!("    - 现代压缩，更优压缩率与速度");
            println!("    - 建议：推荐");
            println!("    - 用法：--compress zstd --compression-level 3\n");

            println!("=== 通用建议 ===\n");
            println!("  • 文件：使用 AES-256-GCM + 密码加密");
            println!("  • 目录：使用 AES-256-GCM + Zstd 压缩");
            println!("  • 公钥加密：使用 ECIES-P256 或 RSA-OAEP-4096");
            println!("  • 始终使用强且唯一的密码（12+ 字符）");
            println!("  • 安全存储密钥，切勿共享私钥\n");
        } else {
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
        }

        Ok(())
    }

    /// Handle the info command
    /// 处理信息命令
    fn handle_info(&self, args: InfoArgs) -> Result<()> {
        use crate::cli;
        use crate::file_handler;

        cli::log_verbose(
            args.verbose,
            i18n::t("Reading encrypted file header", "读取加密文件头"),
        );

        // Open and read the encrypted file header
        let input_file = std::fs::File::open(&args.input).map_err(|e| {
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
        if i18n::is_zh() {
            println!("\n=== 加密文件信息 ===\n");
            println!("文件：{}", args.input.display());
            println!("格式版本：{}", header.version);
        } else {
            println!("\n=== Encrypted File Information ===\n");
            println!("File: {}", args.input.display());
            println!("Format Version: {}", header.version);
        }

        // Display algorithm
        let algo_name = match header.algorithm {
            FileAlgorithm::Aes256Gcm => "AES-256-GCM",
            FileAlgorithm::Aes256Cbc => "AES-256-CBC (with HMAC-SHA256)",
            FileAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            FileAlgorithm::RsaOaep2048 => "RSA-OAEP-2048 (hybrid)",
            FileAlgorithm::RsaOaep4096 => "RSA-OAEP-4096 (hybrid)",
            FileAlgorithm::EciesP256 => "ECIES-P256 (hybrid)",
        };
        if i18n::is_zh() {
            println!("算法：{}", algo_name);
        } else {
            println!("Algorithm: {}", algo_name);
        }

        // Display AEAD support
        let is_aead = matches!(
            header.algorithm,
            FileAlgorithm::Aes256Gcm | FileAlgorithm::ChaCha20Poly1305
        );
        if i18n::is_zh() {
            println!("AEAD：{}", if is_aead { "是" } else { "否" });
        } else {
            println!("AEAD: {}", if is_aead { "Yes" } else { "No" });
        }

        // Display KDF information
        if let Some(kdf) = header.kdf {
            let kdf_name = match kdf {
                KdfAlgorithm::Pbkdf2Sha256 => "PBKDF2-SHA256",
                KdfAlgorithm::Argon2id => "Argon2id",
            };
            if i18n::is_zh() {
                println!("密钥派生：{}", kdf_name);
            } else {
                println!("Key Derivation: {}", kdf_name);
            }

            if let Some(iterations) = header.kdf_iterations {
                if i18n::is_zh() {
                    println!("KDF 迭代次数：{}", iterations);
                } else {
                    println!("KDF Iterations: {}", iterations);
                }
            }

            if let Some(salt) = &header.salt {
                if i18n::is_zh() {
                    println!("盐长度：{} 字节", salt.len());
                } else {
                    println!("Salt Length: {} bytes", salt.len());
                }
            }
        } else {
            if i18n::is_zh() {
                println!("密钥派生：无（使用原始密钥）");
            } else {
                println!("Key Derivation: None (raw key used)");
            }
        }

        // Display IV information
        if i18n::is_zh() {
            println!("IV/Nonce 长度：{} 字节", header.iv.len());
        } else {
            println!("IV/Nonce Length: {} bytes", header.iv.len());
        }

        // Display compression information
        if header.compressed {
            let comp_name = match header.compression_algo {
                Some(CompressionAlgorithm::Gzip) => "Gzip",
                Some(CompressionAlgorithm::Zstd) => "Zstd",
                None => {
                    if i18n::is_zh() {
                        "未知"
                    } else {
                        "Unknown"
                    }
                }
            };
            if i18n::is_zh() {
                println!("压缩：{}（已启用）", comp_name);
            } else {
                println!("Compression: {} (enabled)", comp_name);
            }
        } else {
            if i18n::is_zh() {
                println!("压缩：无");
            } else {
                println!("Compression: None");
            }
        }

        // Display original size
        if i18n::is_zh() {
            println!("原始大小：{} 字节", header.original_size);
        } else {
            println!("Original Size: {} bytes", header.original_size);
        }

        let stream_metadata = file_handler::streaming_metadata_from_header(&header)?;
        if let Some(metadata) = &stream_metadata {
            if i18n::is_zh() {
                println!("是否流式：是");
                println!("流式格式版本：{}", metadata.stream_version);
                println!("分块大小：{} 字节", metadata.chunk_size);
                println!("总分块数：{}", metadata.total_chunks);
            } else {
                println!("Streaming: Yes");
                println!("Stream Version: {}", metadata.stream_version);
                println!("Chunk Size: {} bytes", metadata.chunk_size);
                println!("Total Chunks: {}", metadata.total_chunks);
            }
        } else if i18n::is_zh() {
            println!("是否流式：否");
        } else {
            println!("Streaming: No");
        }

        // Display metadata if present
        if !header.metadata.is_empty() {
            if i18n::is_zh() {
                println!("元数据长度：{} 字节", header.metadata.len());
            } else {
                println!("Metadata Length: {} bytes", header.metadata.len());
            }

            if args.verbose {
                // Try to parse metadata as JSON
                if let Ok(metadata_str) = String::from_utf8(header.metadata.clone()) {
                    if i18n::is_zh() {
                        println!("元数据内容：");
                    } else {
                        println!("Metadata Content:");
                    }
                    println!("{}", metadata_str);
                }
            }
        } else {
            if i18n::is_zh() {
                println!("元数据：无");
            } else {
                println!("Metadata: None");
            }
        }

        println!();

        Ok(())
    }
}
