// File Handler module - file I/O, streaming, and directory operations
// 文件处理器模块 - 文件 I/O、流式处理和目录操作

use crate::error::{CryptoError, Result};
use crate::i18n;
use crate::key_manager::KdfAlgorithm;
use crate::compression::CompressionAlgorithm;
use std::io::{Read, Write};
use sha2::{Sha256, Digest};

/// Magic bytes for encrypted file identification: "CRYPTOOL"
/// 加密文件识别的魔数字节："CRYPTOOL"
pub const MAGIC_BYTES: [u8; 8] = *b"CRYPTOOL";

/// Current file format version
/// 当前文件格式版本
pub const CURRENT_VERSION: u16 = 1;

/// Encryption algorithm identifiers
/// 加密算法标识符
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    Aes256Gcm = 0x01,
    Aes256Cbc = 0x02,
    ChaCha20Poly1305 = 0x03,
    RsaOaep2048 = 0x04,
    RsaOaep4096 = 0x05,
    EciesP256 = 0x06,
}

impl Algorithm {
    /// Convert from byte representation
    /// 从字节表示转换
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Algorithm::Aes256Gcm),
            0x02 => Ok(Algorithm::Aes256Cbc),
            0x03 => Ok(Algorithm::ChaCha20Poly1305),
            0x04 => Ok(Algorithm::RsaOaep2048),
            0x05 => Ok(Algorithm::RsaOaep4096),
            0x06 => Ok(Algorithm::EciesP256),
            _ => Err(CryptoError::InvalidFileFormat),
        }
    }
    
    /// Convert to byte representation
    /// 转换为字节表示
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Encrypted file header structure
/// 加密文件头部结构
///
/// This structure contains all metadata needed to decrypt a file,
/// including algorithm information, KDF parameters, IV, and optional metadata.
/// 此结构包含解密文件所需的所有元数据，包括算法信息、KDF 参数、IV 和可选元数据。
#[derive(Debug, Clone)]
pub struct EncryptedFileHeader {
    /// Magic bytes for file identification: "CRYPTOOL"
    /// 文件识别的魔数字节："CRYPTOOL"
    pub magic: [u8; 8],
    
    /// File format version
    /// 文件格式版本
    pub version: u16,
    
    /// Encryption algorithm used
    /// 使用的加密算法
    pub algorithm: Algorithm,
    
    /// Key derivation function (None if raw key was used)
    /// 密钥派生函数（如果使用原始密钥则为 None）
    pub kdf: Option<KdfAlgorithm>,
    
    /// KDF iteration count (None if KDF not used)
    /// KDF 迭代次数（如果未使用 KDF 则为 None）
    pub kdf_iterations: Option<u32>,
    
    /// Salt for key derivation (None if KDF not used)
    /// 密钥派生的盐（如果未使用 KDF 则为 None）
    pub salt: Option<Vec<u8>>,
    
    /// Initialization vector or nonce
    /// 初始化向量或 nonce
    pub iv: Vec<u8>,
    
    /// Whether the data was compressed before encryption
    /// 数据在加密前是否被压缩
    pub compressed: bool,
    
    /// Compression algorithm used (None if not compressed)
    /// 使用的压缩算法（如果未压缩则为 None）
    pub compression_algo: Option<CompressionAlgorithm>,
    
    /// Original unencrypted file size
    /// 原始未加密文件大小
    pub original_size: u64,
    
    /// Additional metadata in JSON format
    /// JSON 格式的附加元数据
    pub metadata: Vec<u8>,
}

impl EncryptedFileHeader {
    /// Create a new encrypted file header with default values
    /// 使用默认值创建新的加密文件头部
    pub fn new(algorithm: Algorithm, iv: Vec<u8>, original_size: u64) -> Self {
        Self {
            magic: MAGIC_BYTES,
            version: CURRENT_VERSION,
            algorithm,
            kdf: None,
            kdf_iterations: None,
            salt: None,
            iv,
            compressed: false,
            compression_algo: None,
            original_size,
            metadata: Vec::new(),
        }
    }
    
    /// Set KDF parameters
    /// 设置 KDF 参数
    pub fn with_kdf(mut self, kdf: KdfAlgorithm, iterations: u32, salt: Vec<u8>) -> Self {
        self.kdf = Some(kdf);
        self.kdf_iterations = Some(iterations);
        self.salt = Some(salt);
        self
    }
    
    /// Set compression parameters
    /// 设置压缩参数
    pub fn with_compression(mut self, algo: CompressionAlgorithm) -> Self {
        self.compressed = true;
        self.compression_algo = Some(algo);
        self
    }
    
    /// Set metadata
    /// 设置元数据
    pub fn with_metadata(mut self, metadata: Vec<u8>) -> Self {
        self.metadata = metadata;
        self
    }
    
    /// Serialize the header to binary format and write to a writer
    /// 将头部序列化为二进制格式并写入写入器
    ///
    /// Format: / 格式：
    /// - Magic Bytes (8 bytes): "CRYPTOOL" / 魔数字节（8 字节）："CRYPTOOL"
    /// - Version (2 bytes): u16 little-endian / 版本（2 字节）：u16 小端序
    /// - Algorithm ID (1 byte) / 算法 ID（1 字节）
    /// - Flags (1 byte): [compressed|reserved|reserved|...] / 标志（1 字节）：[已压缩|保留|保留|...]
    /// - Compression Algorithm (1 byte, 0x00 if not compressed) / 压缩算法（1 字节，如果未压缩则为 0x00）
    /// - KDF Algorithm (1 byte, 0x00 if not used) / KDF 算法（1 字节，如果未使用则为 0x00）
    /// - KDF Iterations (4 bytes, 0 if not used) / KDF 迭代次数（4 字节，如果未使用则为 0）
    /// - Salt Length (1 byte) / 盐长度（1 字节）
    /// - Salt (variable, 0-255 bytes) / 盐（可变，0-255 字节）
    /// - IV Length (1 byte) / IV 长度（1 字节）
    /// - IV (variable, typically 12-16 bytes) / IV（可变，通常 12-16 字节）
    /// - Original Size (8 bytes) / 原始大小（8 字节）
    /// - Metadata Length (2 bytes) / 元数据长度（2 字节）
    /// - Metadata (variable, JSON format) / 元数据（可变，JSON 格式）
    /// - Header Checksum (32 bytes, SHA-256) / 头部校验和（32 字节，SHA-256）
    ///
    /// # Arguments / 参数
    /// * `writer` - The writer to write the header to / 要写入头部的写入器
    ///
    /// # Returns / 返回值
    /// Ok(()) on success, or an error if writing fails / 成功时返回 Ok(())，写入失败时返回错误
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Build header data (everything except the checksum)
        let mut header_data = Vec::new();
        
        // Magic bytes (8 bytes)
        header_data.extend_from_slice(&self.magic);
        
        // Version (2 bytes, little-endian)
        header_data.extend_from_slice(&self.version.to_le_bytes());
        
        // Algorithm ID (1 byte)
        header_data.push(self.algorithm.to_u8());
        
        // Flags (1 byte)
        let mut flags: u8 = 0;
        if self.compressed {
            flags |= 0x01; // Set bit 0 for compressed
        }
        header_data.push(flags);
        
        // Compression Algorithm (1 byte)
        let comp_byte = match self.compression_algo {
            None => 0x00,
            Some(CompressionAlgorithm::Gzip) => 0x01,
            Some(CompressionAlgorithm::Zstd) => 0x02,
        };
        header_data.push(comp_byte);
        
        // KDF Algorithm (1 byte)
        let kdf_byte = match self.kdf {
            None => 0x00,
            Some(KdfAlgorithm::Pbkdf2Sha256) => 0x01,
            Some(KdfAlgorithm::Argon2id) => 0x02,
        };
        header_data.push(kdf_byte);
        
        // KDF Iterations (4 bytes, little-endian)
        let iterations = self.kdf_iterations.unwrap_or(0);
        header_data.extend_from_slice(&iterations.to_le_bytes());
        
        // Salt Length and Salt
        let salt = self.salt.as_ref().map(|s| s.as_slice()).unwrap_or(&[]);
        if salt.len() > 255 {
            let msg = if i18n::is_zh() {
                "盐过长（最大 255 字节）".to_string()
            } else {
                "Salt too long (max 255 bytes)".to_string()
            };
            return Err(CryptoError::InvalidArguments(msg));
        }
        header_data.push(salt.len() as u8);
        header_data.extend_from_slice(salt);
        
        // IV Length and IV
        if self.iv.len() > 255 {
            let msg = if i18n::is_zh() {
                "IV 过长（最大 255 字节）".to_string()
            } else {
                "IV too long (max 255 bytes)".to_string()
            };
            return Err(CryptoError::InvalidArguments(msg));
        }
        header_data.push(self.iv.len() as u8);
        header_data.extend_from_slice(&self.iv);
        
        // Original Size (8 bytes, little-endian)
        header_data.extend_from_slice(&self.original_size.to_le_bytes());
        
        // Metadata Length and Metadata
        if self.metadata.len() > 65535 {
            let msg = if i18n::is_zh() {
                "元数据过长（最大 65535 字节）".to_string()
            } else {
                "Metadata too long (max 65535 bytes)".to_string()
            };
            return Err(CryptoError::InvalidArguments(msg));
        }
        let metadata_len = self.metadata.len() as u16;
        header_data.extend_from_slice(&metadata_len.to_le_bytes());
        header_data.extend_from_slice(&self.metadata);
        
        // Compute SHA-256 checksum of header data
        let mut hasher = Sha256::new();
        hasher.update(&header_data);
        let checksum = hasher.finalize();
        
        // Write header data to writer
        writer.write_all(&header_data)
            .map_err(|e| {
                let msg = if i18n::is_zh() {
                    format!("写入文件头失败：{}", e)
                } else {
                    format!("Failed to write header: {}", e)
                };
                CryptoError::SystemError(msg)
            })?;
        
        // Write checksum (32 bytes)
        writer.write_all(&checksum)
            .map_err(|e| {
                let msg = if i18n::is_zh() {
                    format!("写入文件头校验和失败：{}", e)
                } else {
                    format!("Failed to write header checksum: {}", e)
                };
                CryptoError::SystemError(msg)
            })?;
        
        Ok(())
    }
    
    /// Deserialize the header from binary format and read from a reader
    /// 从二进制格式反序列化头部并从读取器读取
    ///
    /// This function reads the header, verifies the checksum, and validates
    /// the version and algorithm IDs.
    /// 此函数读取头部，验证校验和，并验证版本和算法 ID。
    ///
    /// # Arguments / 参数
    /// * `reader` - The reader to read the header from / 要读取头部的读取器
    ///
    /// # Returns / 返回值
    /// The deserialized EncryptedFileHeader on success, or an error if reading,
    /// verification, or validation fails
    /// 成功时返回反序列化的 EncryptedFileHeader，读取、验证或校验失败时返回错误
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        // Read magic bytes (8 bytes)
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)
            .map_err(|_| CryptoError::InvalidFileFormat)?;
        
        if magic != MAGIC_BYTES {
            return Err(CryptoError::InvalidFileFormat);
        }
        
        // Start collecting header data for checksum verification
        let mut header_data = Vec::new();
        header_data.extend_from_slice(&magic);
        
        // Read version (2 bytes)
        let mut version_bytes = [0u8; 2];
        reader.read_exact(&mut version_bytes)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        header_data.extend_from_slice(&version_bytes);
        let version = u16::from_le_bytes(version_bytes);
        
        // Validate version
        if version != CURRENT_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        
        // Read algorithm ID (1 byte)
        let mut algo_byte = [0u8; 1];
        reader.read_exact(&mut algo_byte)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        header_data.push(algo_byte[0]);
        let algorithm = Algorithm::from_u8(algo_byte[0])?;
        
        // Read flags (1 byte)
        let mut flags_byte = [0u8; 1];
        reader.read_exact(&mut flags_byte)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        header_data.push(flags_byte[0]);
        let compressed = (flags_byte[0] & 0x01) != 0;
        
        // Read Compression Algorithm (1 byte)
        let mut comp_byte = [0u8; 1];
        reader.read_exact(&mut comp_byte)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        header_data.push(comp_byte[0]);
        
        let compression_algo = match comp_byte[0] {
            0x00 => None,
            0x01 => Some(CompressionAlgorithm::Gzip),
            0x02 => Some(CompressionAlgorithm::Zstd),
            _ => return Err(CryptoError::InvalidFileFormat),
        };
        
        // Read KDF algorithm (1 byte)
        let mut kdf_byte = [0u8; 1];
        reader.read_exact(&mut kdf_byte)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        header_data.push(kdf_byte[0]);
        
        let kdf = match kdf_byte[0] {
            0x00 => None,
            0x01 => Some(KdfAlgorithm::Pbkdf2Sha256),
            0x02 => Some(KdfAlgorithm::Argon2id),
            _ => return Err(CryptoError::InvalidFileFormat),
        };
        
        // Read KDF iterations (4 bytes)
        let mut iterations_bytes = [0u8; 4];
        reader.read_exact(&mut iterations_bytes)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        header_data.extend_from_slice(&iterations_bytes);
        let iterations_value = u32::from_le_bytes(iterations_bytes);
        let kdf_iterations = if iterations_value == 0 { None } else { Some(iterations_value) };
        
        // Read salt length (1 byte)
        let mut salt_len_byte = [0u8; 1];
        reader.read_exact(&mut salt_len_byte)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        header_data.push(salt_len_byte[0]);
        let salt_len = salt_len_byte[0] as usize;
        
        // Read salt
        let salt = if salt_len > 0 {
            let mut salt_bytes = vec![0u8; salt_len];
            reader.read_exact(&mut salt_bytes)
                .map_err(|_| CryptoError::CorruptedHeader)?;
            header_data.extend_from_slice(&salt_bytes);
            Some(salt_bytes)
        } else {
            None
        };
        
        // Read IV length (1 byte)
        let mut iv_len_byte = [0u8; 1];
        reader.read_exact(&mut iv_len_byte)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        header_data.push(iv_len_byte[0]);
        let iv_len = iv_len_byte[0] as usize;
        
        if iv_len == 0 {
            return Err(CryptoError::InvalidIV);
        }
        
        // Read IV
        let mut iv = vec![0u8; iv_len];
        reader.read_exact(&mut iv)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        header_data.extend_from_slice(&iv);
        
        // Read original size (8 bytes)
        let mut size_bytes = [0u8; 8];
        reader.read_exact(&mut size_bytes)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        header_data.extend_from_slice(&size_bytes);
        let original_size = u64::from_le_bytes(size_bytes);
        
        // Read metadata length (2 bytes)
        let mut metadata_len_bytes = [0u8; 2];
        reader.read_exact(&mut metadata_len_bytes)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        header_data.extend_from_slice(&metadata_len_bytes);
        let metadata_len = u16::from_le_bytes(metadata_len_bytes) as usize;
        
        // Read metadata
        let metadata = if metadata_len > 0 {
            let mut metadata_bytes = vec![0u8; metadata_len];
            reader.read_exact(&mut metadata_bytes)
                .map_err(|_| CryptoError::CorruptedHeader)?;
            header_data.extend_from_slice(&metadata_bytes);
            metadata_bytes
        } else {
            Vec::new()
        };
        
        // Read checksum (32 bytes)
        let mut checksum = [0u8; 32];
        reader.read_exact(&mut checksum)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        
        // Verify checksum
        let mut hasher = Sha256::new();
        hasher.update(&header_data);
        let computed_checksum = hasher.finalize();
        
        if checksum != computed_checksum.as_slice() {
            return Err(CryptoError::CorruptedHeader);
        }
        
        Ok(EncryptedFileHeader {
            magic,
            version,
            algorithm,
            kdf,
            kdf_iterations,
            salt,
            iv,
            compressed,
            compression_algo,
            original_size,
            metadata,
        })
    }
}

/// Encrypt a file with the specified algorithm and key
/// 使用指定的算法和密钥加密文件
///
/// This function implements the complete file encryption workflow:
/// 此函数实现完整的文件加密工作流：
/// 1. Read plaintext file / 读取明文文件
/// 2. Optionally compress the data / 可选地压缩数据
/// 3. Encrypt with the chosen algorithm / 使用选定的算法加密
/// 4. Write encrypted file with header / 写入带头部的加密文件
///
/// # Arguments / 参数
/// * `input_path` - Path to the plaintext file / 明文文件的路径
/// * `output_path` - Path for the encrypted output file / 加密输出文件的路径
/// * `key` - Encryption key / 加密密钥
/// * `algorithm` - Encryption algorithm to use / 要使用的加密算法
/// * `compression` - Optional compression algorithm / 可选的压缩算法
/// * `kdf_params` - Optional KDF parameters (if key was derived from password) / 可选的 KDF 参数（如果密钥是从密码派生的）
///
/// # Returns / 返回值
/// Ok(()) on success, or an error if encryption fails / 成功时返回 Ok(())，加密失败时返回错误
pub fn encrypt_file(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    key: &crate::key_manager::SecureBytes,
    algorithm: Algorithm,
    compression: Option<CompressionAlgorithm>,
    kdf_params: Option<(KdfAlgorithm, u32, Vec<u8>)>, // (kdf, iterations, salt) / (kdf, 迭代次数, 盐)
) -> Result<()> {
    use std::fs::File;
    use std::io::BufReader;
    use crate::crypto;
    use crate::compression;
    
    // Read the plaintext file
    let input_file = File::open(input_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CryptoError::FileNotFound(input_path.to_path_buf())
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                CryptoError::PermissionDenied(input_path.to_path_buf())
            } else {
                CryptoError::FileReadError(input_path.to_path_buf(), e)
            }
        })?;
    
    let mut reader = BufReader::new(input_file);
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)
        .map_err(|e| CryptoError::FileReadError(input_path.to_path_buf(), e))?;
    
    let original_size = plaintext.len() as u64;
    
    // Optionally compress the data
    let data_to_encrypt = if let Some(comp_algo) = compression {
        let comp_context = compression::CompressionContext::new(comp_algo);
        compression::compress(&plaintext, &comp_context)?
    } else {
        plaintext
    };
    
    // Encrypt the data based on the algorithm
    let (ciphertext, iv, tag, mac) = match algorithm {
        Algorithm::Aes256Gcm => {
            let context = crypto::EncryptionContext {
                key: key.clone(),
                iv: None, // Will be generated
                aad: None,
            };
            let result = crypto::encrypt_aes_256_gcm(&data_to_encrypt, &context)?;
            (result.ciphertext, result.iv, result.tag, result.mac)
        }
        Algorithm::ChaCha20Poly1305 => {
            let context = crypto::EncryptionContext {
                key: key.clone(),
                iv: None, // Will be generated
                aad: None,
            };
            let result = crypto::encrypt_chacha20_poly1305(&data_to_encrypt, &context)?;
            (result.ciphertext, result.iv, result.tag, result.mac)
        }
        Algorithm::Aes256Cbc => {
            let context = crypto::EncryptionContext {
                key: key.clone(),
                iv: None, // Will be generated
                aad: None,
            };
            let result = crypto::encrypt_aes_256_cbc_hmac(&data_to_encrypt, &context)?;
            (result.ciphertext, result.iv, result.tag, result.mac)
        }
        _ => {
            let msg = if i18n::is_zh() {
                "不支持使用非对称算法直接加密文件".to_string()
            } else {
                "Asymmetric algorithms not supported for direct file encryption".to_string()
            };
            return Err(CryptoError::InvalidArguments(msg));
        }
    };
    
    // Create the encrypted file header
    let mut header = EncryptedFileHeader::new(algorithm, iv, original_size);
    
    // Add KDF parameters if provided
    if let Some((kdf, iterations, salt)) = kdf_params {
        header = header.with_kdf(kdf, iterations, salt);
    }
    
    // Add compression info if used
    if let Some(comp_algo) = compression {
        header = header.with_compression(comp_algo);
    }
    
    // Use atomic file operations for safe writing
    let mut atomic_file = atomic::AtomicFile::new(output_path)?;
    
    // Write the header
    {
        let file = atomic_file.file_mut()?;
        let mut writer = std::io::BufWriter::new(file);
        header.write_to(&mut writer)?;
        
        // Write the ciphertext
        writer.write_all(&ciphertext)
            .map_err(|e| CryptoError::from_io_error(e, output_path.to_path_buf(), "write"))?;
        
        // Write the authentication tag or MAC
        if let Some(tag_data) = tag {
            writer.write_all(&tag_data)
                .map_err(|e| CryptoError::from_io_error(e, output_path.to_path_buf(), "write"))?;
        } else if let Some(mac_data) = mac {
            writer.write_all(&mac_data)
                .map_err(|e| CryptoError::from_io_error(e, output_path.to_path_buf(), "write"))?;
        }
        
        writer.flush()
            .map_err(|e| CryptoError::from_io_error(e, output_path.to_path_buf(), "write"))?;
    }
    
    // Flush and commit the atomic operation
    atomic_file.flush()?;
    atomic_file.commit()?;
    
    Ok(())
}

/// Decrypt a file that was encrypted with encrypt_file
/// 解密使用 encrypt_file 加密的文件
///
/// This function implements the complete file decryption workflow:
/// 此函数实现完整的文件解密工作流：
/// 1. Read and parse encrypted file header / 读取并解析加密文件头部
/// 2. Verify authentication tag / 验证认证标签
/// 3. Decrypt ciphertext / 解密密文
/// 4. Optionally decompress / 可选地解压缩
/// 5. Write plaintext file / 写入明文文件
///
/// # Arguments / 参数
/// * `input_path` - Path to the encrypted file / 加密文件的路径
/// * `output_path` - Path for the decrypted output file / 解密输出文件的路径
/// * `key` - Decryption key / 解密密钥
///
/// # Returns / 返回值
/// Ok(()) on success, or an error if decryption fails / 成功时返回 Ok(())，解密失败时返回错误
pub fn decrypt_file(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    key: &crate::key_manager::SecureBytes,
) -> Result<()> {
    use std::fs::File;
    use std::io::BufReader;
    use crate::crypto;
    use crate::compression;
    
    // Open and read the encrypted file
    let input_file = File::open(input_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CryptoError::FileNotFound(input_path.to_path_buf())
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                CryptoError::PermissionDenied(input_path.to_path_buf())
            } else {
                CryptoError::FileReadError(input_path.to_path_buf(), e)
            }
        })?;
    
    let mut reader = BufReader::new(input_file);
    
    // Read and parse the header
    let header = EncryptedFileHeader::read_from(&mut reader)?;
    
    // Read the ciphertext (everything after header except tag/mac)
    let mut encrypted_data = Vec::new();
    reader.read_to_end(&mut encrypted_data)
        .map_err(|e| CryptoError::FileReadError(input_path.to_path_buf(), e))?;
    
    // Determine tag/mac size based on algorithm
    let auth_size = match header.algorithm {
        Algorithm::Aes256Gcm | Algorithm::ChaCha20Poly1305 => 16, // AEAD tag
        Algorithm::Aes256Cbc => 32, // HMAC-SHA256
        _ => {
            let msg = if i18n::is_zh() {
                "不支持使用非对称算法直接解密文件".to_string()
            } else {
                "Asymmetric algorithms not supported for direct file decryption".to_string()
            };
            return Err(CryptoError::InvalidArguments(msg));
        }
    };
    
    if encrypted_data.len() < auth_size {
        let msg = if i18n::is_zh() {
            "文件过短".to_string()
        } else {
            "File too short".to_string()
        };
        return Err(CryptoError::DecryptionFailed(msg));
    }
    
    // Split ciphertext and authentication data
    let split_point = encrypted_data.len() - auth_size;
    let ciphertext = &encrypted_data[..split_point];
    let auth_data = &encrypted_data[split_point..];
    
    // Decrypt based on algorithm
    let decrypted_data = match header.algorithm {
        Algorithm::Aes256Gcm => {
            let context = crypto::DecryptionContext {
                key: key.clone(),
                iv: header.iv.clone(),
                tag: Some(auth_data.to_vec()),
                mac: None,
            };
            crypto::decrypt_aes_256_gcm(ciphertext, &context)?
        }
        Algorithm::ChaCha20Poly1305 => {
            let context = crypto::DecryptionContext {
                key: key.clone(),
                iv: header.iv.clone(),
                tag: Some(auth_data.to_vec()),
                mac: None,
            };
            crypto::decrypt_chacha20_poly1305(ciphertext, &context)?
        }
        Algorithm::Aes256Cbc => {
            let context = crypto::DecryptionContext {
                key: key.clone(),
                iv: header.iv.clone(),
                tag: None,
                mac: Some(auth_data.to_vec()),
            };
            crypto::decrypt_aes_256_cbc_hmac(ciphertext, &context)?
        }
        _ => {
            let msg = if i18n::is_zh() {
                "不支持用于文件解密的算法".to_string()
            } else {
                "Unsupported algorithm for file decryption".to_string()
            };
            return Err(CryptoError::InvalidArguments(msg));
        }
    };
    
    // Optionally decompress the data
    let plaintext = if header.compressed {
        let comp_algo = header.compression_algo
            .ok_or(CryptoError::InvalidMetadata)?;
        compression::decompress(&decrypted_data, comp_algo)?
    } else {
        decrypted_data
    };
    
    // Use atomic file operations for safe writing
    let mut atomic_file = atomic::AtomicFile::new(output_path)?;
    
    // Write the plaintext
    atomic_file.write_all(&plaintext)?;
    
    // Flush and commit the atomic operation
    atomic_file.flush()?;
    atomic_file.commit()?;
    
    Ok(())
}

/// Atomic file operations module
/// 原子文件操作模块
/// 
/// This module provides utilities for atomic file operations that ensure
/// data integrity even in the presence of failures or crashes.
/// 此模块提供原子文件操作的实用工具，即使在出现故障或崩溃时也能确保数据完整性。
pub mod atomic {
    use crate::error::{CryptoError, Result};
    use crate::i18n;
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    
    /// A temporary file that will be cleaned up on drop if not committed
    /// 如果未提交，将在销毁时清理的临时文件
    pub struct AtomicFile {
        temp_path: PathBuf,
        final_path: PathBuf,
        file: Option<File>,
        committed: bool,
    }
    
    impl AtomicFile {
        /// Create a new atomic file operation
        /// 创建新的原子文件操作
        /// 
        /// This creates a temporary file that will be atomically renamed
        /// to the final path when committed.
        /// 这会创建一个临时文件，在提交时将原子地重命名为最终路径。
        pub fn new(final_path: &Path) -> Result<Self> {
            let temp_path = final_path.with_extension("tmp");
            
            let file = File::create(&temp_path)
                .map_err(|e| CryptoError::from_io_error(e, temp_path.clone(), "write"))?;
            
            Ok(AtomicFile {
                temp_path,
                final_path: final_path.to_path_buf(),
                file: Some(file),
                committed: false,
            })
        }
        
        /// Get a mutable reference to the underlying file
        /// 获取底层文件的可变引用
        pub fn file_mut(&mut self) -> Result<&mut File> {
            self.file.as_mut().ok_or_else(|| {
                let msg = if i18n::is_zh() {
                    "原子文件已关闭".to_string()
                } else {
                    "Atomic file already closed".to_string()
                };
                CryptoError::SystemError(msg)
            })
        }
        
        /// Write data to the temporary file
        /// 将数据写入临时文件
        pub fn write_all(&mut self, data: &[u8]) -> Result<()> {
            let file = self.file_mut()?;
            file.write_all(data)
                .map_err(|e| CryptoError::from_io_error(e, self.temp_path.clone(), "write"))
        }
        
        /// Flush the file to ensure all data is written
        pub fn flush(&mut self) -> Result<()> {
            let temp_path = self.temp_path.clone();
            let file = self.file_mut()?;
            file.flush()
                .map_err(|e| CryptoError::from_io_error(e, temp_path.clone(), "write"))?;
            
            // Sync to disk for durability
            file.sync_all()
                .map_err(|e| CryptoError::from_io_error(e, temp_path, "write"))
        }
        
        /// Commit the atomic operation by renaming temp file to final path
        /// 
        /// This is an atomic operation on most filesystems. If this succeeds,
        /// the file will not be cleaned up on drop.
        pub fn commit(mut self) -> Result<()> {
            // Close the file first
            if let Some(file) = self.file.take() {
                drop(file);
            }
            
            // Atomically rename temp file to final path
            std::fs::rename(&self.temp_path, &self.final_path)
                .map_err(|e| CryptoError::from_io_error(e, self.final_path.clone(), "write"))?;
            
            self.committed = true;
            Ok(())
        }
        
        /// Get the temporary file path
        pub fn temp_path(&self) -> &Path {
            &self.temp_path
        }
        
        /// Get the final file path
        pub fn final_path(&self) -> &Path {
            &self.final_path
        }
    }
    
    impl Drop for AtomicFile {
        fn drop(&mut self) {
            // If not committed, clean up the temporary file
            if !self.committed {
                // Close the file first
                if let Some(file) = self.file.take() {
                    drop(file);
                }
                
                // Try to remove the temp file, but don't panic if it fails
                let _ = std::fs::remove_file(&self.temp_path);
            }
        }
    }
    
    /// Write data to a file atomically
    /// 
    /// This function writes data to a temporary file and then atomically
    /// renames it to the final path. If any error occurs, the temporary
    /// file is cleaned up.
    pub fn write_file_atomic(path: &Path, data: &[u8]) -> Result<()> {
        let mut atomic_file = AtomicFile::new(path)?;
        atomic_file.write_all(data)?;
        atomic_file.flush()?;
        atomic_file.commit()
    }
}
