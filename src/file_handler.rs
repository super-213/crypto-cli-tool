// File Handler module - file I/O, streaming, and directory operations

use crate::error::{CryptoError, Result};
use crate::key_manager::KdfAlgorithm;
use crate::compression::CompressionAlgorithm;
use std::io::{Read, Write};
use sha2::{Sha256, Digest};

/// Magic bytes for encrypted file identification: "CRYPTOOL"
pub const MAGIC_BYTES: [u8; 8] = *b"CRYPTOOL";

/// Current file format version
pub const CURRENT_VERSION: u16 = 1;

/// Encryption algorithm identifiers
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
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Encrypted file header structure
///
/// This structure contains all metadata needed to decrypt a file,
/// including algorithm information, KDF parameters, IV, and optional metadata.
#[derive(Debug, Clone)]
pub struct EncryptedFileHeader {
    /// Magic bytes for file identification: "CRYPTOOL"
    pub magic: [u8; 8],
    
    /// File format version
    pub version: u16,
    
    /// Encryption algorithm used
    pub algorithm: Algorithm,
    
    /// Key derivation function (None if raw key was used)
    pub kdf: Option<KdfAlgorithm>,
    
    /// KDF iteration count (None if KDF not used)
    pub kdf_iterations: Option<u32>,
    
    /// Salt for key derivation (None if KDF not used)
    pub salt: Option<Vec<u8>>,
    
    /// Initialization vector or nonce
    pub iv: Vec<u8>,
    
    /// Whether the data was compressed before encryption
    pub compressed: bool,
    
    /// Compression algorithm used (None if not compressed)
    pub compression_algo: Option<CompressionAlgorithm>,
    
    /// Original unencrypted file size
    pub original_size: u64,
    
    /// Additional metadata in JSON format
    pub metadata: Vec<u8>,
}

impl EncryptedFileHeader {
    /// Create a new encrypted file header with default values
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
    pub fn with_kdf(mut self, kdf: KdfAlgorithm, iterations: u32, salt: Vec<u8>) -> Self {
        self.kdf = Some(kdf);
        self.kdf_iterations = Some(iterations);
        self.salt = Some(salt);
        self
    }
    
    /// Set compression parameters
    pub fn with_compression(mut self, algo: CompressionAlgorithm) -> Self {
        self.compressed = true;
        self.compression_algo = Some(algo);
        self
    }
    
    /// Set metadata
    pub fn with_metadata(mut self, metadata: Vec<u8>) -> Self {
        self.metadata = metadata;
        self
    }
    
    /// Serialize the header to binary format and write to a writer
    ///
    /// Format:
    /// - Magic Bytes (8 bytes): "CRYPTOOL"
    /// - Version (2 bytes): u16 little-endian
    /// - Algorithm ID (1 byte)
    /// - Flags (1 byte): [compressed|reserved|reserved|...]
    /// - Compression Algorithm (1 byte, 0x00 if not compressed)
    /// - KDF Algorithm (1 byte, 0x00 if not used)
    /// - KDF Iterations (4 bytes, 0 if not used)
    /// - Salt Length (1 byte)
    /// - Salt (variable, 0-255 bytes)
    /// - IV Length (1 byte)
    /// - IV (variable, typically 12-16 bytes)
    /// - Original Size (8 bytes)
    /// - Metadata Length (2 bytes)
    /// - Metadata (variable, JSON format)
    /// - Header Checksum (32 bytes, SHA-256)
    ///
    /// # Arguments
    /// * `writer` - The writer to write the header to
    ///
    /// # Returns
    /// Ok(()) on success, or an error if writing fails
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
            return Err(CryptoError::InvalidArguments("Salt too long (max 255 bytes)".to_string()));
        }
        header_data.push(salt.len() as u8);
        header_data.extend_from_slice(salt);
        
        // IV Length and IV
        if self.iv.len() > 255 {
            return Err(CryptoError::InvalidArguments("IV too long (max 255 bytes)".to_string()));
        }
        header_data.push(self.iv.len() as u8);
        header_data.extend_from_slice(&self.iv);
        
        // Original Size (8 bytes, little-endian)
        header_data.extend_from_slice(&self.original_size.to_le_bytes());
        
        // Metadata Length and Metadata
        if self.metadata.len() > 65535 {
            return Err(CryptoError::InvalidArguments("Metadata too long (max 65535 bytes)".to_string()));
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
            .map_err(|e| CryptoError::SystemError(format!("Failed to write header: {}", e)))?;
        
        // Write checksum (32 bytes)
        writer.write_all(&checksum)
            .map_err(|e| CryptoError::SystemError(format!("Failed to write header checksum: {}", e)))?;
        
        Ok(())
    }
    
    /// Deserialize the header from binary format and read from a reader
    ///
    /// This function reads the header, verifies the checksum, and validates
    /// the version and algorithm IDs.
    ///
    /// # Arguments
    /// * `reader` - The reader to read the header from
    ///
    /// # Returns
    /// The deserialized EncryptedFileHeader on success, or an error if reading,
    /// verification, or validation fails
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
///
/// This function implements the complete file encryption workflow:
/// 1. Read plaintext file
/// 2. Optionally compress the data
/// 3. Encrypt with the chosen algorithm
/// 4. Write encrypted file with header
///
/// # Arguments
/// * `input_path` - Path to the plaintext file
/// * `output_path` - Path for the encrypted output file
/// * `key` - Encryption key
/// * `algorithm` - Encryption algorithm to use
/// * `compression` - Optional compression algorithm
/// * `kdf_params` - Optional KDF parameters (if key was derived from password)
///
/// # Returns
/// Ok(()) on success, or an error if encryption fails
pub fn encrypt_file(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    key: &crate::key_manager::SecureBytes,
    algorithm: Algorithm,
    compression: Option<CompressionAlgorithm>,
    kdf_params: Option<(KdfAlgorithm, u32, Vec<u8>)>, // (kdf, iterations, salt)
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
            return Err(CryptoError::InvalidArguments(
                "Asymmetric algorithms not supported for direct file encryption".to_string()
            ));
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
///
/// This function implements the complete file decryption workflow:
/// 1. Read and parse encrypted file header
/// 2. Verify authentication tag
/// 3. Decrypt ciphertext
/// 4. Optionally decompress
/// 5. Write plaintext file
///
/// # Arguments
/// * `input_path` - Path to the encrypted file
/// * `output_path` - Path for the decrypted output file
/// * `key` - Decryption key
///
/// # Returns
/// Ok(()) on success, or an error if decryption fails
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
            return Err(CryptoError::InvalidArguments(
                "Asymmetric algorithms not supported for direct file decryption".to_string()
            ));
        }
    };
    
    if encrypted_data.len() < auth_size {
        return Err(CryptoError::DecryptionFailed("File too short".to_string()));
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
            return Err(CryptoError::InvalidArguments(
                "Unsupported algorithm for file decryption".to_string()
            ));
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
/// 
/// This module provides utilities for atomic file operations that ensure
/// data integrity even in the presence of failures or crashes.
pub mod atomic {
    use crate::error::{CryptoError, Result};
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    
    /// A temporary file that will be cleaned up on drop if not committed
    pub struct AtomicFile {
        temp_path: PathBuf,
        final_path: PathBuf,
        file: Option<File>,
        committed: bool,
    }
    
    impl AtomicFile {
        /// Create a new atomic file operation
        /// 
        /// This creates a temporary file that will be atomically renamed
        /// to the final path when committed.
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
        pub fn file_mut(&mut self) -> Result<&mut File> {
            self.file.as_mut().ok_or_else(|| {
                CryptoError::SystemError("Atomic file already closed".to_string())
            })
        }
        
        /// Write data to the temporary file
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
