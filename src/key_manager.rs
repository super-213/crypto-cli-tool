// Key Manager module - key derivation, generation, and management
// 密钥管理器模块 - 密钥派生、生成和管理

use crate::error::{CryptoError, Result};
use crate::i18n;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use std::num::NonZeroU32;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// SecureBytes is a wrapper around Vec<u8> that zeros memory on drop
/// This ensures sensitive key material is cleared from memory when no longer needed
/// SecureBytes 是 Vec<u8> 的包装器，在销毁时清零内存
/// 这确保敏感的密钥材料在不再需要时从内存中清除
#[derive(Clone)]
pub struct SecureBytes {
    data: Vec<u8>,
}

impl SecureBytes {
    /// Create a new SecureBytes from a Vec<u8>
    /// 从 Vec<u8> 创建新的 SecureBytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a new SecureBytes with a specific capacity
    /// 创建具有特定容量的新 SecureBytes
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Create a new SecureBytes filled with zeros
    /// 创建填充零的新 SecureBytes
    pub fn zeros(len: usize) -> Self {
        Self {
            data: vec![0u8; len],
        }
    }

    /// Get the length of the data
    /// 获取数据的长度
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the data is empty
    /// 检查数据是否为空
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Convert to a Vec<u8>, consuming self
    /// 转换为 Vec<u8>，消耗 self
    pub fn into_vec(mut self) -> Vec<u8> {
        // Take ownership of the inner vec without zeroing
        // 获取内部 vec 的所有权而不清零
        std::mem::take(&mut self.data)
    }

    /// Get a reference to the inner data as a slice
    /// 获取内部数据的切片引用
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the inner data as a slice
    /// 获取内部数据的可变切片引用
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Deref for SecureBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecureBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        // Zero the memory before deallocation
        // 在释放前清零内存
        self.data.zeroize();
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for SecureBytes {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for SecureBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

/// SecureString is a wrapper around String that zeros memory on drop
/// This ensures sensitive password/passphrase material is cleared from memory when no longer needed
/// SecureString 是 String 的包装器，在销毁时清零内存
/// 这确保敏感的密码/口令材料在不再需要时从内存中清除
#[derive(Clone)]
pub struct SecureString {
    data: String,
}

impl SecureString {
    /// Create a new SecureString from a String
    pub fn new(data: String) -> Self {
        Self { data }
    }

    /// Create a new empty SecureString
    pub fn empty() -> Self {
        Self {
            data: String::new(),
        }
    }

    /// Create a new SecureString with a specific capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: String::with_capacity(capacity),
        }
    }

    /// Get the length of the string in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the string is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Convert to a String, consuming self
    pub fn into_string(mut self) -> String {
        // Take ownership of the inner string without zeroing
        std::mem::take(&mut self.data)
    }

    /// Get a reference to the inner string as a str
    pub fn as_str(&self) -> &str {
        &self.data
    }

    /// Convert to bytes for cryptographic operations
    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_bytes()
    }
}

impl Deref for SecureString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Zero the memory before deallocation
        // 在释放前清零内存
        // SAFETY: We're zeroing the string's bytes, which is safe
        // The string will be dropped immediately after
        // 安全性：我们正在清零字符串的字节，这是安全的
        // 字符串将在之后立即被销毁
        unsafe {
            self.data.as_bytes_mut().zeroize();
        }
    }
}

impl From<String> for SecureString {
    fn from(data: String) -> Self {
        Self::new(data)
    }
}

impl From<&str> for SecureString {
    fn from(data: &str) -> Self {
        Self::new(data.to_string())
    }
}

impl AsRef<str> for SecureString {
    fn as_ref(&self) -> &str {
        &self.data
    }
}


/// Key Derivation Function algorithms
/// 密钥派生函数算法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    Pbkdf2Sha256,
    Argon2id,
}

/// Algorithm types for key generation
/// 密钥生成的算法类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Aes256Gcm,
    Aes256Cbc,
    ChaCha20Poly1305,
    RsaOaep2048,
    RsaOaep4096,
    EciesP256,
}

impl Algorithm {
    /// Get the key size in bytes for symmetric algorithms
    /// 获取对称算法的密钥大小（字节）
    pub fn key_size(&self) -> usize {
        match self {
            Algorithm::Aes256Gcm => 32,
            Algorithm::Aes256Cbc => 32,
            Algorithm::ChaCha20Poly1305 => 32,
            Algorithm::RsaOaep2048 => 0, // Asymmetric - no fixed key size / 非对称 - 无固定密钥大小
            Algorithm::RsaOaep4096 => 0, // Asymmetric - no fixed key size / 非对称 - 无固定密钥大小
            Algorithm::EciesP256 => 0,   // Asymmetric - no fixed key size / 非对称 - 无固定密钥大小
        }
    }
}

/// Asymmetric algorithm types for key pair generation
/// 密钥对生成的非对称算法类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsymmetricAlgorithm {
    RsaOaep2048,
    RsaOaep4096,
    EciesP256,
}

/// Key pair structure for asymmetric algorithms
/// 非对称算法的密钥对结构
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: SecureBytes,
}

/// Derive a key from a password using PBKDF2-SHA256
/// 使用 PBKDF2-SHA256 从密码派生密钥
///
/// # Arguments / 参数
/// * `password` - The password to derive from / 要派生的密码
/// * `salt` - The salt (should be at least 16 bytes, preferably 32) / 盐（应至少 16 字节，最好 32 字节）
/// * `iterations` - Number of iterations (minimum 100,000 recommended) / 迭代次数（建议最少 100,000）
/// * `output_length` - Length of the derived key in bytes / 派生密钥的长度（字节）
///
/// # Returns / 返回值
/// A SecureBytes containing the derived key / 包含派生密钥的 SecureBytes
pub fn derive_key_pbkdf2(
    password: &SecureString,
    salt: &[u8],
    iterations: u32,
    output_length: usize,
) -> Result<SecureBytes> {
    let mut key = SecureBytes::zeros(output_length);
    
    let iterations = NonZeroU32::new(iterations)
        .ok_or(CryptoError::KeyDerivationFailed)?;
    
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password.as_bytes(),
        key.as_mut_slice(),
    );
    
    Ok(key)
}

/// Derive a key from a password using Argon2id
/// 使用 Argon2id 从密码派生密钥
///
/// # Arguments / 参数
/// * `password` - The password to derive from / 要派生的密码
/// * `salt` - The salt (should be at least 16 bytes, preferably 32) / 盐（应至少 16 字节，最好 32 字节）
/// * `memory_cost` - Memory cost in KiB (default: 19456 = 19 MiB) / 内存成本（KiB）（默认：19456 = 19 MiB）
/// * `time_cost` - Time cost / iterations (default: 2) / 时间成本/迭代次数（默认：2）
/// * `output_length` - Length of the derived key in bytes / 派生密钥的长度（字节）
///
/// # Returns / 返回值
/// A SecureBytes containing the derived key / 包含派生密钥的 SecureBytes
pub fn derive_key_argon2id(
    password: &SecureString,
    salt: &[u8],
    memory_cost: u32,
    time_cost: u32,
    output_length: usize,
) -> Result<SecureBytes> {
    // Create Argon2 context with specified parameters
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(memory_cost, time_cost, 1, Some(output_length))
            .map_err(|_| CryptoError::KeyDerivationFailed)?,
    );
    
    // Convert salt to SaltString format
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    
    // Derive the key
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    
    // Extract the hash bytes
    let hash_bytes = password_hash
        .hash
        .ok_or(CryptoError::KeyDerivationFailed)?;
    
    // Convert to SecureBytes
    let key = SecureBytes::from(hash_bytes.as_bytes());
    
    Ok(key)
}


/// Generate a cryptographically secure random salt
/// 生成加密安全的随机盐
///
/// # Returns / 返回值
/// A 32-byte array containing the random salt / 包含随机盐的 32 字节数组
pub fn generate_salt() -> Result<[u8; 32]> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; 32];
    
    rng.fill(&mut salt)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    Ok(salt)
}

/// Generate a symmetric key of the specified length
/// 生成指定长度的对称密钥
///
/// # Arguments / 参数
/// * `algorithm` - The algorithm to generate a key for / 要生成密钥的算法
///
/// # Returns / 返回值
/// A SecureBytes containing the random key / 包含随机密钥的 SecureBytes
pub fn generate_symmetric_key(algorithm: Algorithm) -> Result<SecureBytes> {
    let key_size = algorithm.key_size();
    
    if key_size == 0 {
        let msg = if i18n::is_zh() {
            "无法为非对称算法生成对称密钥".to_string()
        } else {
            "Cannot generate symmetric key for asymmetric algorithm".to_string()
        };
        return Err(CryptoError::InvalidArguments(msg));
    }
    
    let rng = SystemRandom::new();
    let mut key = SecureBytes::zeros(key_size);
    
    rng.fill(key.as_mut_slice())
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    Ok(key)
}

/// Generate an asymmetric key pair
/// 生成非对称密钥对
///
/// # Arguments / 参数
/// * `algorithm` - The asymmetric algorithm to generate keys for / 要生成密钥的非对称算法
///
/// # Returns / 返回值
/// A KeyPair containing the public and private keys / 包含公钥和私钥的 KeyPair
pub fn generate_key_pair(algorithm: AsymmetricAlgorithm) -> Result<KeyPair> {
    match algorithm {
        AsymmetricAlgorithm::RsaOaep2048 => generate_rsa_key_pair(2048),
        AsymmetricAlgorithm::RsaOaep4096 => generate_rsa_key_pair(4096),
        AsymmetricAlgorithm::EciesP256 => generate_ecies_key_pair(),
    }
}

/// Generate an RSA key pair
/// 生成 RSA 密钥对
fn generate_rsa_key_pair(bits: usize) -> Result<KeyPair> {
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    
    let mut rng = rand::thread_rng();
    
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    let public_key = RsaPublicKey::from(&private_key);
    
    // Encode keys to DER format
    let private_der = private_key
        .to_pkcs8_der()
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    let public_der = public_key
        .to_public_key_der()
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    Ok(KeyPair {
        public_key: public_der.as_bytes().to_vec(),
        private_key: SecureBytes::from(private_der.as_bytes()),
    })
}

/// Generate an ECIES P-256 key pair
/// 生成 ECIES P-256 密钥对
fn generate_ecies_key_pair() -> Result<KeyPair> {
    use p256::SecretKey;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    
    let mut rng = rand::thread_rng();
    
    let private_key = SecretKey::random(&mut rng);
    let public_key = private_key.public_key();
    
    // Encode keys to DER format
    let private_der = private_key
        .to_pkcs8_der()
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    let public_der = public_key
        .to_public_key_der()
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    Ok(KeyPair {
        public_key: public_der.as_bytes().to_vec(),
        private_key: SecureBytes::from(private_der.as_bytes()),
    })
}
