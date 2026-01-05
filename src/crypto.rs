// Crypto module - core cryptographic operations
// 加密模块 - 核心加密操作

use crate::error::{CryptoError, Result};
use crate::key_manager::SecureBytes;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey};
use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use ring::rand::{SecureRandom, SystemRandom};
use rsa::{RsaPrivateKey, RsaPublicKey, Oaep};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use p256::{SecretKey, PublicKey, ecdh::EphemeralSecret, ecdh::diffie_hellman};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use hkdf::Hkdf;

type HmacSha256 = Hmac<Sha256>;

/// Result of an encryption operation
/// 加密操作的结果
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub tag: Option<Vec<u8>>,  // For AEAD modes / 用于 AEAD 模式
    pub mac: Option<Vec<u8>>,  // For non-AEAD modes (CBC + HMAC) / 用于非 AEAD 模式（CBC + HMAC）
}

/// Result of a hybrid encryption operation
/// 混合加密操作的结果
#[derive(Debug, Clone)]
pub struct HybridEncryptionResult {
    pub encrypted_data: EncryptionResult,
    pub encrypted_key: Vec<u8>,
    pub algorithm: HybridAlgorithm,
}

/// Hybrid encryption algorithm types
/// 混合加密算法类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridAlgorithm {
    RsaOaep2048Aes256Gcm,
    RsaOaep4096Aes256Gcm,
    EciesP256Aes256Gcm,
}

/// Context for encryption operations
/// 加密操作的上下文
pub struct EncryptionContext {
    pub key: SecureBytes,
    pub iv: Option<Vec<u8>>,  // If None, will be generated / 如果为 None，将自动生成
    pub aad: Option<Vec<u8>>, // Additional authenticated data for AEAD / AEAD 的附加认证数据
}

/// Context for decryption operations
/// 解密操作的上下文
pub struct DecryptionContext {
    pub key: SecureBytes,
    pub iv: Vec<u8>,
    pub tag: Option<Vec<u8>>,
    pub mac: Option<Vec<u8>>,
}

/// Generate a random IV/nonce of the specified length
/// 生成指定长度的随机 IV/nonce
pub fn generate_iv(length: usize) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut iv = vec![0u8; length];
    
    rng.fill(&mut iv)
        .map_err(|_| CryptoError::SystemError("Failed to generate IV".to_string()))?;
    
    Ok(iv)
}

/// Encrypt data using AES-256-GCM
/// 使用 AES-256-GCM 加密数据
///
/// # Arguments / 参数
/// * `plaintext` - The data to encrypt / 要加密的数据
/// * `context` - Encryption context containing key, optional IV, and optional AAD / 包含密钥、可选 IV 和可选 AAD 的加密上下文
///
/// # Returns / 返回值
/// EncryptionResult containing ciphertext, IV, and authentication tag / 包含密文、IV 和认证标签的 EncryptionResult
pub fn encrypt_aes_256_gcm(
    plaintext: &[u8],
    context: &EncryptionContext,
) -> Result<EncryptionResult> {
    // Validate key size / 验证密钥大小
    if context.key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    
    // Generate or use provided IV (12 bytes for GCM) / 生成或使用提供的 IV（GCM 需要 12 字节）
    let iv = match &context.iv {
        Some(iv) => {
            if iv.len() != 12 {
                return Err(CryptoError::InvalidIV);
            }
            iv.clone()
        }
        None => generate_iv(12)?,
    };
    
    // Create cipher instance / 创建密码实例
    let cipher = Aes256Gcm::new_from_slice(context.key.as_ref())
        .map_err(|_| CryptoError::InvalidKey)?;
    
    let nonce = Nonce::from_slice(&iv);
    
    // Prepare payload with optional AAD / 准备带有可选 AAD 的有效载荷
    let payload = match &context.aad {
        Some(aad) => Payload {
            msg: plaintext,
            aad: aad.as_slice(),
        },
        None => Payload {
            msg: plaintext,
            aad: &[],
        },
    };
    
    // Encrypt and get ciphertext with tag appended / 加密并获取附加标签的密文
    let ciphertext_with_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed("AES-256-GCM encryption failed".to_string()))?;
    
    // Split ciphertext and tag (tag is last 16 bytes) / 分离密文和标签（标签是最后 16 字节）
    let tag_len = 16;
    if ciphertext_with_tag.len() < tag_len {
        return Err(CryptoError::EncryptionFailed("Invalid ciphertext length".to_string()));
    }
    
    let split_point = ciphertext_with_tag.len() - tag_len;
    let ciphertext = ciphertext_with_tag[..split_point].to_vec();
    let tag = ciphertext_with_tag[split_point..].to_vec();
    
    Ok(EncryptionResult {
        ciphertext,
        iv,
        tag: Some(tag),
        mac: None,
    })
}

/// Decrypt data using AES-256-GCM
/// 使用 AES-256-GCM 解密数据
///
/// # Arguments / 参数
/// * `ciphertext` - The encrypted data / 加密的数据
/// * `context` - Decryption context containing key, IV, and authentication tag / 包含密钥、IV 和认证标签的解密上下文
///
/// # Returns / 返回值
/// Decrypted plaintext / 解密的明文
pub fn decrypt_aes_256_gcm(
    ciphertext: &[u8],
    context: &DecryptionContext,
) -> Result<Vec<u8>> {
    // Validate key size
    if context.key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    
    // Validate IV size
    if context.iv.len() != 12 {
        return Err(CryptoError::InvalidIV);
    }
    
    // Get authentication tag
    let tag = context.tag.as_ref()
        .ok_or(CryptoError::AuthenticationFailed)?;
    
    if tag.len() != 16 {
        return Err(CryptoError::AuthenticationFailed);
    }
    
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(context.key.as_ref())
        .map_err(|_| CryptoError::InvalidKey)?;
    
    let nonce = Nonce::from_slice(&context.iv);
    
    // Combine ciphertext and tag for decryption
    let mut ciphertext_with_tag = ciphertext.to_vec();
    ciphertext_with_tag.extend_from_slice(tag);
    
    // Decrypt and verify
    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag.as_slice())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    
    Ok(plaintext)
}

/// Encrypt data using ChaCha20-Poly1305
/// 使用 ChaCha20-Poly1305 加密数据
///
/// # Arguments / 参数
/// * `plaintext` - The data to encrypt / 要加密的数据
/// * `context` - Encryption context containing key, optional IV, and optional AAD / 包含密钥、可选 IV 和可选 AAD 的加密上下文
///
/// # Returns / 返回值
/// EncryptionResult containing ciphertext, nonce, and authentication tag / 包含密文、nonce 和认证标签的 EncryptionResult
pub fn encrypt_chacha20_poly1305(
    plaintext: &[u8],
    context: &EncryptionContext,
) -> Result<EncryptionResult> {
    // Validate key size
    if context.key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    
    // Generate or use provided nonce (12 bytes for ChaCha20-Poly1305)
    let nonce_bytes = match &context.iv {
        Some(iv) => {
            if iv.len() != 12 {
                return Err(CryptoError::InvalidIV);
            }
            iv.clone()
        }
        None => generate_iv(12)?,
    };
    
    // Create cipher instance
    let key = ChaChaKey::from_slice(context.key.as_ref());
    let cipher = ChaCha20Poly1305::new(key);
    
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    
    // Prepare payload with optional AAD
    let payload = match &context.aad {
        Some(aad) => Payload {
            msg: plaintext,
            aad: aad.as_slice(),
        },
        None => Payload {
            msg: plaintext,
            aad: &[],
        },
    };
    
    // Encrypt and get ciphertext with tag appended
    let ciphertext_with_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed("ChaCha20-Poly1305 encryption failed".to_string()))?;
    
    // Split ciphertext and tag (tag is last 16 bytes)
    let tag_len = 16;
    if ciphertext_with_tag.len() < tag_len {
        return Err(CryptoError::EncryptionFailed("Invalid ciphertext length".to_string()));
    }
    
    let split_point = ciphertext_with_tag.len() - tag_len;
    let ciphertext = ciphertext_with_tag[..split_point].to_vec();
    let tag = ciphertext_with_tag[split_point..].to_vec();
    
    Ok(EncryptionResult {
        ciphertext,
        iv: nonce_bytes,
        tag: Some(tag),
        mac: None,
    })
}

/// Decrypt data using ChaCha20-Poly1305
/// 使用 ChaCha20-Poly1305 解密数据
///
/// # Arguments / 参数
/// * `ciphertext` - The encrypted data / 加密的数据
/// * `context` - Decryption context containing key, nonce, and authentication tag / 包含密钥、nonce 和认证标签的解密上下文
///
/// # Returns / 返回值
/// Decrypted plaintext / 解密的明文
pub fn decrypt_chacha20_poly1305(
    ciphertext: &[u8],
    context: &DecryptionContext,
) -> Result<Vec<u8>> {
    // Validate key size
    if context.key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    
    // Validate nonce size
    if context.iv.len() != 12 {
        return Err(CryptoError::InvalidIV);
    }
    
    // Get authentication tag
    let tag = context.tag.as_ref()
        .ok_or(CryptoError::AuthenticationFailed)?;
    
    if tag.len() != 16 {
        return Err(CryptoError::AuthenticationFailed);
    }
    
    // Create cipher instance
    let key = ChaChaKey::from_slice(context.key.as_ref());
    let cipher = ChaCha20Poly1305::new(key);
    
    let nonce = chacha20poly1305::Nonce::from_slice(&context.iv);
    
    // Combine ciphertext and tag for decryption
    let mut ciphertext_with_tag = ciphertext.to_vec();
    ciphertext_with_tag.extend_from_slice(tag);
    
    // Decrypt and verify
    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag.as_slice())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    
    Ok(plaintext)
}

/// Encrypt data using AES-256-CBC with HMAC-SHA256 (Encrypt-then-MAC)
/// 使用 AES-256-CBC 和 HMAC-SHA256 加密数据（先加密后 MAC）
///
/// # Arguments / 参数
/// * `plaintext` - The data to encrypt / 要加密的数据
/// * `context` - Encryption context containing key and optional IV / 包含密钥和可选 IV 的加密上下文
///
/// # Returns / 返回值
/// EncryptionResult containing ciphertext, IV, and HMAC / 包含密文、IV 和 HMAC 的 EncryptionResult
pub fn encrypt_aes_256_cbc_hmac(
    plaintext: &[u8],
    context: &EncryptionContext,
) -> Result<EncryptionResult> {
    // Validate key size (32 bytes for AES-256)
    if context.key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    
    // Generate or use provided IV (16 bytes for AES-CBC)
    let iv = match &context.iv {
        Some(iv) => {
            if iv.len() != 16 {
                return Err(CryptoError::InvalidIV);
            }
            iv.clone()
        }
        None => generate_iv(16)?,
    };
    
    // Apply PKCS7 padding
    let padded_plaintext = pkcs7_pad(plaintext, 16);
    
    // Encrypt using AES-256-CBC
    type Aes256CbcEnc = cbc::Encryptor<Aes256>;
    
    let cipher = Aes256CbcEnc::new_from_slices(context.key.as_ref(), &iv)
        .map_err(|_| CryptoError::InvalidKey)?;
    
    let mut buffer = padded_plaintext.clone();
    let ciphertext = cipher.encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buffer, padded_plaintext.len())
        .map_err(|_| CryptoError::EncryptionFailed("AES-256-CBC encryption failed".to_string()))?
        .to_vec();
    
    // Compute HMAC-SHA256 over IV || ciphertext (Encrypt-then-MAC)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(context.key.as_ref())
        .map_err(|_| CryptoError::InvalidKey)?;
    
    mac.update(&iv);
    mac.update(&ciphertext);
    
    let mac_result = mac.finalize().into_bytes().to_vec();
    
    Ok(EncryptionResult {
        ciphertext,
        iv,
        tag: None,
        mac: Some(mac_result),
    })
}

/// Decrypt data using AES-256-CBC with HMAC-SHA256 verification
/// 使用 AES-256-CBC 和 HMAC-SHA256 验证解密数据
///
/// # Arguments / 参数
/// * `ciphertext` - The encrypted data / 加密的数据
/// * `context` - Decryption context containing key, IV, and HMAC / 包含密钥、IV 和 HMAC 的解密上下文
///
/// # Returns / 返回值
/// Decrypted plaintext / 解密的明文
pub fn decrypt_aes_256_cbc_hmac(
    ciphertext: &[u8],
    context: &DecryptionContext,
) -> Result<Vec<u8>> {
    // Validate key size
    if context.key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    
    // Validate IV size
    if context.iv.len() != 16 {
        return Err(CryptoError::InvalidIV);
    }
    
    // Get HMAC
    let expected_mac = context.mac.as_ref()
        .ok_or(CryptoError::AuthenticationFailed)?;
    
    // Verify HMAC before decryption (Encrypt-then-MAC)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(context.key.as_ref())
        .map_err(|_| CryptoError::InvalidKey)?;
    
    mac.update(&context.iv);
    mac.update(ciphertext);
    
    mac.verify_slice(expected_mac)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    
    // Decrypt using AES-256-CBC
    type Aes256CbcDec = cbc::Decryptor<Aes256>;
    
    let cipher = Aes256CbcDec::new_from_slices(context.key.as_ref(), &context.iv)
        .map_err(|_| CryptoError::InvalidKey)?;
    
    let mut buffer = ciphertext.to_vec();
    let plaintext = cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buffer)
        .map_err(|_| CryptoError::DecryptionFailed("AES-256-CBC decryption failed".to_string()))?;
    
    // Remove PKCS7 padding
    let unpadded = pkcs7_unpad(plaintext)?;
    
    Ok(unpadded.to_vec())
}

/// Apply PKCS7 padding to data
/// 对数据应用 PKCS7 填充
fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(vec![padding_len as u8; padding_len]);
    padded
}

/// Remove PKCS7 padding from data
/// 从数据中移除 PKCS7 填充
fn pkcs7_unpad(data: &[u8]) -> Result<&[u8]> {
    if data.is_empty() {
        return Err(CryptoError::DecryptionFailed("Empty data for unpadding".to_string()));
    }
    
    let padding_len = data[data.len() - 1] as usize;
    
    if padding_len == 0 || padding_len > 16 {
        return Err(CryptoError::DecryptionFailed("Invalid padding".to_string()));
    }
    
    if data.len() < padding_len {
        return Err(CryptoError::DecryptionFailed("Invalid padding length".to_string()));
    }
    
    // Verify all padding bytes are correct
    for i in 0..padding_len {
        if data[data.len() - 1 - i] != padding_len as u8 {
            return Err(CryptoError::DecryptionFailed("Invalid padding bytes".to_string()));
        }
    }
    
    Ok(&data[..data.len() - padding_len])
}


/// Encrypt data using RSA-OAEP
/// 使用 RSA-OAEP 加密数据
///
/// # Arguments / 参数
/// * `plaintext` - The data to encrypt (must be smaller than key size - padding overhead) / 要加密的数据（必须小于密钥大小 - 填充开销）
/// * `public_key_der` - The RSA public key in DER format / DER 格式的 RSA 公钥
///
/// # Returns / 返回值
/// Encrypted ciphertext / 加密的密文
pub fn encrypt_rsa_oaep(
    plaintext: &[u8],
    public_key_der: &[u8],
) -> Result<Vec<u8>> {
    // Decode the public key from DER format
    let public_key = RsaPublicKey::from_public_key_der(public_key_der)
        .map_err(|_| CryptoError::InvalidKey)?;
    
    // Create OAEP padding with SHA-256
    let padding = Oaep::new::<sha2::Sha256>();
    
    // Encrypt the plaintext
    let mut rng = rand::thread_rng();
    let ciphertext = public_key
        .encrypt(&mut rng, padding, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed("RSA-OAEP encryption failed".to_string()))?;
    
    Ok(ciphertext)
}

/// Decrypt data using RSA-OAEP
/// 使用 RSA-OAEP 解密数据
///
/// # Arguments / 参数
/// * `ciphertext` - The encrypted data / 加密的数据
/// * `private_key_der` - The RSA private key in DER format / DER 格式的 RSA 私钥
///
/// # Returns / 返回值
/// Decrypted plaintext / 解密的明文
pub fn decrypt_rsa_oaep(
    ciphertext: &[u8],
    private_key_der: &[u8],
) -> Result<Vec<u8>> {
    // Decode the private key from DER format
    let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
        .map_err(|_| CryptoError::InvalidKey)?;
    
    // Create OAEP padding with SHA-256
    let padding = Oaep::new::<sha2::Sha256>();
    
    // Decrypt the ciphertext
    let plaintext = private_key
        .decrypt(padding, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed("RSA-OAEP decryption failed".to_string()))?;
    
    Ok(plaintext)
}

/// Encrypt data using ECIES with P-256 curve
/// 使用 P-256 曲线的 ECIES 加密数据
///
/// ECIES (Elliptic Curve Integrated Encryption Scheme) combines:
/// ECIES（椭圆曲线集成加密方案）结合了：
/// 1. ECDH for key agreement / ECDH 用于密钥协商
/// 2. HKDF for key derivation / HKDF 用于密钥派生
/// 3. AES-256-GCM for symmetric encryption / AES-256-GCM 用于对称加密
///
/// # Arguments / 参数
/// * `plaintext` - The data to encrypt / 要加密的数据
/// * `public_key_der` - The P-256 public key in DER format / DER 格式的 P-256 公钥
///
/// # Returns / 返回值
/// Encrypted data with ephemeral public key prepended / 前置临时公钥的加密数据
pub fn encrypt_ecies_p256(
    plaintext: &[u8],
    public_key_der: &[u8],
) -> Result<Vec<u8>> {
    // Decode the recipient's public key from DER format
    let recipient_public_key = PublicKey::from_public_key_der(public_key_der)
        .map_err(|_| CryptoError::InvalidKey)?;
    
    // Generate ephemeral key pair
    let mut rng = rand::thread_rng();
    let ephemeral_secret = EphemeralSecret::random(&mut rng);
    let ephemeral_public = ephemeral_secret.public_key();
    
    // Perform ECDH to get shared secret
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public_key);
    
    // Derive encryption key using HKDF-SHA256
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
    let mut derived_key = [0u8; 32];
    hkdf.expand(b"ecies-encryption-key", &mut derived_key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    
    // Encrypt the plaintext using AES-256-GCM
    let key = SecureBytes::from(&derived_key[..]);
    let context = EncryptionContext {
        key,
        iv: None, // Will be generated
        aad: None,
    };
    
    let encryption_result = encrypt_aes_256_gcm(plaintext, &context)?;
    
    // Encode ephemeral public key to compressed SEC1 format
    let ephemeral_public_bytes = ephemeral_public.to_encoded_point(true).as_bytes().to_vec();
    
    // Package: ephemeral_public_key || iv || ciphertext || tag
    let mut result = Vec::new();
    result.push(ephemeral_public_bytes.len() as u8); // 1 byte length prefix
    result.extend_from_slice(&ephemeral_public_bytes);
    result.push(encryption_result.iv.len() as u8); // 1 byte length prefix
    result.extend_from_slice(&encryption_result.iv);
    result.extend_from_slice(&encryption_result.ciphertext);
    result.extend_from_slice(&encryption_result.tag.unwrap());
    
    Ok(result)
}

/// Decrypt data using ECIES with P-256 curve
/// 使用 P-256 曲线的 ECIES 解密数据
///
/// # Arguments / 参数
/// * `ciphertext` - The encrypted data (ephemeral public key || iv || ciphertext || tag) / 加密的数据（临时公钥 || iv || 密文 || 标签）
/// * `private_key_der` - The P-256 private key in DER format / DER 格式的 P-256 私钥
///
/// # Returns / 返回值
/// Decrypted plaintext / 解密的明文
pub fn decrypt_ecies_p256(
    ciphertext: &[u8],
    private_key_der: &[u8],
) -> Result<Vec<u8>> {
    // Decode the private key from DER format
    let private_key = SecretKey::from_pkcs8_der(private_key_der)
        .map_err(|_| CryptoError::InvalidKey)?;
    
    // Parse the encrypted data structure
    if ciphertext.len() < 2 {
        return Err(CryptoError::DecryptionFailed("Invalid ciphertext format".to_string()));
    }
    
    let mut offset = 0;
    
    // Read ephemeral public key
    let ephemeral_public_len = ciphertext[offset] as usize;
    offset += 1;
    
    if ciphertext.len() < offset + ephemeral_public_len {
        return Err(CryptoError::DecryptionFailed("Invalid ciphertext format".to_string()));
    }
    
    let ephemeral_public_bytes = &ciphertext[offset..offset + ephemeral_public_len];
    offset += ephemeral_public_len;
    
    // Decode ephemeral public key
    let ephemeral_public = PublicKey::from_sec1_bytes(ephemeral_public_bytes)
        .map_err(|_| CryptoError::InvalidKey)?;
    
    // Read IV
    if ciphertext.len() < offset + 1 {
        return Err(CryptoError::DecryptionFailed("Invalid ciphertext format".to_string()));
    }
    
    let iv_len = ciphertext[offset] as usize;
    offset += 1;
    
    if ciphertext.len() < offset + iv_len {
        return Err(CryptoError::DecryptionFailed("Invalid ciphertext format".to_string()));
    }
    
    let iv = ciphertext[offset..offset + iv_len].to_vec();
    offset += iv_len;
    
    // Remaining data is ciphertext + tag (tag is last 16 bytes)
    if ciphertext.len() < offset + 16 {
        return Err(CryptoError::DecryptionFailed("Invalid ciphertext format".to_string()));
    }
    
    let encrypted_data = &ciphertext[offset..];
    let tag_offset = encrypted_data.len() - 16;
    let encrypted_plaintext = &encrypted_data[..tag_offset];
    let tag = encrypted_data[tag_offset..].to_vec();
    
    // Perform ECDH to get shared secret
    let shared_secret = diffie_hellman(
        private_key.to_nonzero_scalar(),
        ephemeral_public.as_affine(),
    );
    
    // Derive decryption key using HKDF-SHA256
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
    let mut derived_key = [0u8; 32];
    hkdf.expand(b"ecies-encryption-key", &mut derived_key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    
    // Decrypt the ciphertext using AES-256-GCM
    let key = SecureBytes::from(&derived_key[..]);
    let context = DecryptionContext {
        key,
        iv,
        tag: Some(tag),
        mac: None,
    };
    
    let plaintext = decrypt_aes_256_gcm(encrypted_plaintext, &context)?;
    
    Ok(plaintext)
}

/// Encrypt data using hybrid encryption (asymmetric + symmetric)
///
/// Hybrid encryption combines the efficiency of symmetric encryption with
/// the key distribution benefits of asymmetric encryption:
/// 1. Generate a random symmetric key
/// 2. Encrypt the data with the symmetric key (AES-256-GCM)
/// 3. Encrypt the symmetric key with the public key (RSA-OAEP or ECIES)
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `public_key_der` - The public key in DER format
/// * `algorithm` - The hybrid algorithm to use
///
/// # Returns
/// HybridEncryptionResult containing encrypted data and encrypted symmetric key
pub fn encrypt_hybrid(
    plaintext: &[u8],
    public_key_der: &[u8],
    algorithm: HybridAlgorithm,
) -> Result<HybridEncryptionResult> {
    // Generate a random 256-bit symmetric key
    let rng = SystemRandom::new();
    let mut symmetric_key = vec![0u8; 32];
    rng.fill(&mut symmetric_key)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    // Encrypt the data with AES-256-GCM
    let key = SecureBytes::from(&symmetric_key[..]);
    let context = EncryptionContext {
        key,
        iv: None, // Will be generated
        aad: None,
    };
    
    let encrypted_data = encrypt_aes_256_gcm(plaintext, &context)?;
    
    // Encrypt the symmetric key with the public key
    let encrypted_key = match algorithm {
        HybridAlgorithm::RsaOaep2048Aes256Gcm | HybridAlgorithm::RsaOaep4096Aes256Gcm => {
            encrypt_rsa_oaep(&symmetric_key, public_key_der)?
        }
        HybridAlgorithm::EciesP256Aes256Gcm => {
            encrypt_ecies_p256(&symmetric_key, public_key_der)?
        }
    };
    
    Ok(HybridEncryptionResult {
        encrypted_data,
        encrypted_key,
        algorithm,
    })
}

/// Decrypt data using hybrid encryption (asymmetric + symmetric)
/// 使用混合加密（非对称 + 对称）解密数据
///
/// # Arguments / 参数
/// * `hybrid_result` - The hybrid encryption result containing encrypted data and key / 包含加密数据和密钥的混合加密结果
/// * `private_key_der` - The private key in DER format / DER 格式的私钥
///
/// # Returns / 返回值
/// Decrypted plaintext / 解密的明文
pub fn decrypt_hybrid(
    hybrid_result: &HybridEncryptionResult,
    private_key_der: &[u8],
) -> Result<Vec<u8>> {
    // Decrypt the symmetric key with the private key
    let symmetric_key = match hybrid_result.algorithm {
        HybridAlgorithm::RsaOaep2048Aes256Gcm | HybridAlgorithm::RsaOaep4096Aes256Gcm => {
            decrypt_rsa_oaep(&hybrid_result.encrypted_key, private_key_der)?
        }
        HybridAlgorithm::EciesP256Aes256Gcm => {
            decrypt_ecies_p256(&hybrid_result.encrypted_key, private_key_der)?
        }
    };
    
    // Decrypt the data with AES-256-GCM
    let key = SecureBytes::from(&symmetric_key[..]);
    let context = DecryptionContext {
        key,
        iv: hybrid_result.encrypted_data.iv.clone(),
        tag: hybrid_result.encrypted_data.tag.clone(),
        mac: None,
    };
    
    let plaintext = decrypt_aes_256_gcm(&hybrid_result.encrypted_data.ciphertext, &context)?;
    
    Ok(plaintext)
}

use std::io::{Read, Write};

/// Chunk size for streaming encryption (64KB)
/// 流式加密的块大小（64KB）
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Result of streaming encryption operation
/// 流式加密操作的结果
#[derive(Debug, Clone)]
pub struct StreamEncryptionResult {
    pub iv: Vec<u8>,
    pub total_chunks: u64,
}

/// Encrypt data from a reader to a writer using streaming with AES-256-GCM
/// 使用 AES-256-GCM 流式加密从读取器到写入器的数据
///
/// This function processes data in 64KB chunks to maintain constant memory usage.
/// Each chunk is encrypted independently with AEAD, using the chunk counter as AAD
/// to prevent reordering attacks.
/// 此函数以 64KB 块处理数据以保持恒定的内存使用。
/// 每个块使用 AEAD 独立加密，使用块计数器作为 AAD 以防止重排序攻击。
///
/// # Arguments / 参数
/// * `reader` - Source of plaintext data / 明文数据源
/// * `writer` - Destination for encrypted data / 加密数据目标
/// * `key` - 256-bit encryption key / 256 位加密密钥
///
/// # Returns / 返回值
/// StreamEncryptionResult containing the IV and total number of chunks / 包含 IV 和总块数的 StreamEncryptionResult
///
/// # Format / 格式
/// The output format is: / 输出格式为：
/// [chunk_0_ciphertext][chunk_0_tag][chunk_1_ciphertext][chunk_1_tag]...
pub fn encrypt_stream_aes_256_gcm<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key: &SecureBytes,
) -> Result<StreamEncryptionResult> {
    // Validate key size
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    
    // Generate a single IV for the entire stream
    let iv = generate_iv(12)?;
    
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| CryptoError::InvalidKey)?;
    
    let mut chunk_counter: u64 = 0;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    
    loop {
        // Read a chunk from the reader
        let bytes_read = reader.read(&mut buffer)
            .map_err(|e| CryptoError::SystemError(format!("Failed to read data: {}", e)))?;
        
        if bytes_read == 0 {
            break; // End of stream
        }
        
        // Prepare AAD with chunk counter to prevent reordering
        let aad = chunk_counter.to_le_bytes();
        
        // Create a unique nonce by XORing the base IV with the chunk counter
        // This ensures each chunk has a unique nonce while maintaining determinism
        let mut chunk_nonce = iv.clone();
        for (i, byte) in aad.iter().enumerate() {
            if i < chunk_nonce.len() {
                chunk_nonce[i] ^= byte;
            }
        }
        
        let nonce = Nonce::from_slice(&chunk_nonce);
        
        // Prepare payload with chunk counter as AAD
        let payload = Payload {
            msg: &buffer[..bytes_read],
            aad: &aad,
        };
        
        // Encrypt the chunk
        let ciphertext_with_tag = cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::EncryptionFailed("Streaming encryption failed".to_string()))?;
        
        // Write encrypted chunk to output
        writer.write_all(&ciphertext_with_tag)
            .map_err(|e| CryptoError::SystemError(format!("Failed to write encrypted data: {}", e)))?;
        
        chunk_counter += 1;
    }
    
    Ok(StreamEncryptionResult {
        iv,
        total_chunks: chunk_counter,
    })
}

/// Encrypt data from a reader to a writer using streaming with ChaCha20-Poly1305
/// 使用 ChaCha20-Poly1305 流式加密从读取器到写入器的数据
///
/// This function processes data in 64KB chunks to maintain constant memory usage.
/// Each chunk is encrypted independently with AEAD, using the chunk counter as AAD
/// to prevent reordering attacks.
/// 此函数以 64KB 块处理数据以保持恒定的内存使用。
/// 每个块使用 AEAD 独立加密，使用块计数器作为 AAD 以防止重排序攻击。
///
/// # Arguments / 参数
/// * `reader` - Source of plaintext data / 明文数据源
/// * `writer` - Destination for encrypted data / 加密数据目标
/// * `key` - 256-bit encryption key / 256 位加密密钥
///
/// # Returns / 返回值
/// StreamEncryptionResult containing the nonce and total number of chunks / 包含 nonce 和总块数的 StreamEncryptionResult
pub fn encrypt_stream_chacha20_poly1305<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key: &SecureBytes,
) -> Result<StreamEncryptionResult> {
    // Validate key size
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    
    // Generate a single nonce for the entire stream
    let nonce_bytes = generate_iv(12)?;
    
    // Create cipher instance
    let cipher_key = ChaChaKey::from_slice(key.as_ref());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    
    let mut chunk_counter: u64 = 0;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    
    loop {
        // Read a chunk from the reader
        let bytes_read = reader.read(&mut buffer)
            .map_err(|e| CryptoError::SystemError(format!("Failed to read data: {}", e)))?;
        
        if bytes_read == 0 {
            break; // End of stream
        }
        
        // Prepare AAD with chunk counter to prevent reordering
        let aad = chunk_counter.to_le_bytes();
        
        // Create a unique nonce by XORing the base nonce with the chunk counter
        let mut chunk_nonce = nonce_bytes.clone();
        for (i, byte) in aad.iter().enumerate() {
            if i < chunk_nonce.len() {
                chunk_nonce[i] ^= byte;
            }
        }
        
        let nonce = chacha20poly1305::Nonce::from_slice(&chunk_nonce);
        
        // Prepare payload with chunk counter as AAD
        let payload = Payload {
            msg: &buffer[..bytes_read],
            aad: &aad,
        };
        
        // Encrypt the chunk
        let ciphertext_with_tag = cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::EncryptionFailed("Streaming encryption failed".to_string()))?;
        
        // Write encrypted chunk to output
        writer.write_all(&ciphertext_with_tag)
            .map_err(|e| CryptoError::SystemError(format!("Failed to write encrypted data: {}", e)))?;
        
        chunk_counter += 1;
    }
    
    Ok(StreamEncryptionResult {
        iv: nonce_bytes,
        total_chunks: chunk_counter,
    })
}

/// Decrypt data from a reader to a writer using streaming with AES-256-GCM
/// 使用 AES-256-GCM 流式解密从读取器到写入器的数据
///
/// This function processes data in chunks to maintain constant memory usage.
/// Each chunk is decrypted and authenticated independently, with the chunk counter
/// verified as AAD to detect reordering attacks.
/// 此函数以块处理数据以保持恒定的内存使用。
/// 每个块独立解密和认证，验证块计数器作为 AAD 以检测重排序攻击。
///
/// # Arguments / 参数
/// * `reader` - Source of encrypted data / 加密数据源
/// * `writer` - Destination for decrypted data / 解密数据目标
/// * `key` - 256-bit decryption key / 256 位解密密钥
/// * `iv` - The IV used during encryption / 加密时使用的 IV
/// * `total_chunks` - Total number of chunks to decrypt / 要解密的总块数
///
/// # Returns / 返回值
/// Ok(()) on success, or an error if decryption or authentication fails / 成功时返回 Ok(())，解密或认证失败时返回错误
pub fn decrypt_stream_aes_256_gcm<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key: &SecureBytes,
    iv: &[u8],
    total_chunks: u64,
) -> Result<()> {
    // Validate key size
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    
    // Validate IV size
    if iv.len() != 12 {
        return Err(CryptoError::InvalidIV);
    }
    
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| CryptoError::InvalidKey)?;
    
    // Each encrypted chunk has: ciphertext + 16-byte tag
    // We need to read chunks of variable size (up to CHUNK_SIZE + 16)
    let max_encrypted_chunk_size = CHUNK_SIZE + 16;
    let mut buffer = vec![0u8; max_encrypted_chunk_size];
    
    for chunk_counter in 0..total_chunks {
        // Determine expected chunk size
        // Last chunk might be smaller, but we don't know the exact size
        // So we try to read up to max_encrypted_chunk_size
        let bytes_read = reader.read(&mut buffer)
            .map_err(|e| CryptoError::SystemError(format!("Failed to read encrypted data: {}", e)))?;
        
        if bytes_read == 0 {
            return Err(CryptoError::DecryptionFailed("Unexpected end of stream".to_string()));
        }
        
        // Prepare AAD with chunk counter
        let aad = chunk_counter.to_le_bytes();
        
        // Create the same unique nonce used during encryption
        let mut chunk_nonce = iv.to_vec();
        for (i, byte) in aad.iter().enumerate() {
            if i < chunk_nonce.len() {
                chunk_nonce[i] ^= byte;
            }
        }
        
        let nonce = Nonce::from_slice(&chunk_nonce);
        
        // Prepare payload with chunk counter as AAD
        let payload = Payload {
            msg: &buffer[..bytes_read],
            aad: &aad,
        };
        
        // Decrypt and verify the chunk
        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        
        // Write decrypted chunk to output
        writer.write_all(&plaintext)
            .map_err(|e| CryptoError::SystemError(format!("Failed to write decrypted data: {}", e)))?;
    }
    
    Ok(())
}

/// Decrypt data from a reader to a writer using streaming with ChaCha20-Poly1305
///
/// This function processes data in chunks to maintain constant memory usage.
/// Each chunk is decrypted and authenticated independently, with the chunk counter
/// verified as AAD to detect reordering attacks.
///
/// # Arguments
/// * `reader` - Source of encrypted data
/// * `writer` - Destination for decrypted data
/// * `key` - 256-bit decryption key
/// * `nonce` - The nonce used during encryption
/// * `total_chunks` - Total number of chunks to decrypt
///
/// # Returns
/// Ok(()) on success, or an error if decryption or authentication fails
pub fn decrypt_stream_chacha20_poly1305<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key: &SecureBytes,
    nonce: &[u8],
    total_chunks: u64,
) -> Result<()> {
    // Validate key size
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    
    // Validate nonce size
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidIV);
    }
    
    // Create cipher instance
    let cipher_key = ChaChaKey::from_slice(key.as_ref());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    
    // Each encrypted chunk has: ciphertext + 16-byte tag
    let max_encrypted_chunk_size = CHUNK_SIZE + 16;
    let mut buffer = vec![0u8; max_encrypted_chunk_size];
    
    for chunk_counter in 0..total_chunks {
        // Read encrypted chunk
        let bytes_read = reader.read(&mut buffer)
            .map_err(|e| CryptoError::SystemError(format!("Failed to read encrypted data: {}", e)))?;
        
        if bytes_read == 0 {
            return Err(CryptoError::DecryptionFailed("Unexpected end of stream".to_string()));
        }
        
        // Prepare AAD with chunk counter
        let aad = chunk_counter.to_le_bytes();
        
        // Create the same unique nonce used during encryption
        let mut chunk_nonce = nonce.to_vec();
        for (i, byte) in aad.iter().enumerate() {
            if i < chunk_nonce.len() {
                chunk_nonce[i] ^= byte;
            }
        }
        
        let nonce_slice = chacha20poly1305::Nonce::from_slice(&chunk_nonce);
        
        // Prepare payload with chunk counter as AAD
        let payload = Payload {
            msg: &buffer[..bytes_read],
            aad: &aad,
        };
        
        // Decrypt and verify the chunk
        let plaintext = cipher
            .decrypt(nonce_slice, payload)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        
        // Write decrypted chunk to output
        writer.write_all(&plaintext)
            .map_err(|e| CryptoError::SystemError(format!("Failed to write decrypted data: {}", e)))?;
    }
    
    Ok(())
}
