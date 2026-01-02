// Compression module - compression and decompression operations

use crate::error::{CryptoError, Result};
use flate2::read::{GzDecoder, GzEncoder};
use flate2::Compression as GzipCompression;
use std::io::{Read, Write};

/// Compression algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    Gzip,
    Zstd,
}

/// Compression context with algorithm and level
#[derive(Debug, Clone)]
pub struct CompressionContext {
    pub algorithm: CompressionAlgorithm,
    pub level: u32,
}

impl CompressionContext {
    /// Create a new compression context with default level
    pub fn new(algorithm: CompressionAlgorithm) -> Self {
        let level = match algorithm {
            CompressionAlgorithm::Gzip => 6, // Default gzip level
            CompressionAlgorithm::Zstd => 3, // Default zstd level
        };
        Self { algorithm, level }
    }

    /// Create a new compression context with specific level
    pub fn with_level(algorithm: CompressionAlgorithm, level: u32) -> Result<Self> {
        // Validate compression level
        match algorithm {
            CompressionAlgorithm::Gzip => {
                if level < 1 || level > 9 {
                    return Err(CryptoError::InvalidArguments(
                        "Gzip compression level must be between 1 and 9".to_string(),
                    ));
                }
            }
            CompressionAlgorithm::Zstd => {
                if level < 1 || level > 22 {
                    return Err(CryptoError::InvalidArguments(
                        "Zstd compression level must be between 1 and 22".to_string(),
                    ));
                }
            }
        }
        Ok(Self { algorithm, level })
    }
}

/// Compress data using the specified algorithm and level
pub fn compress(data: &[u8], context: &CompressionContext) -> Result<Vec<u8>> {
    match context.algorithm {
        CompressionAlgorithm::Gzip => compress_gzip(data, context.level),
        CompressionAlgorithm::Zstd => compress_zstd(data, context.level),
    }
}

/// Decompress data using the specified algorithm
pub fn decompress(data: &[u8], algorithm: CompressionAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        CompressionAlgorithm::Gzip => decompress_gzip(data),
        CompressionAlgorithm::Zstd => decompress_zstd(data),
    }
}

/// Compress data using gzip
fn compress_gzip(data: &[u8], level: u32) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(data, GzipCompression::new(level));
    let mut compressed = Vec::new();
    encoder
        .read_to_end(&mut compressed)
        .map_err(|e| CryptoError::SystemError(format!("Gzip compression failed: {}", e)))?;
    Ok(compressed)
}

/// Decompress gzip data
fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| CryptoError::SystemError(format!("Gzip decompression failed: {}", e)))?;
    Ok(decompressed)
}

/// Compress data using zstd
fn compress_zstd(data: &[u8], level: u32) -> Result<Vec<u8>> {
    zstd::encode_all(data, level as i32)
        .map_err(|e| CryptoError::SystemError(format!("Zstd compression failed: {}", e)))
}

/// Decompress zstd data
fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(data)
        .map_err(|e| CryptoError::SystemError(format!("Zstd decompression failed: {}", e)))
}

/// Compress data from a reader to a writer using streaming
pub fn compress_stream(
    reader: &mut impl Read,
    writer: &mut impl Write,
    context: &CompressionContext,
) -> Result<()> {
    match context.algorithm {
        CompressionAlgorithm::Gzip => compress_stream_gzip(reader, writer, context.level),
        CompressionAlgorithm::Zstd => compress_stream_zstd(reader, writer, context.level),
    }
}

/// Decompress data from a reader to a writer using streaming
pub fn decompress_stream(
    reader: &mut impl Read,
    writer: &mut impl Write,
    algorithm: CompressionAlgorithm,
) -> Result<()> {
    match algorithm {
        CompressionAlgorithm::Gzip => decompress_stream_gzip(reader, writer),
        CompressionAlgorithm::Zstd => decompress_stream_zstd(reader, writer),
    }
}

/// Compress stream using gzip
fn compress_stream_gzip(
    reader: &mut impl Read,
    writer: &mut impl Write,
    level: u32,
) -> Result<()> {
    let mut encoder = flate2::write::GzEncoder::new(writer, GzipCompression::new(level));
    std::io::copy(reader, &mut encoder)
        .map_err(|e| CryptoError::SystemError(format!("Gzip stream compression failed: {}", e)))?;
    encoder
        .finish()
        .map_err(|e| CryptoError::SystemError(format!("Gzip stream finalization failed: {}", e)))?;
    Ok(())
}

/// Decompress stream using gzip
fn decompress_stream_gzip(reader: &mut impl Read, writer: &mut impl Write) -> Result<()> {
    let mut decoder = flate2::read::GzDecoder::new(reader);
    std::io::copy(&mut decoder, writer)
        .map_err(|e| CryptoError::SystemError(format!("Gzip stream decompression failed: {}", e)))?;
    Ok(())
}

/// Compress stream using zstd
fn compress_stream_zstd(
    reader: &mut impl Read,
    writer: &mut impl Write,
    level: u32,
) -> Result<()> {
    let mut encoder = zstd::Encoder::new(writer, level as i32)
        .map_err(|e| CryptoError::SystemError(format!("Zstd encoder creation failed: {}", e)))?;
    std::io::copy(reader, &mut encoder)
        .map_err(|e| CryptoError::SystemError(format!("Zstd stream compression failed: {}", e)))?;
    encoder
        .finish()
        .map_err(|e| CryptoError::SystemError(format!("Zstd stream finalization failed: {}", e)))?;
    Ok(())
}

/// Decompress stream using zstd
fn decompress_stream_zstd(reader: &mut impl Read, writer: &mut impl Write) -> Result<()> {
    let mut decoder = zstd::Decoder::new(reader)
        .map_err(|e| CryptoError::SystemError(format!("Zstd decoder creation failed: {}", e)))?;
    std::io::copy(&mut decoder, writer)
        .map_err(|e| CryptoError::SystemError(format!("Zstd stream decompression failed: {}", e)))?;
    Ok(())
}
