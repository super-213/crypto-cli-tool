// Archive module - directory archiving and extraction
// 归档模块 - 目录归档和提取

use crate::error::{CryptoError, Result};
use std::path::{Path, PathBuf};
use std::io::{Read, Write};

/// Magic bytes for archive identification: "CRYTAR"
/// 归档识别的魔数字节："CRYTAR"
pub const ARCHIVE_MAGIC: [u8; 6] = *b"CRYTAR";

/// Current archive format version
/// 当前归档格式版本
pub const ARCHIVE_VERSION: u16 = 1;

/// Archive header structure
/// 归档头部结构
///
/// This structure contains metadata about the archive including
/// the number of entries it contains.
/// 此结构包含有关归档的元数据，包括它包含的条目数。
#[derive(Debug, Clone)]
pub struct ArchiveHeader {
    /// Magic bytes for archive identification: "CRYTAR"
    /// 归档识别的魔数字节："CRYTAR"
    pub magic: [u8; 6],
    
    /// Archive format version
    /// 归档格式版本
    pub version: u16,
    
    /// Number of entries in the archive
    /// 归档中的条目数
    pub entry_count: u32,
}

impl ArchiveHeader {
    /// Create a new archive header
    /// 创建新的归档头部
    pub fn new(entry_count: u32) -> Self {
        Self {
            magic: ARCHIVE_MAGIC,
            version: ARCHIVE_VERSION,
            entry_count,
        }
    }
    
    /// Serialize the archive header to binary format
    /// 将归档头部序列化为二进制格式
    ///
    /// Format: / 格式：
    /// - Magic Bytes (6 bytes): "CRYTAR" / 魔数字节（6 字节）："CRYTAR"
    /// - Version (2 bytes): u16 little-endian / 版本（2 字节）：u16 小端序
    /// - Entry Count (4 bytes): u32 little-endian / 条目计数（4 字节）：u32 小端序
    ///
    /// Total: 12 bytes / 总计：12 字节
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write magic bytes
        writer.write_all(&self.magic)
            .map_err(|e| CryptoError::SystemError(format!("Failed to write archive magic: {}", e)))?;
        
        // Write version
        writer.write_all(&self.version.to_le_bytes())
            .map_err(|e| CryptoError::SystemError(format!("Failed to write archive version: {}", e)))?;
        
        // Write entry count
        writer.write_all(&self.entry_count.to_le_bytes())
            .map_err(|e| CryptoError::SystemError(format!("Failed to write entry count: {}", e)))?;
        
        Ok(())
    }
    
    /// Deserialize the archive header from binary format
    /// 从二进制格式反序列化归档头部
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        // Read magic bytes
        let mut magic = [0u8; 6];
        reader.read_exact(&mut magic)
            .map_err(|_| CryptoError::InvalidFileFormat)?;
        
        if magic != ARCHIVE_MAGIC {
            return Err(CryptoError::InvalidFileFormat);
        }
        
        // Read version
        let mut version_bytes = [0u8; 2];
        reader.read_exact(&mut version_bytes)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        let version = u16::from_le_bytes(version_bytes);
        
        if version != ARCHIVE_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        
        // Read entry count
        let mut count_bytes = [0u8; 4];
        reader.read_exact(&mut count_bytes)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        let entry_count = u32::from_le_bytes(count_bytes);
        
        Ok(ArchiveHeader {
            magic,
            version,
            entry_count,
        })
    }
}

/// Archive entry header structure
/// 归档条目头部结构
///
/// This structure contains metadata about a single file in the archive,
/// including its path, size, permissions, and modification time.
/// 此结构包含归档中单个文件的元数据，包括其路径、大小、权限和修改时间。
#[derive(Debug, Clone)]
pub struct ArchiveEntryHeader {
    /// Relative path of the file within the archive (UTF-8)
    /// 归档中文件的相对路径（UTF-8）
    pub path: PathBuf,
    
    /// Size of the file data in bytes
    /// 文件数据的大小（字节）
    pub file_size: u64,
    
    /// Unix file permissions (mode bits)
    /// Unix 文件权限（模式位）
    pub permissions: u32,
    
    /// Modified time as Unix timestamp (seconds since epoch)
    /// 修改时间（Unix 时间戳，自纪元以来的秒数）
    pub modified_time: u64,
}

impl ArchiveEntryHeader {
    /// Create a new archive entry header
    /// 创建新的归档条目头部
    pub fn new(path: PathBuf, file_size: u64, permissions: u32, modified_time: u64) -> Self {
        Self {
            path,
            file_size,
            permissions,
            modified_time,
        }
    }
    
    /// Serialize the entry header to binary format
    /// 将条目头部序列化为二进制格式
    ///
    /// Format: / 格式：
    /// - Path Length (2 bytes): u16 little-endian / 路径长度（2 字节）：u16 小端序
    /// - Path (variable): UTF-8 encoded string / 路径（可变）：UTF-8 编码字符串
    /// - File Size (8 bytes): u64 little-endian / 文件大小（8 字节）：u64 小端序
    /// - Permissions (4 bytes): u32 little-endian / 权限（4 字节）：u32 小端序
    /// - Modified Time (8 bytes): u64 little-endian / 修改时间（8 字节）：u64 小端序
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Convert path to UTF-8 string
        let path_str = self.path.to_str()
            .ok_or_else(|| CryptoError::InvalidArguments("Path contains invalid UTF-8".to_string()))?;
        let path_bytes = path_str.as_bytes();
        
        // Check path length
        if path_bytes.len() > u16::MAX as usize {
            return Err(CryptoError::InvalidArguments("Path too long (max 65535 bytes)".to_string()));
        }
        
        // Write path length
        let path_len = path_bytes.len() as u16;
        writer.write_all(&path_len.to_le_bytes())
            .map_err(|e| CryptoError::SystemError(format!("Failed to write path length: {}", e)))?;
        
        // Write path
        writer.write_all(path_bytes)
            .map_err(|e| CryptoError::SystemError(format!("Failed to write path: {}", e)))?;
        
        // Write file size
        writer.write_all(&self.file_size.to_le_bytes())
            .map_err(|e| CryptoError::SystemError(format!("Failed to write file size: {}", e)))?;
        
        // Write permissions
        writer.write_all(&self.permissions.to_le_bytes())
            .map_err(|e| CryptoError::SystemError(format!("Failed to write permissions: {}", e)))?;
        
        // Write modified time
        writer.write_all(&self.modified_time.to_le_bytes())
            .map_err(|e| CryptoError::SystemError(format!("Failed to write modified time: {}", e)))?;
        
        Ok(())
    }
    
    /// Deserialize the entry header from binary format
    /// 从二进制格式反序列化条目头部
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        // Read path length
        let mut path_len_bytes = [0u8; 2];
        reader.read_exact(&mut path_len_bytes)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        let path_len = u16::from_le_bytes(path_len_bytes) as usize;
        
        // Read path
        let mut path_bytes = vec![0u8; path_len];
        reader.read_exact(&mut path_bytes)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        
        let path_str = String::from_utf8(path_bytes)
            .map_err(|_| CryptoError::InvalidMetadata)?;
        let path = PathBuf::from(path_str);
        
        // Read file size
        let mut size_bytes = [0u8; 8];
        reader.read_exact(&mut size_bytes)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        let file_size = u64::from_le_bytes(size_bytes);
        
        // Read permissions
        let mut perm_bytes = [0u8; 4];
        reader.read_exact(&mut perm_bytes)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        let permissions = u32::from_le_bytes(perm_bytes);
        
        // Read modified time
        let mut mtime_bytes = [0u8; 8];
        reader.read_exact(&mut mtime_bytes)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        let modified_time = u64::from_le_bytes(mtime_bytes);
        
        Ok(ArchiveEntryHeader {
            path,
            file_size,
            permissions,
            modified_time,
        })
    }
}

/// Traverse a directory recursively and collect all files with their metadata
/// 递归遍历目录并收集所有文件及其元数据
///
/// # Arguments / 参数
/// * `dir_path` - The directory to traverse / 要遍历的目录
/// * `base_path` - The base path to use for computing relative paths / 用于计算相对路径的基础路径
///
/// # Returns / 返回值
/// A vector of tuples containing (relative_path, absolute_path, metadata)
/// 包含元组的向量（相对路径、绝对路径、元数据）
fn collect_files(dir_path: &Path, base_path: &Path) -> Result<Vec<(PathBuf, PathBuf, std::fs::Metadata)>> {
    use std::fs;
    
    let mut files = Vec::new();
    
    // Read directory entries
    let entries = fs::read_dir(dir_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CryptoError::FileNotFound(dir_path.to_path_buf())
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                CryptoError::PermissionDenied(dir_path.to_path_buf())
            } else {
                CryptoError::FileReadError(dir_path.to_path_buf(), e)
            }
        })?;
    
    for entry in entries {
        let entry = entry
            .map_err(|e| CryptoError::FileReadError(dir_path.to_path_buf(), e))?;
        
        let path = entry.path();
        let metadata = entry.metadata()
            .map_err(|e| CryptoError::FileReadError(path.clone(), e))?;
        
        if metadata.is_file() {
            // Compute relative path from base
            // 从基础路径计算相对路径
            let relative_path = path.strip_prefix(base_path)
                .map_err(|_| CryptoError::InvalidArguments("Path is not within base directory".to_string()))?
                .to_path_buf();
            
            files.push((relative_path, path, metadata));
        } else if metadata.is_dir() {
            // Recursively collect files from subdirectory
            // 从子目录递归收集文件
            let mut subdir_files = collect_files(&path, base_path)?;
            files.append(&mut subdir_files);
        }
        // Skip symbolic links and other special files
        // 跳过符号链接和其他特殊文件
    }
    
    Ok(files)
}

/// Create an archive from a directory
/// 从目录创建归档
///
/// This function traverses the directory recursively, collects all files
/// with their metadata, and serializes them into the archive format.
/// 此函数递归遍历目录，收集所有文件及其元数据，并将它们序列化为归档格式。
///
/// # Arguments / 参数
/// * `dir_path` - The directory to archive / 要归档的目录
///
/// # Returns / 返回值
/// A byte vector containing the serialized archive / 包含序列化归档的字节向量
pub fn create_archive(dir_path: &Path) -> Result<Vec<u8>> {
    use std::fs::File;
    use std::io::BufReader;
    
    // Validate that the path is a directory
    if !dir_path.is_dir() {
        return Err(CryptoError::InvalidArguments(
            format!("{} is not a directory", dir_path.display())
        ));
    }
    
    // Collect all files recursively
    let files = collect_files(dir_path, dir_path)?;
    
    // Create archive in memory
    let mut archive_data = Vec::new();
    
    // Write archive header
    let header = ArchiveHeader::new(files.len() as u32);
    header.write_to(&mut archive_data)?;
    
    // Write each file entry
    for (relative_path, absolute_path, metadata) in files {
        // Get file size
        // 获取文件大小
        let file_size = metadata.len();
        
        // Get permissions (Unix-specific, defaults to 0644 on other platforms)
        // 获取权限（Unix 特定，在其他平台上默认为 0644）
        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode()
        };
        #[cfg(not(unix))]
        let permissions = 0o644u32;
        
        // Get modified time
        // 获取修改时间
        let modified_time = metadata.modified()
            .map_err(|e| CryptoError::SystemError(format!("Failed to get modified time: {}", e)))?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CryptoError::SystemError(format!("Invalid modified time: {}", e)))?
            .as_secs();
        
        // Write entry header
        // 写入条目头部
        let entry_header = ArchiveEntryHeader::new(
            relative_path,
            file_size,
            permissions,
            modified_time,
        );
        entry_header.write_to(&mut archive_data)?;
        
        // Read and write file data
        // 读取并写入文件数据
        let file = File::open(&absolute_path)
            .map_err(|e| CryptoError::FileReadError(absolute_path.clone(), e))?;
        let mut reader = BufReader::new(file);
        
        std::io::copy(&mut reader, &mut archive_data)
            .map_err(|e| CryptoError::FileReadError(absolute_path, e))?;
    }
    
    Ok(archive_data)
}

/// Extract an archive to a directory
/// 将归档提取到目录
///
/// This function parses the archive format, creates the directory structure,
/// and extracts all files with their original metadata.
/// 此函数解析归档格式，创建目录结构，并提取所有文件及其原始元数据。
///
/// # Arguments / 参数
/// * `archive_data` - The serialized archive data / 序列化的归档数据
/// * `output_path` - The directory where files should be extracted / 应提取文件的目录
///
/// # Returns / 返回值
/// Ok(()) on success, or an error if extraction fails / 成功时返回 Ok(())，提取失败时返回错误
pub fn extract_archive(archive_data: &[u8], output_path: &Path) -> Result<()> {
    use std::fs::{self, File};
    use std::io::{Cursor, Write};
    
    let mut reader = Cursor::new(archive_data);
    
    // Read archive header
    let header = ArchiveHeader::read_from(&mut reader)?;
    
    // Create output directory if it doesn't exist
    if !output_path.exists() {
        fs::create_dir_all(output_path)
            .map_err(|e| CryptoError::FileWriteError(output_path.to_path_buf(), e))?;
    }
    
    // Extract each file entry
    for _ in 0..header.entry_count {
        // Read entry header
        let entry_header = ArchiveEntryHeader::read_from(&mut reader)?;
        
        // Construct full output path
        let file_path = output_path.join(&entry_header.path);
        
        // Create parent directories if needed
        if let Some(parent) = file_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .map_err(|e| CryptoError::FileWriteError(parent.to_path_buf(), e))?;
            }
        }
        
        // Read file data
        let mut file_data = vec![0u8; entry_header.file_size as usize];
        reader.read_exact(&mut file_data)
            .map_err(|_| CryptoError::CorruptedHeader)?;
        
        // Write file to disk
        let mut file = File::create(&file_path)
            .map_err(|e| CryptoError::FileWriteError(file_path.clone(), e))?;
        
        file.write_all(&file_data)
            .map_err(|e| CryptoError::FileWriteError(file_path.clone(), e))?;
        
        file.flush()
            .map_err(|e| CryptoError::FileWriteError(file_path.clone(), e))?;
        
        drop(file); // Close the file before setting metadata / 在设置元数据之前关闭文件
        
        // Restore file permissions (Unix-specific)
        // 恢复文件权限（Unix 特定）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(entry_header.permissions);
            fs::set_permissions(&file_path, permissions)
                .map_err(|e| CryptoError::FileWriteError(file_path.clone(), e))?;
        }
        
        // Restore modified time
        // 恢复修改时间
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(entry_header.modified_time);
        let file_times = filetime::FileTime::from_system_time(mtime);
        filetime::set_file_mtime(&file_path, file_times)
            .map_err(|e| CryptoError::SystemError(format!("Failed to set modified time: {}", e)))?;
    }
    
    Ok(())
}
