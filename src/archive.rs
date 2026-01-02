// Archive module - directory archiving and extraction

use crate::error::{CryptoError, Result};
use std::path::{Path, PathBuf};
use std::io::{Read, Write};

/// Magic bytes for archive identification: "CRYTAR"
pub const ARCHIVE_MAGIC: [u8; 6] = *b"CRYTAR";

/// Current archive format version
pub const ARCHIVE_VERSION: u16 = 1;

/// Archive header structure
///
/// This structure contains metadata about the archive including
/// the number of entries it contains.
#[derive(Debug, Clone)]
pub struct ArchiveHeader {
    /// Magic bytes for archive identification: "CRYTAR"
    pub magic: [u8; 6],
    
    /// Archive format version
    pub version: u16,
    
    /// Number of entries in the archive
    pub entry_count: u32,
}

impl ArchiveHeader {
    /// Create a new archive header
    pub fn new(entry_count: u32) -> Self {
        Self {
            magic: ARCHIVE_MAGIC,
            version: ARCHIVE_VERSION,
            entry_count,
        }
    }
    
    /// Serialize the archive header to binary format
    ///
    /// Format:
    /// - Magic Bytes (6 bytes): "CRYTAR"
    /// - Version (2 bytes): u16 little-endian
    /// - Entry Count (4 bytes): u32 little-endian
    ///
    /// Total: 12 bytes
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
///
/// This structure contains metadata about a single file in the archive,
/// including its path, size, permissions, and modification time.
#[derive(Debug, Clone)]
pub struct ArchiveEntryHeader {
    /// Relative path of the file within the archive (UTF-8)
    pub path: PathBuf,
    
    /// Size of the file data in bytes
    pub file_size: u64,
    
    /// Unix file permissions (mode bits)
    pub permissions: u32,
    
    /// Modified time as Unix timestamp (seconds since epoch)
    pub modified_time: u64,
}

impl ArchiveEntryHeader {
    /// Create a new archive entry header
    pub fn new(path: PathBuf, file_size: u64, permissions: u32, modified_time: u64) -> Self {
        Self {
            path,
            file_size,
            permissions,
            modified_time,
        }
    }
    
    /// Serialize the entry header to binary format
    ///
    /// Format:
    /// - Path Length (2 bytes): u16 little-endian
    /// - Path (variable): UTF-8 encoded string
    /// - File Size (8 bytes): u64 little-endian
    /// - Permissions (4 bytes): u32 little-endian
    /// - Modified Time (8 bytes): u64 little-endian
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
///
/// # Arguments
/// * `dir_path` - The directory to traverse
/// * `base_path` - The base path to use for computing relative paths
///
/// # Returns
/// A vector of tuples containing (relative_path, absolute_path, metadata)
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
            let relative_path = path.strip_prefix(base_path)
                .map_err(|_| CryptoError::InvalidArguments("Path is not within base directory".to_string()))?
                .to_path_buf();
            
            files.push((relative_path, path, metadata));
        } else if metadata.is_dir() {
            // Recursively collect files from subdirectory
            let mut subdir_files = collect_files(&path, base_path)?;
            files.append(&mut subdir_files);
        }
        // Skip symbolic links and other special files
    }
    
    Ok(files)
}

/// Create an archive from a directory
///
/// This function traverses the directory recursively, collects all files
/// with their metadata, and serializes them into the archive format.
///
/// # Arguments
/// * `dir_path` - The directory to archive
///
/// # Returns
/// A byte vector containing the serialized archive
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
        let file_size = metadata.len();
        
        // Get permissions (Unix-specific, defaults to 0644 on other platforms)
        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode()
        };
        #[cfg(not(unix))]
        let permissions = 0o644u32;
        
        // Get modified time
        let modified_time = metadata.modified()
            .map_err(|e| CryptoError::SystemError(format!("Failed to get modified time: {}", e)))?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CryptoError::SystemError(format!("Invalid modified time: {}", e)))?
            .as_secs();
        
        // Write entry header
        let entry_header = ArchiveEntryHeader::new(
            relative_path,
            file_size,
            permissions,
            modified_time,
        );
        entry_header.write_to(&mut archive_data)?;
        
        // Read and write file data
        let file = File::open(&absolute_path)
            .map_err(|e| CryptoError::FileReadError(absolute_path.clone(), e))?;
        let mut reader = BufReader::new(file);
        
        std::io::copy(&mut reader, &mut archive_data)
            .map_err(|e| CryptoError::FileReadError(absolute_path, e))?;
    }
    
    Ok(archive_data)
}

/// Extract an archive to a directory
///
/// This function parses the archive format, creates the directory structure,
/// and extracts all files with their original metadata.
///
/// # Arguments
/// * `archive_data` - The serialized archive data
/// * `output_path` - The directory where files should be extracted
///
/// # Returns
/// Ok(()) on success, or an error if extraction fails
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
        
        drop(file); // Close the file before setting metadata
        
        // Restore file permissions (Unix-specific)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(entry_header.permissions);
            fs::set_permissions(&file_path, permissions)
                .map_err(|e| CryptoError::FileWriteError(file_path.clone(), e))?;
        }
        
        // Restore modified time
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(entry_header.modified_time);
        let file_times = filetime::FileTime::from_system_time(mtime);
        filetime::set_file_mtime(&file_path, file_times)
            .map_err(|e| CryptoError::SystemError(format!("Failed to set modified time: {}", e)))?;
    }
    
    Ok(())
}
