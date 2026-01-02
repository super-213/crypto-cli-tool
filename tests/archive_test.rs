// Archive module tests

use crypto_cli_tool::archive::{create_archive, extract_archive};
use std::fs::{self, File};
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_archive_single_file() {
    // Create a temporary directory with a single file
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path().join("test_dir");
    fs::create_dir(&test_dir).unwrap();
    
    let test_file = test_dir.join("test.txt");
    let mut file = File::create(&test_file).unwrap();
    file.write_all(b"Hello, World!").unwrap();
    drop(file);
    
    // Create archive
    let archive_data = create_archive(&test_dir).unwrap();
    
    // Extract to a new directory
    let extract_dir = temp_dir.path().join("extracted");
    extract_archive(&archive_data, &extract_dir).unwrap();
    
    // Verify the file was extracted correctly
    let extracted_file = extract_dir.join("test.txt");
    assert!(extracted_file.exists());
    
    let content = fs::read_to_string(&extracted_file).unwrap();
    assert_eq!(content, "Hello, World!");
}

#[test]
fn test_archive_nested_directories() {
    // Create a temporary directory with nested structure
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path().join("test_dir");
    fs::create_dir(&test_dir).unwrap();
    
    // Create nested directories
    let subdir1 = test_dir.join("subdir1");
    let subdir2 = subdir1.join("subdir2");
    fs::create_dir_all(&subdir2).unwrap();
    
    // Create files at different levels
    let mut file1 = File::create(test_dir.join("root.txt")).unwrap();
    file1.write_all(b"Root file").unwrap();
    drop(file1);
    
    let mut file2 = File::create(subdir1.join("level1.txt")).unwrap();
    file2.write_all(b"Level 1 file").unwrap();
    drop(file2);
    
    let mut file3 = File::create(subdir2.join("level2.txt")).unwrap();
    file3.write_all(b"Level 2 file").unwrap();
    drop(file3);
    
    // Create archive
    let archive_data = create_archive(&test_dir).unwrap();
    
    // Extract to a new directory
    let extract_dir = temp_dir.path().join("extracted");
    extract_archive(&archive_data, &extract_dir).unwrap();
    
    // Verify all files were extracted correctly
    assert!(extract_dir.join("root.txt").exists());
    assert!(extract_dir.join("subdir1/level1.txt").exists());
    assert!(extract_dir.join("subdir1/subdir2/level2.txt").exists());
    
    assert_eq!(fs::read_to_string(extract_dir.join("root.txt")).unwrap(), "Root file");
    assert_eq!(fs::read_to_string(extract_dir.join("subdir1/level1.txt")).unwrap(), "Level 1 file");
    assert_eq!(fs::read_to_string(extract_dir.join("subdir1/subdir2/level2.txt")).unwrap(), "Level 2 file");
}

#[test]
fn test_archive_empty_directory() {
    // Create an empty directory
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path().join("empty_dir");
    fs::create_dir(&test_dir).unwrap();
    
    // Create archive (should succeed with 0 entries)
    let archive_data = create_archive(&test_dir).unwrap();
    
    // Extract to a new directory
    let extract_dir = temp_dir.path().join("extracted");
    extract_archive(&archive_data, &extract_dir).unwrap();
    
    // Verify the directory was created
    assert!(extract_dir.exists());
    assert!(extract_dir.is_dir());
}

#[test]
fn test_archive_preserves_file_content() {
    // Create a temporary directory with various file types
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path().join("test_dir");
    fs::create_dir(&test_dir).unwrap();
    
    // Create a binary file
    let binary_file = test_dir.join("binary.dat");
    let binary_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
    fs::write(&binary_file, &binary_data).unwrap();
    
    // Create a text file with special characters
    let text_file = test_dir.join("special.txt");
    fs::write(&text_file, "Hello 世界! 🚀\n").unwrap();
    
    // Create archive
    let archive_data = create_archive(&test_dir).unwrap();
    
    // Extract to a new directory
    let extract_dir = temp_dir.path().join("extracted");
    extract_archive(&archive_data, &extract_dir).unwrap();
    
    // Verify binary file
    let extracted_binary = fs::read(extract_dir.join("binary.dat")).unwrap();
    assert_eq!(extracted_binary, binary_data);
    
    // Verify text file
    let extracted_text = fs::read_to_string(extract_dir.join("special.txt")).unwrap();
    assert_eq!(extracted_text, "Hello 世界! 🚀\n");
}
