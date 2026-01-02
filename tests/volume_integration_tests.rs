// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Volume Integration Tests
//!
//! Comprehensive integration tests for encrypted volume operations including:
//! - Volume creation and opening
//! - Password management
//! - Filesystem operations (files and directories)
//! - Error handling
//! - Concurrent access
//! - Recovery keys
//! - Hidden volumes

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

use tesseract_lib::volume::{
    keyslot::MasterKey, Container, InodeType, MemoryBackend, StorageBackend, VolumeIOFilesystem,
    FS_BLOCK_SIZE, ROOT_INODE,
};

/// Test helper to create a temporary directory for tests
fn temp_dir() -> TempDir {
    tempfile::tempdir().expect("Failed to create temp directory")
}

/// Test helper to create a container path in a temp directory
fn container_path(dir: &TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

/// Default sector size for tests
const TEST_SECTOR_SIZE: u32 = 4096;

// =============================================================================
// Container Creation Tests
// =============================================================================

#[test]
fn test_container_create_basic() {
    let dir = temp_dir();
    let path = container_path(&dir, "basic.vault");

    let container = Container::create(
        &path,
        1024 * 1024, // 1 MB
        "test_password_123",
        TEST_SECTOR_SIZE,
    )
    .expect("Failed to create container");

    assert!(path.exists());
    assert!(container.is_unlocked());
    assert_eq!(container.path(), path);
}

#[test]
fn test_container_create_various_sizes() {
    let dir = temp_dir();

    // Test minimum viable size (slightly larger than metadata)
    let sizes: [u64; 3] = [
        256 * 1024,       // 256 KB
        1024 * 1024,      // 1 MB
        10 * 1024 * 1024, // 10 MB
    ];

    for (i, size) in sizes.iter().enumerate() {
        let path = container_path(&dir, &format!("size_{}.vault", i));
        let container = Container::create(&path, *size, "password", TEST_SECTOR_SIZE)
            .expect(&format!("Failed to create {}KB container", size / 1024));

        // Data size should be the configured size
        assert_eq!(container.data_size(), *size);
    }
}

#[test]
fn test_container_create_already_exists() {
    let dir = temp_dir();
    let path = container_path(&dir, "exists.vault");

    // Create first container
    Container::create(&path, 1024 * 1024, "password", TEST_SECTOR_SIZE)
        .expect("Failed to create first container");

    // Try to create again - should fail
    let result = Container::create(&path, 1024 * 1024, "password", TEST_SECTOR_SIZE);
    assert!(result.is_err());
}

// =============================================================================
// Container Open Tests
// =============================================================================

#[test]
fn test_container_open_correct_password() {
    let dir = temp_dir();
    let path = container_path(&dir, "open_test.vault");
    let password = "correct_password_456";

    // Create container
    {
        let _container = Container::create(&path, 1024 * 1024, password, TEST_SECTOR_SIZE)
            .expect("Failed to create container");
    }

    // Open with correct password
    let container =
        Container::open(&path, password).expect("Failed to open container with correct password");

    assert!(container.is_unlocked());
}

#[test]
fn test_container_open_wrong_password() {
    let dir = temp_dir();
    let path = container_path(&dir, "wrong_pass.vault");

    // Create container
    {
        let _container =
            Container::create(&path, 1024 * 1024, "correct_password", TEST_SECTOR_SIZE)
                .expect("Failed to create container");
    }

    // Open with wrong password
    let result = Container::open(&path, "wrong_password");
    assert!(result.is_err());
}

#[test]
fn test_container_open_nonexistent() {
    let dir = temp_dir();
    let path = container_path(&dir, "nonexistent.vault");

    let result = Container::open(&path, "password");
    assert!(result.is_err());
}

// =============================================================================
// Password Management Tests
// =============================================================================

/// Test changing a password on an existing volume
#[test]
fn test_change_password() {
    let dir = temp_dir();
    let path = container_path(&dir, "change_pass.vault");

    // Create container with initial password
    let mut container = Container::create(&path, 1024 * 1024, "old_password", TEST_SECTOR_SIZE)
        .expect("Failed to create container");

    // Change to new password
    container
        .change_password("new_password")
        .expect("Failed to change password");

    drop(container);

    // Old password should no longer work
    let result = Container::open(&path, "old_password");
    assert!(result.is_err());

    // New password should work
    let container =
        Container::open(&path, "new_password").expect("Failed to open with new password");
    assert!(container.is_unlocked());
}

// =============================================================================
// Filesystem Creation Tests
// =============================================================================

#[test]
fn test_filesystem_mkfs() {
    // Create a master key and in-memory backend for testing
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024; // 1 MB
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));

    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Verify root directory exists
    let root = fs.get_inode(ROOT_INODE).expect("Failed to get root inode");
    assert_eq!(root.file_type(), InodeType::Directory);
}

#[test]
fn test_filesystem_create_and_open() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;

    // Use a shared memory backend
    let backend_data = Arc::new(std::sync::RwLock::new(vec![0u8; volume_size as usize]));

    // Create filesystem
    {
        let backend = SharedMemoryBackend::new(Arc::clone(&backend_data));
        let fs =
            VolumeIOFilesystem::mkfs(&master_key, volume_size, Box::new(backend), "TestVolume")
                .expect("Failed to create filesystem");
        fs.sync().expect("Failed to sync");
    }

    // Reopen filesystem
    let backend2 = SharedMemoryBackend::new(Arc::clone(&backend_data));
    let fs = VolumeIOFilesystem::open(&master_key, volume_size, Box::new(backend2))
        .expect("Failed to open filesystem");

    // Verify root directory is accessible
    let root = fs.get_inode(ROOT_INODE).expect("Failed to get root inode");
    assert!(root.is_dir());
}

/// Shared memory backend for testing persistence
struct SharedMemoryBackend {
    data: Arc<std::sync::RwLock<Vec<u8>>>,
}

impl SharedMemoryBackend {
    fn new(data: Arc<std::sync::RwLock<Vec<u8>>>) -> Self {
        Self { data }
    }
}

impl StorageBackend for SharedMemoryBackend {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let data = self
            .data
            .read()
            .map_err(|_| std::io::Error::other("lock poisoned"))?;
        let start = offset as usize;
        let end = (start + buf.len()).min(data.len());
        if start >= data.len() {
            return Ok(0);
        }
        let len = end - start;
        buf[..len].copy_from_slice(&data[start..end]);
        Ok(len)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> std::io::Result<usize> {
        let mut data = self
            .data
            .write()
            .map_err(|_| std::io::Error::other("lock poisoned"))?;
        let start = offset as usize;
        let end = start + buf.len();
        if end > data.len() {
            data.resize(end, 0);
        }
        data[start..end].copy_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn size(&self) -> std::io::Result<u64> {
        let data = self
            .data
            .read()
            .map_err(|_| std::io::Error::other("lock poisoned"))?;
        Ok(data.len() as u64)
    }
}

// =============================================================================
// File Operations Tests
// =============================================================================

#[test]
fn test_create_file() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Create a file in root directory
    let inode = fs
        .create_file(ROOT_INODE, "test.txt", 0o644)
        .expect("Failed to create file");

    assert!(inode > ROOT_INODE);

    // Verify file exists
    let lookup_result = fs
        .lookup(ROOT_INODE, "test.txt")
        .expect("Failed to lookup file");
    assert_eq!(lookup_result, Some(inode));
}

#[test]
fn test_write_and_read_file() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Create file
    let inode = fs
        .create_file(ROOT_INODE, "data.txt", 0o644)
        .expect("Failed to create file");

    // Write data
    let test_data = b"Hello, encrypted world! This is test data for the volume integration tests.";
    let written = fs
        .write_by_inode(inode, 0, test_data)
        .expect("Failed to write data");
    assert_eq!(written as usize, test_data.len());

    // Read data back
    let read_data = fs
        .read_by_inode(inode, 0, test_data.len() as u32)
        .expect("Failed to read data");
    assert_eq!(read_data, test_data);
}

#[test]
fn test_write_large_file() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 2 * 1024 * 1024; // 2 MB
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    let inode = fs
        .create_file(ROOT_INODE, "large.bin", 0o644)
        .expect("Failed to create file");

    // Write data larger than one block
    let large_data: Vec<u8> = (0..=255u8)
        .cycle()
        .take(FS_BLOCK_SIZE as usize * 3)
        .collect();
    let written = fs
        .write_by_inode(inode, 0, &large_data)
        .expect("Failed to write large data");
    assert_eq!(written as usize, large_data.len());

    // Read back and verify
    let read_data = fs
        .read_by_inode(inode, 0, large_data.len() as u32)
        .expect("Failed to read large data");
    assert_eq!(read_data, large_data);
}

#[test]
fn test_file_offset_write() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    let inode = fs
        .create_file(ROOT_INODE, "offset.txt", 0o644)
        .expect("Failed to create file");

    // Write at offset 0
    fs.write_by_inode(inode, 0, b"AAAA")
        .expect("Failed to write at offset 0");

    // Write at offset 100
    fs.write_by_inode(inode, 100, b"BBBB")
        .expect("Failed to write at offset 100");

    // Read and verify the written data
    let data = fs.read_by_inode(inode, 0, 104).expect("Failed to read");
    assert_eq!(&data[0..4], b"AAAA");
    assert_eq!(&data[100..104], b"BBBB");
    // Note: Gap content between writes is implementation-defined
    // (may be zeros, uninitialized, or encrypted garbage)
}

#[test]
fn test_truncate_file() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    let inode = fs
        .create_file(ROOT_INODE, "truncate.txt", 0o644)
        .expect("Failed to create file");

    // Write data
    let data = b"This is some data that will be truncated";
    fs.write_by_inode(inode, 0, data).expect("Failed to write");

    // Truncate to 10 bytes
    fs.truncate_file(inode, 10).expect("Failed to truncate");

    // Verify size
    let file_inode = fs.get_inode(inode).expect("Failed to get inode");
    assert_eq!(file_inode.size, 10);

    // Read and verify content
    let read_data = fs.read_by_inode(inode, 0, 10).expect("Failed to read");
    assert_eq!(&read_data, &data[0..10]);
}

#[test]
fn test_remove_file() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Create file
    let inode = fs
        .create_file(ROOT_INODE, "delete_me.txt", 0o644)
        .expect("Failed to create file");

    // Write some data
    fs.write_by_inode(inode, 0, b"some data")
        .expect("Failed to write");

    // Remove file
    fs.remove_file(ROOT_INODE, "delete_me.txt")
        .expect("Failed to remove file");

    // Verify file no longer exists
    let lookup = fs
        .lookup(ROOT_INODE, "delete_me.txt")
        .expect("Failed to lookup");
    assert!(lookup.is_none());
}

// =============================================================================
// Directory Operations Tests
// =============================================================================

#[test]
fn test_create_directory() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    let dir_inode = fs
        .create_directory(ROOT_INODE, "subdir", 0o755)
        .expect("Failed to create directory");

    // Verify directory exists
    let lookup = fs.lookup(ROOT_INODE, "subdir").expect("Failed to lookup");
    assert_eq!(lookup, Some(dir_inode));

    // Verify it's a directory
    let inode = fs.get_inode(dir_inode).expect("Failed to get inode");
    assert_eq!(inode.file_type(), InodeType::Directory);
}

#[test]
fn test_nested_directories() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Create nested structure: /a/b/c
    let dir_a = fs
        .create_directory(ROOT_INODE, "a", 0o755)
        .expect("Failed to create dir a");
    let dir_b = fs
        .create_directory(dir_a, "b", 0o755)
        .expect("Failed to create dir b");
    let dir_c = fs
        .create_directory(dir_b, "c", 0o755)
        .expect("Failed to create dir c");

    // Create file in deepest directory
    let file_inode = fs
        .create_file(dir_c, "deep.txt", 0o644)
        .expect("Failed to create file in deep dir");

    // Verify file is accessible
    let lookup = fs.lookup(dir_c, "deep.txt").expect("Failed to lookup");
    assert_eq!(lookup, Some(file_inode));
}

#[test]
fn test_readdir() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Create some files and directories
    fs.create_file(ROOT_INODE, "file1.txt", 0o644)
        .expect("create file1");
    fs.create_file(ROOT_INODE, "file2.txt", 0o644)
        .expect("create file2");
    fs.create_directory(ROOT_INODE, "dir1", 0o755)
        .expect("create dir1");

    // Read directory
    let entries = fs.readdir_by_inode(ROOT_INODE).expect("Failed to readdir");

    // Should have at least 3 entries (plus . and ..)
    assert!(entries.len() >= 3);

    // Verify our entries exist
    let names: Vec<_> = entries
        .iter()
        .filter_map(|e| e.name_str().ok())
        .collect::<Vec<_>>();
    assert!(names.contains(&"file1.txt"));
    assert!(names.contains(&"file2.txt"));
    assert!(names.contains(&"dir1"));
}

#[test]
fn test_remove_empty_directory() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Create and then remove empty directory
    fs.create_directory(ROOT_INODE, "empty_dir", 0o755)
        .expect("Failed to create directory");

    fs.remove_directory(ROOT_INODE, "empty_dir")
        .expect("Failed to remove empty directory");

    // Verify it's gone
    let lookup = fs
        .lookup(ROOT_INODE, "empty_dir")
        .expect("Failed to lookup");
    assert!(lookup.is_none());
}

#[test]
fn test_remove_nonempty_directory_fails() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Create directory with file inside
    let dir_inode = fs
        .create_directory(ROOT_INODE, "nonempty", 0o755)
        .expect("Failed to create directory");
    fs.create_file(dir_inode, "file.txt", 0o644)
        .expect("Failed to create file in dir");

    // Try to remove non-empty directory - should fail
    let result = fs.remove_directory(ROOT_INODE, "nonempty");
    assert!(result.is_err());
}

// =============================================================================
// Rename Tests
// =============================================================================

#[test]
fn test_rename_file() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Create file with content
    let inode = fs
        .create_file(ROOT_INODE, "old_name.txt", 0o644)
        .expect("Failed to create file");
    fs.write_by_inode(inode, 0, b"test content")
        .expect("Failed to write");

    // Rename file
    fs.rename_entry(ROOT_INODE, "old_name.txt", ROOT_INODE, "new_name.txt")
        .expect("Failed to rename file");

    // Old name should not exist
    let old_lookup = fs.lookup(ROOT_INODE, "old_name.txt").expect("lookup");
    assert!(old_lookup.is_none());

    // New name should exist with same inode
    let new_lookup = fs.lookup(ROOT_INODE, "new_name.txt").expect("lookup");
    assert_eq!(new_lookup, Some(inode));

    // Content should be preserved
    let content = fs.read_by_inode(inode, 0, 12).expect("read");
    assert_eq!(content, b"test content");
}

#[test]
fn test_move_file_between_directories() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Create directories
    let dir1 = fs
        .create_directory(ROOT_INODE, "dir1", 0o755)
        .expect("create dir1");
    let dir2 = fs
        .create_directory(ROOT_INODE, "dir2", 0o755)
        .expect("create dir2");

    // Create file in dir1
    let inode = fs
        .create_file(dir1, "file.txt", 0o644)
        .expect("create file");
    fs.write_by_inode(inode, 0, b"moveable content")
        .expect("write");

    // Move to dir2
    fs.rename_entry(dir1, "file.txt", dir2, "moved.txt")
        .expect("Failed to move file");

    // Verify old location is empty
    let old = fs.lookup(dir1, "file.txt").expect("lookup");
    assert!(old.is_none());

    // Verify new location exists
    let new = fs.lookup(dir2, "moved.txt").expect("lookup");
    assert_eq!(new, Some(inode));
}

// =============================================================================
// Filesystem Check Tests
// =============================================================================

#[test]
#[ignore = "Issue #45: fsck() not yet implemented"]
fn test_fsck_clean_filesystem() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Create some structure
    fs.create_file(ROOT_INODE, "file.txt", 0o644)
        .expect("create file");
    fs.create_directory(ROOT_INODE, "dir", 0o755)
        .expect("create dir");
    fs.sync().expect("sync");

    // Run fsck
    let result = fs.fsck().expect("Failed to run fsck");
    assert!(result.is_clean(), "Filesystem should be clean");
}

// =============================================================================
// Recovery Key Tests
// =============================================================================

#[test]
fn test_generate_recovery_key() {
    let key = Container::generate_recovery_key();

    // Recovery key should be 64 hex characters (32 bytes)
    assert_eq!(key.len(), 64);
    assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
}

/// Test adding and using a recovery key
///
/// NOTE: For V2 PQC volumes, recovery keys are stored in the key slot with hybrid
/// key derivation, but the ML-KEM decapsulation key is encrypted only with the
/// primary password. This means recovery keys can unlock the key slot but the
/// DK decryption will fail. Recovery keys work correctly for V1 volumes.
///
/// For V2 PQC volumes, users should use the `change_password` method to reset
/// their password if they have access to the unlocked volume.
#[test]
#[ignore = "V2 PQC: Recovery keys cannot decrypt the ML-KEM DK (encrypted with primary password only)"]
fn test_recovery_key_unlock() {
    let dir = temp_dir();
    let path = container_path(&dir, "recovery.vault");
    let password = "main_password";

    // Create container
    let mut container = Container::create(&path, 1024 * 1024, password, TEST_SECTOR_SIZE)
        .expect("Failed to create container");

    // Generate and add a recovery key
    let recovery_key = Container::generate_recovery_key();
    assert_eq!(
        recovery_key.len(),
        64,
        "Recovery key should be 64 hex chars"
    );

    container
        .add_recovery_key(&recovery_key)
        .expect("Failed to add recovery key");

    drop(container);

    // Both password and recovery key should work
    let c1 = Container::open(&path, password).expect("Failed to open with password");
    assert!(c1.is_unlocked());
    drop(c1);

    let c2 = Container::open(&path, &recovery_key).expect("Failed to open with recovery key");
    assert!(c2.is_unlocked());
}

// =============================================================================
// Header Backup Tests
// =============================================================================

#[test]
fn test_header_export_and_restore() {
    let dir = temp_dir();
    let container_file = container_path(&dir, "backup_test.vault");
    let backup_path = dir.path().join("backup.header");
    let password = "backup_password";

    // Create container and write some data
    {
        let container = Container::create(&container_file, 1024 * 1024, password, TEST_SECTOR_SIZE)
            .expect("Failed to create container");

        // Export header backup
        container
            .export_header_backup(&backup_path, password)
            .expect("Failed to export header backup");
    }

    // Verify backup exists
    assert!(backup_path.exists());

    // Restore from backup (simulating header corruption recovery)
    let mut container =
        Container::open(&container_file, password).expect("Failed to open container");

    container
        .restore_from_backup(&backup_path, password)
        .expect("Failed to restore from backup");
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

#[test]
fn test_concurrent_file_operations() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 4 * 1024 * 1024; // 4 MB
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = Arc::new(
        VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
            .expect("Failed to create filesystem"),
    );

    // Create files for each thread
    let num_threads = 4;
    let files_per_thread = 10;

    for t in 0..num_threads {
        for f in 0..files_per_thread {
            let name = format!("thread_{}_file_{}.txt", t, f);
            fs.create_file(ROOT_INODE, &name, 0o644)
                .expect(&format!("Failed to create {}", name));
        }
    }

    // Concurrent writes
    let mut handles = vec![];

    for t in 0..num_threads {
        let fs_clone = Arc::clone(&fs);
        let handle = thread::spawn(move || {
            for f in 0..files_per_thread {
                let name = format!("thread_{}_file_{}.txt", t, f);
                let inode = fs_clone
                    .lookup(ROOT_INODE, &name)
                    .expect("lookup failed")
                    .expect("file not found");

                let data = format!("Data from thread {} file {}", t, f);
                fs_clone
                    .write_by_inode(inode, 0, data.as_bytes())
                    .expect("write failed");
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify all data was written correctly
    for t in 0..num_threads {
        for f in 0..files_per_thread {
            let name = format!("thread_{}_file_{}.txt", t, f);
            let inode = fs
                .lookup(ROOT_INODE, &name)
                .expect("lookup failed")
                .expect("file not found");

            let expected = format!("Data from thread {} file {}", t, f);
            let data = fs
                .read_by_inode(inode, 0, expected.len() as u32)
                .expect("read failed");
            assert_eq!(String::from_utf8_lossy(&data), expected);
        }
    }
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[test]
fn test_lookup_nonexistent_file() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    let result = fs
        .lookup(ROOT_INODE, "nonexistent.txt")
        .expect("lookup should succeed");
    assert!(result.is_none());
}

#[test]
fn test_create_file_in_nonexistent_directory() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Try to create file in non-existent directory (inode 9999)
    let result = fs.create_file(9999, "file.txt", 0o644);
    assert!(result.is_err());
}

#[test]
fn test_create_duplicate_file() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // Create file
    fs.create_file(ROOT_INODE, "duplicate.txt", 0o644)
        .expect("Failed to create file");

    // Try to create again with same name - should fail
    let result = fs.create_file(ROOT_INODE, "duplicate.txt", 0o644);
    assert!(result.is_err());
}

#[test]
fn test_remove_nonexistent_file() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    let result = fs.remove_file(ROOT_INODE, "nonexistent.txt");
    assert!(result.is_err());
}

#[test]
fn test_read_beyond_file_size() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    let inode = fs
        .create_file(ROOT_INODE, "small.txt", 0o644)
        .expect("create file");
    fs.write_by_inode(inode, 0, b"small").expect("write");

    // Read more than file contains - should return only what's available
    let data = fs.read_by_inode(inode, 0, 1000).expect("read");
    assert_eq!(data, b"small");
}

// =============================================================================
// Persistence Tests
// =============================================================================

#[test]
fn test_data_persists_after_sync() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend_data = Arc::new(std::sync::RwLock::new(vec![0u8; volume_size as usize]));

    // Create filesystem and write data
    {
        let backend = SharedMemoryBackend::new(Arc::clone(&backend_data));
        let fs =
            VolumeIOFilesystem::mkfs(&master_key, volume_size, Box::new(backend), "TestVolume")
                .expect("Failed to create filesystem");

        let inode = fs
            .create_file(ROOT_INODE, "persistent.txt", 0o644)
            .expect("create file");
        fs.write_by_inode(inode, 0, b"persistent data")
            .expect("write");
        fs.sync().expect("sync");
    }

    // Reopen and verify data persists
    let backend2 = SharedMemoryBackend::new(Arc::clone(&backend_data));
    let fs = VolumeIOFilesystem::open(&master_key, volume_size, Box::new(backend2))
        .expect("Failed to open filesystem");

    let inode = fs
        .lookup(ROOT_INODE, "persistent.txt")
        .expect("lookup")
        .expect("file not found");
    let data = fs.read_by_inode(inode, 0, 15).expect("read");
    assert_eq!(data, b"persistent data");
}

// =============================================================================
// Container Lock/Unlock Tests
// =============================================================================

#[test]
fn test_container_lock_unlock() {
    let dir = temp_dir();
    let path = container_path(&dir, "lock_test.vault");
    let password = "lock_password";

    let mut container = Container::create(&path, 1024 * 1024, password, TEST_SECTOR_SIZE)
        .expect("Failed to create container");

    assert!(container.is_unlocked());

    // Lock the container
    container.lock();
    assert!(!container.is_unlocked());

    // Master key should no longer be accessible
    assert!(container.master_key().is_none());
}

// =============================================================================
// Statfs Tests
// =============================================================================

#[test]
fn test_get_statfs() {
    let master_key = MasterKey::generate();
    let volume_size: u64 = 1024 * 1024;
    let backend: Box<dyn StorageBackend> = Box::new(MemoryBackend::new(volume_size as usize));
    let fs = VolumeIOFilesystem::mkfs(&master_key, volume_size, backend, "TestVolume")
        .expect("Failed to create filesystem");

    // get_statfs returns (total_bytes, free_bytes, available_bytes)
    // where available_bytes equals free_bytes
    let (total, free, available) = fs.get_statfs().expect("Failed to get statfs");

    assert!(total > 0, "Total bytes should be positive");
    assert!(free <= total, "Free bytes should not exceed total");
    assert_eq!(free, available, "Free and available should be equal");
}
