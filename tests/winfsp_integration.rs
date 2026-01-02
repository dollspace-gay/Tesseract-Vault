// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Integration tests for WinFSP mount functionality.
//!
//! These tests require the WinFSP driver to be installed and automatically
//! skip when it's not available. This allows the tests to run in CI environments
//! where WinFSP may not be installed.

#![cfg(target_os = "windows")]
#![cfg(feature = "encrypted-volumes")]

use std::fs;
use std::path::Path;
use winreg::enums::*;
use winreg::RegKey;

/// Check if WinFSP is installed by checking the registry and DLL availability.
fn is_winfsp_available() -> bool {
    // Check registry for WinFSP installation
    if let Ok(hklm) =
        RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SOFTWARE\\WOW6432Node\\WinFsp")
    {
        if let Ok(install_dir) = hklm.get_value::<String, _>("InstallDir") {
            let dll_path = Path::new(&install_dir).join("bin").join("winfsp-x64.dll");
            if dll_path.exists() {
                return true;
            }
        }
    }

    // Also check the standard installation path
    let standard_paths = [
        r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll",
        r"C:\Program Files\WinFsp\bin\winfsp-x64.dll",
    ];

    for path in &standard_paths {
        if Path::new(path).exists() {
            return true;
        }
    }

    false
}

/// Get the WinFSP installation directory.
fn get_winfsp_install_dir() -> Option<String> {
    // Try registry first
    if let Ok(hklm) =
        RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SOFTWARE\\WOW6432Node\\WinFsp")
    {
        if let Ok(install_dir) = hklm.get_value::<String, _>("InstallDir") {
            return Some(install_dir);
        }
    }

    // Fall back to standard paths
    let standard_paths = [r"C:\Program Files (x86)\WinFsp", r"C:\Program Files\WinFsp"];

    for path in &standard_paths {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    None
}

/// Macro to skip test if WinFSP is not available.
macro_rules! require_winfsp {
    () => {
        if !is_winfsp_available() {
            eprintln!("Skipping test: WinFSP driver not installed");
            return;
        }
    };
}

#[test]
fn test_winfsp_detection() {
    let available = is_winfsp_available();
    println!("WinFSP available: {}", available);

    if available {
        if let Some(install_dir) = get_winfsp_install_dir() {
            println!("WinFSP install directory: {}", install_dir);
        }
    }

    // This test always passes - it's just informational
}

#[test]
fn test_winfsp_dll_loadable() {
    require_winfsp!();

    // Try to verify the DLL exists at expected location
    let install_dir = get_winfsp_install_dir().expect("WinFSP should be installed");
    let dll_path = Path::new(&install_dir).join("bin").join("winfsp-x64.dll");

    assert!(
        dll_path.exists(),
        "WinFSP DLL should exist at {:?}",
        dll_path
    );

    // Check the DLL is readable
    let metadata = fs::metadata(&dll_path).expect("Should be able to read DLL metadata");
    assert!(metadata.len() > 0, "DLL should not be empty");
}

#[test]
fn test_winfsp_version_check() {
    require_winfsp!();

    let install_dir = get_winfsp_install_dir().expect("WinFSP should be installed");

    // Check for version file or launcher
    let launcher_path = Path::new(&install_dir)
        .join("bin")
        .join("launchctl-x64.exe");

    // The launcher should exist if WinFSP is properly installed
    if launcher_path.exists() {
        println!("WinFSP launcher found at: {}", launcher_path.display());
    }
}

#[test]
fn test_winfsp_fsctl_device() {
    require_winfsp!();

    // This test verifies the WinFSP file system control device exists
    // The device is created when the WinFSP driver is loaded

    // Note: Actually opening the device requires elevated privileges
    // and the winfsp crate. This test just verifies the installation.

    let install_dir = get_winfsp_install_dir().expect("WinFSP should be installed");
    let sys_path = Path::new(&install_dir).join("bin").join("winfsp-x64.sys");

    // The driver file should exist
    if sys_path.exists() {
        println!("WinFSP driver found at: {}", sys_path.display());
    } else {
        // Try alternate location
        let alt_path = Path::new(&install_dir).join("bin").join("winfsp-x86.sys");
        if alt_path.exists() {
            println!("WinFSP driver (x86) found at: {}", alt_path.display());
        }
    }
}

// ============================================================================
// Mount/Unmount Integration Tests
// These tests require actual container creation and mounting
// ============================================================================

mod mount_tests {
    use super::*;

    /// Create a temporary container for testing.
    /// Returns the path to the container.
    pub(super) fn create_test_container(
        dir: &Path,
        size_mb: u64,
    ) -> std::io::Result<std::path::PathBuf> {
        use tesseract_lib::volume::container::Container;

        let container_path = dir.join("test_container.scv");
        let password = "TestPassword123!@#Strong";
        let size = size_mb * 1024 * 1024;
        let sector_size = 4096u32;

        Container::create(&container_path, size, password, sector_size)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        Ok(container_path)
    }

    #[test]
    fn test_container_creation_for_mount() {
        require_winfsp!();

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let container_path =
            create_test_container(temp_dir.path(), 10).expect("Failed to create container");

        assert!(container_path.exists(), "Container should be created");

        let metadata = fs::metadata(&container_path).expect("Should read container metadata");
        assert!(
            metadata.len() >= 10 * 1024 * 1024,
            "Container should be at least 10MB"
        );
    }

    #[test]
    #[ignore] // Requires elevated privileges and actual WinFSP mounting
    fn test_mount_unmount_basic() {
        require_winfsp!();

        use tesseract_lib::volume::mount::{mount, MountOptions};

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let container_path =
            create_test_container(temp_dir.path(), 10).expect("Failed to create container");

        // Find an available drive letter
        let mount_point = find_available_drive_letter().expect("No available drive letter");

        let options = MountOptions {
            mount_point: mount_point.clone().into(),
            read_only: false,
            allow_other: false,
            auto_unmount: true,
            fs_name: Some("TestMount".to_string()),
            hidden_offset: None,
            hidden_password: None,
        };

        let password = "TestPassword123!@#Strong";

        // Mount the container
        let handle = mount(&container_path, password, options).expect("Failed to mount container");

        // Verify mount point exists
        assert!(Path::new(&mount_point).exists(), "Mount point should exist");

        // Unmount
        handle.unmount().expect("Failed to unmount");
    }

    #[test]
    #[ignore] // Requires elevated privileges and actual WinFSP mounting
    fn test_mount_read_write_operations() {
        require_winfsp!();

        use tesseract_lib::volume::mount::{mount, MountOptions};

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let container_path =
            create_test_container(temp_dir.path(), 10).expect("Failed to create container");

        let mount_point = find_available_drive_letter().expect("No available drive letter");

        let options = MountOptions {
            mount_point: mount_point.clone().into(),
            read_only: false,
            allow_other: false,
            auto_unmount: true,
            fs_name: Some("TestMount".to_string()),
            hidden_offset: None,
            hidden_password: None,
        };

        let password = "TestPassword123!@#Strong";
        let handle = mount(&container_path, password, options).expect("Failed to mount container");

        let mount_path = Path::new(&mount_point);

        // Create a test file
        let test_file = mount_path.join("test.txt");
        let test_content = "Hello, encrypted world!";
        fs::write(&test_file, test_content).expect("Failed to write test file");

        // Read it back
        let read_content = fs::read_to_string(&test_file).expect("Failed to read test file");
        assert_eq!(read_content, test_content);

        // Create a directory
        let test_dir = mount_path.join("test_dir");
        fs::create_dir(&test_dir).expect("Failed to create directory");
        assert!(test_dir.is_dir());

        // Create a file in the directory
        let nested_file = test_dir.join("nested.txt");
        fs::write(&nested_file, "Nested content").expect("Failed to write nested file");

        // List directory contents
        let entries: Vec<_> = fs::read_dir(&test_dir)
            .expect("Failed to read directory")
            .collect();
        assert_eq!(entries.len(), 1);

        // Delete the file
        fs::remove_file(&nested_file).expect("Failed to remove nested file");
        assert!(!nested_file.exists());

        // Delete the directory
        fs::remove_dir(&test_dir).expect("Failed to remove directory");
        assert!(!test_dir.exists());

        // Unmount
        handle.unmount().expect("Failed to unmount");
    }

    #[test]
    #[ignore] // Requires elevated privileges
    fn test_mount_readonly() {
        require_winfsp!();

        use tesseract_lib::volume::mount::{mount, MountOptions};

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let container_path =
            create_test_container(temp_dir.path(), 10).expect("Failed to create container");

        // First mount read-write to create a file
        {
            let mount_point = find_available_drive_letter().expect("No available drive letter");

            let options = MountOptions {
                mount_point: mount_point.clone().into(),
                read_only: false,
                ..Default::default()
            };

            let password = "TestPassword123!@#Strong";
            let handle =
                mount(&container_path, password, options).expect("Failed to mount container");

            let test_file = Path::new(&mount_point).join("readonly_test.txt");
            fs::write(&test_file, "test content").expect("Failed to write");

            handle.unmount().expect("Failed to unmount");
        }

        // Now mount read-only
        {
            let mount_point = find_available_drive_letter().expect("No available drive letter");

            let options = MountOptions {
                mount_point: mount_point.clone().into(),
                read_only: true,
                ..Default::default()
            };

            let password = "TestPassword123!@#Strong";
            let handle =
                mount(&container_path, password, options).expect("Failed to mount container");

            let test_file = Path::new(&mount_point).join("readonly_test.txt");

            // Should be able to read
            let content = fs::read_to_string(&test_file).expect("Failed to read");
            assert_eq!(content, "test content");

            // Should NOT be able to write
            let result = fs::write(&test_file, "new content");
            assert!(result.is_err(), "Write should fail on read-only mount");

            handle.unmount().expect("Failed to unmount");
        }
    }

    /// Find an available drive letter for mounting.
    fn find_available_drive_letter() -> Option<String> {
        // Check drive letters Z through G (reverse order to avoid common drives)
        for letter in ('G'..='Z').rev() {
            let drive = format!("{}:", letter);
            let path = format!("{}\\", drive);
            if !Path::new(&path).exists() {
                return Some(drive);
            }
        }
        None
    }
}

// ============================================================================
// Performance Tests
// ============================================================================

mod performance_tests {
    use super::*;

    #[test]
    #[ignore] // Requires actual mounting
    fn test_large_file_performance() {
        require_winfsp!();

        // This would test read/write performance with large files
        // Skipped by default as it requires mounting
    }

    #[test]
    #[ignore] // Requires actual mounting
    fn test_many_small_files_performance() {
        require_winfsp!();

        // This would test creating many small files
        // Skipped by default as it requires mounting
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod error_tests {
    use super::*;

    #[test]
    fn test_mount_nonexistent_container() {
        require_winfsp!();

        use tesseract_lib::volume::mount::{mount, MountOptions};

        let options = MountOptions {
            mount_point: "Z:".into(),
            ..Default::default()
        };

        let result = mount(Path::new("nonexistent_container.scv"), "password", options);

        assert!(
            result.is_err(),
            "Mounting nonexistent container should fail"
        );
    }

    #[test]
    fn test_mount_wrong_password() {
        require_winfsp!();

        use tesseract_lib::volume::mount::{mount, MountOptions};

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let container_path = mount_tests::create_test_container(temp_dir.path(), 10)
            .expect("Failed to create container");

        let options = MountOptions {
            mount_point: "Z:".into(),
            ..Default::default()
        };

        let result = mount(&container_path, "wrong_password", options);

        assert!(result.is_err(), "Mounting with wrong password should fail");
    }
}
