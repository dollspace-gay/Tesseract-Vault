// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Platform-specific volume mounting implementations
//!
//! This module provides cross-platform support for mounting encrypted volumes
//! as filesystems using FUSE (Linux) or WinFsp (Windows).

#[cfg(target_os = "linux")]
#[cfg(feature = "encrypted-volumes")]
pub mod fuse;

#[cfg(target_os = "windows")]
#[cfg(feature = "encrypted-volumes")]
pub mod winfsp;

/// Pure utility functions for WinFSP, testable without the driver.
#[cfg(target_os = "windows")]
pub mod winfsp_utils;

use std::path::Path;
use thiserror::Error;
use zeroize::Zeroize;

/// Errors that can occur during volume mounting
#[derive(Debug, Error)]
pub enum MountError {
    /// Container error
    #[cfg(feature = "post-quantum")]
    #[error("Container error: {0}")]
    Container(#[from] super::container::ContainerError),

    /// Filesystem error
    #[error("Filesystem error: {0}")]
    Filesystem(String),

    /// Mount point error
    #[error("Mount point error: {0}")]
    MountPoint(String),

    /// Platform not supported
    #[error("Platform not supported for mounting")]
    PlatformNotSupported,

    /// Feature not enabled
    #[error("Encrypted volumes feature not enabled")]
    FeatureNotEnabled,

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Other error
    #[error("Mount error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, MountError>;

/// Options for mounting a volume
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Mount point path
    pub mount_point: std::path::PathBuf,

    /// Read-only mode
    pub read_only: bool,

    /// Allow other users to access the mount
    pub allow_other: bool,

    /// Auto-unmount on process exit
    pub auto_unmount: bool,

    /// Filesystem name/label
    pub fs_name: Option<String>,

    /// Hidden volume offset (for mounting hidden volumes)
    /// If set, the container will be opened at this offset as a hidden volume
    pub hidden_offset: Option<u64>,

    /// Hidden volume password (when mounting hidden volumes)
    /// This is the password for the hidden volume itself
    /// The main password parameter to mount() should be the outer volume password
    pub hidden_password: Option<String>,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            mount_point: std::path::PathBuf::new(),
            read_only: false,
            allow_other: false,
            auto_unmount: true,
            fs_name: Some("Tesseract".to_string()),
            hidden_offset: None,
            hidden_password: None,
        }
    }
}

impl Drop for MountOptions {
    fn drop(&mut self) {
        // Securely zeroize hidden_password from memory (CWE-316 mitigation)
        if let Some(ref mut password) = self.hidden_password {
            password.zeroize();
        }
    }
}

/// Mount an encrypted container
///
/// # Arguments
///
/// * `container_path` - Path to the container file
/// * `password` - Password to unlock the container
/// * `options` - Mount options
///
/// # Returns
///
/// A handle that keeps the mount alive (unmounts on drop)
///
/// # Errors
///
/// Returns an error if:
/// - The container cannot be opened
/// - The password is incorrect
/// - The mount point is invalid
/// - The platform is not supported
#[cfg(feature = "encrypted-volumes")]
pub fn mount(
    container_path: impl AsRef<Path>,
    password: &str,
    options: MountOptions,
) -> Result<MountHandle> {
    #[cfg(target_os = "linux")]
    {
        fuse::mount(container_path, password, options).map(|inner| MountHandle { inner })
    }

    #[cfg(target_os = "windows")]
    {
        winfsp::mount(container_path, password, options).map(|inner| MountHandle { inner })
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(MountError::PlatformNotSupported)
    }
}

/// Handle to a mounted volume
///
/// The volume is automatically unmounted when this handle is dropped.
#[cfg(feature = "encrypted-volumes")]
pub struct MountHandle {
    #[cfg(target_os = "linux")]
    inner: fuse::FuseMountHandle,

    #[cfg(target_os = "windows")]
    inner: winfsp::WinFspMountHandle,
}

#[cfg(feature = "encrypted-volumes")]
impl MountHandle {
    /// Returns the mount point path
    pub fn mount_point(&self) -> &Path {
        #[cfg(target_os = "linux")]
        {
            self.inner.mount_point()
        }

        #[cfg(target_os = "windows")]
        {
            self.inner.mount_point()
        }
    }

    /// Unmounts the volume
    pub fn unmount(self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.inner.unmount()
        }

        #[cfg(target_os = "windows")]
        {
            self.inner.unmount()
        }
    }
}

#[cfg(not(feature = "encrypted-volumes"))]
pub fn mount(
    _container_path: impl AsRef<Path>,
    _password: &str,
    _options: MountOptions,
) -> Result<()> {
    Err(MountError::FeatureNotEnabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_options_default() {
        let opts = MountOptions::default();
        assert!(!opts.read_only);
        assert!(!opts.allow_other);
        assert!(opts.auto_unmount);
        assert_eq!(opts.fs_name, Some("Tesseract".to_string()));
        assert!(opts.hidden_offset.is_none());
        assert!(opts.hidden_password.is_none());
    }

    #[test]
    fn test_mount_options_clone() {
        let opts = MountOptions {
            mount_point: std::path::PathBuf::from("/mnt/test"),
            read_only: true,
            allow_other: true,
            auto_unmount: false,
            fs_name: Some("TestFS".to_string()),
            hidden_offset: Some(1024),
            hidden_password: Some("secret".to_string()),
        };

        let cloned = opts.clone();
        assert_eq!(cloned.mount_point, std::path::PathBuf::from("/mnt/test"));
        assert!(cloned.read_only);
        assert!(cloned.allow_other);
        assert!(!cloned.auto_unmount);
        assert_eq!(cloned.fs_name, Some("TestFS".to_string()));
        assert_eq!(cloned.hidden_offset, Some(1024));
        assert_eq!(cloned.hidden_password, Some("secret".to_string()));
    }

    #[test]
    fn test_mount_error_display() {
        let err = MountError::FeatureNotEnabled;
        assert!(err.to_string().contains("not enabled"));

        let err = MountError::PlatformNotSupported;
        assert!(err.to_string().contains("not supported"));

        let err = MountError::Filesystem("test fs error".to_string());
        assert!(err.to_string().contains("Filesystem error"));
        assert!(err.to_string().contains("test fs error"));

        let err = MountError::MountPoint("invalid path".to_string());
        assert!(err.to_string().contains("Mount point error"));
        assert!(err.to_string().contains("invalid path"));

        let err = MountError::Other("custom error".to_string());
        assert!(err.to_string().contains("Mount error"));
        assert!(err.to_string().contains("custom error"));
    }

    #[test]
    fn test_mount_error_io_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let mount_err: MountError = io_err.into();
        assert!(matches!(mount_err, MountError::Io(_)));
        assert!(mount_err.to_string().contains("I/O error"));
    }

    #[test]
    #[cfg(not(feature = "encrypted-volumes"))]
    fn test_mount_feature_disabled() {
        let result = mount("/fake/path", "password", MountOptions::default());
        assert!(matches!(result, Err(MountError::FeatureNotEnabled)));
    }
}
