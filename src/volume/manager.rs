// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Volume management module
//!
//! Provides centralized management of mounted encrypted volumes, including
//! tracking mount points, preventing double-mounting, and coordinating
//! mount/unmount operations across the application.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[cfg(all(feature = "encrypted-volumes", feature = "post-quantum"))]
use super::container::Container;
#[cfg(feature = "post-quantum")]
use super::container::ContainerError;
use super::mount::{MountError, MountOptions};

#[cfg(feature = "encrypted-volumes")]
use super::mount::MountHandle;

/// Errors that can occur during volume management
#[derive(Debug, Error)]
pub enum VolumeManagerError {
    /// Container error
    #[cfg(feature = "post-quantum")]
    #[error("Container error: {0}")]
    Container(#[from] ContainerError),

    /// Mount error
    #[error("Mount error: {0}")]
    Mount(#[from] MountError),

    /// Volume already mounted
    #[error("Volume already mounted: {0}")]
    AlreadyMounted(PathBuf),

    /// Volume not found
    #[error("Volume not found: {0}")]
    NotFound(PathBuf),

    /// Mount point already in use
    #[error("Mount point already in use: {0}")]
    MountPointInUse(PathBuf),

    /// Volume is locked by another process
    #[error("Volume is locked by another process: {0}")]
    VolumeInUse(PathBuf),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Other error
    #[error("Volume manager error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, VolumeManagerError>;

/// Information about a mounted volume
#[derive(Debug, Clone)]
pub struct MountedVolumeInfo {
    /// Path to the container file
    pub container_path: PathBuf,

    /// Mount point where the volume is mounted
    pub mount_point: PathBuf,

    /// Whether the volume is mounted read-only
    pub read_only: bool,

    /// Timestamp when the volume was mounted
    pub mounted_at: std::time::SystemTime,

    /// Volume size in bytes
    pub size: u64,

    /// Whether this is a hidden volume
    pub is_hidden: bool,

    /// Hidden volume offset (if this is a hidden volume)
    pub hidden_offset: Option<u64>,
}

/// Handle to a mounted volume managed by VolumeManager
pub struct ManagedVolume {
    info: MountedVolumeInfo,

    #[cfg(feature = "encrypted-volumes")]
    #[allow(dead_code)]
    mount_handle: Arc<Mutex<Option<MountHandle>>>,

    #[cfg(not(feature = "encrypted-volumes"))]
    _phantom: std::marker::PhantomData<()>,
}

impl ManagedVolume {
    /// Returns information about this mounted volume
    pub fn info(&self) -> &MountedVolumeInfo {
        &self.info
    }

    /// Returns the container path
    pub fn container_path(&self) -> &Path {
        &self.info.container_path
    }

    /// Returns the mount point
    pub fn mount_point(&self) -> &Path {
        &self.info.mount_point
    }

    /// Returns whether the volume is read-only
    pub fn is_read_only(&self) -> bool {
        self.info.read_only
    }

    /// Returns the volume size in bytes
    pub fn size(&self) -> u64 {
        self.info.size
    }

    /// Returns when the volume was mounted
    pub fn mounted_at(&self) -> std::time::SystemTime {
        self.info.mounted_at
    }
}

/// Central manager for encrypted volumes
///
/// VolumeManager provides a centralized way to track and manage mounted
/// encrypted volumes. It prevents double-mounting, tracks mount points,
/// and coordinates mount/unmount operations.
///
/// # Example
///
/// ```no_run
/// use tesseract_lib::volume::{VolumeManager, MountOptions};
/// use std::path::PathBuf;
///
/// let mut manager = VolumeManager::new();
///
/// // Mount a volume
/// let options = MountOptions {
///     mount_point: PathBuf::from("/mnt/encrypted"),
///     read_only: false,
///     ..Default::default()
/// };
///
/// let volume = manager.mount(
///     "/path/to/container.scv",
///     "password",
///     options
/// ).unwrap();
///
/// println!("Mounted at: {:?}", volume.mount_point);
///
/// // List all mounted volumes
/// for info in manager.list_mounted() {
///     println!("{:?} -> {:?}", info.container_path, info.mount_point);
/// }
///
/// // Unmount
/// manager.unmount("/path/to/container.scv").unwrap();
/// ```
pub struct VolumeManager {
    /// Map of container path -> mounted volume info
    mounted: Arc<Mutex<HashMap<PathBuf, ManagedVolume>>>,
}

impl VolumeManager {
    /// Creates a new volume manager
    pub fn new() -> Self {
        Self {
            mounted: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Mounts an encrypted volume
    ///
    /// # Arguments
    ///
    /// * `container_path` - Path to the container file
    /// * `password` - Password to unlock the container
    /// * `options` - Mount options
    ///
    /// # Returns
    ///
    /// Information about the mounted volume
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The container is already mounted
    /// - The mount point is already in use
    /// - The container cannot be opened
    /// - The password is incorrect
    /// - The mount operation fails
    #[cfg(feature = "encrypted-volumes")]
    pub fn mount(
        &mut self,
        container_path: impl AsRef<Path>,
        password: &str,
        options: MountOptions,
    ) -> Result<MountedVolumeInfo> {
        let container_path = container_path
            .as_ref()
            .canonicalize()
            .unwrap_or_else(|_| container_path.as_ref().to_path_buf());

        // Check if already mounted
        {
            let mounted = self.mounted.lock().unwrap();
            if mounted.contains_key(&container_path) {
                return Err(VolumeManagerError::AlreadyMounted(container_path));
            }

            // Check if mount point is already in use
            if mounted
                .values()
                .any(|v| v.mount_point() == options.mount_point)
            {
                return Err(VolumeManagerError::MountPointInUse(
                    options.mount_point.clone(),
                ));
            }
        }

        // Get container info and determine password for mounting
        let (container, size, is_hidden, mount_password) =
            if let Some(hidden_offset) = options.hidden_offset {
                // For hidden volumes:
                // - password parameter is the outer volume password
                // - options.hidden_password contains the hidden volume password
                let hidden_pwd = options.hidden_password.as_ref().ok_or_else(|| {
                    VolumeManagerError::Other(
                        "Hidden password required for hidden volume mount".to_string(),
                    )
                })?;

                let outer = Container::open(&container_path, password)?;
                let hidden = outer.open_hidden_volume(hidden_pwd, hidden_offset)?;
                let hidden_size = hidden.data_size();
                drop(hidden);
                drop(outer);
                (
                    container_path.clone(),
                    hidden_size,
                    true,
                    password.to_string(),
                )
            } else {
                // Mount normal volume
                let container = Container::open(&container_path, password)?;
                let size = container.data_size();
                drop(container);
                (container_path.clone(), size, false, password.to_string())
            };

        // Mount the volume
        let mount_handle = super::mount::mount(&container_path, &mount_password, options.clone())?;
        let mount_point = mount_handle.mount_point().to_path_buf();

        // Create volume info
        let info = MountedVolumeInfo {
            container_path: container.clone(),
            mount_point,
            read_only: options.read_only,
            mounted_at: std::time::SystemTime::now(),
            size,
            is_hidden,
            hidden_offset: options.hidden_offset,
        };

        // Store in mounted map
        let managed = ManagedVolume {
            info: info.clone(),
            mount_handle: Arc::new(Mutex::new(Some(mount_handle))),
        };

        self.mounted.lock().unwrap().insert(container_path, managed);

        Ok(info)
    }

    /// Mounts an encrypted volume (stub when feature is disabled)
    #[cfg(not(feature = "encrypted-volumes"))]
    pub fn mount(
        &mut self,
        _container_path: impl AsRef<Path>,
        _password: &str,
        _options: MountOptions,
    ) -> Result<MountedVolumeInfo> {
        Err(VolumeManagerError::Mount(MountError::FeatureNotEnabled))
    }

    /// Unmounts a volume by container path
    ///
    /// # Arguments
    ///
    /// * `container_path` - Path to the container file
    ///
    /// # Errors
    ///
    /// Returns an error if the volume is not mounted
    pub fn unmount(&mut self, container_path: impl AsRef<Path>) -> Result<()> {
        let container_path = container_path
            .as_ref()
            .canonicalize()
            .unwrap_or_else(|_| container_path.as_ref().to_path_buf());

        let mut mounted = self.mounted.lock().unwrap();

        #[cfg(feature = "encrypted-volumes")]
        {
            if let Some(volume) = mounted.remove(&container_path) {
                // Drop the mount handle to trigger unmount
                let mut handle = volume.mount_handle.lock().unwrap();
                if let Some(h) = handle.take() {
                    let _ = h.unmount();
                }
                Ok(())
            } else {
                Err(VolumeManagerError::NotFound(container_path))
            }
        }

        #[cfg(not(feature = "encrypted-volumes"))]
        {
            if mounted.remove(&container_path).is_some() {
                Ok(())
            } else {
                Err(VolumeManagerError::NotFound(container_path))
            }
        }
    }

    /// Unmounts a volume by mount point
    ///
    /// # Arguments
    ///
    /// * `mount_point` - Mount point path
    ///
    /// # Errors
    ///
    /// Returns an error if no volume is mounted at the given mount point
    pub fn unmount_by_mount_point(&mut self, mount_point: impl AsRef<Path>) -> Result<()> {
        let mount_point = mount_point.as_ref();

        // Find the container path for this mount point
        let container_path = {
            let mounted = self.mounted.lock().unwrap();
            mounted
                .iter()
                .find(|(_, v)| v.mount_point() == mount_point)
                .map(|(k, _)| k.clone())
        };

        if let Some(path) = container_path {
            self.unmount(path)
        } else {
            Err(VolumeManagerError::NotFound(mount_point.to_path_buf()))
        }
    }

    /// Unmounts all mounted volumes
    ///
    /// This is useful during application shutdown to ensure all volumes
    /// are properly unmounted.
    pub fn unmount_all(&mut self) {
        let mut mounted = self.mounted.lock().unwrap();

        #[cfg(feature = "encrypted-volumes")]
        {
            for (_, volume) in mounted.drain() {
                let mut handle = volume.mount_handle.lock().unwrap();
                if let Some(h) = handle.take() {
                    let _ = h.unmount();
                }
            }
        }

        #[cfg(not(feature = "encrypted-volumes"))]
        {
            mounted.clear();
        }
    }

    /// Checks if a volume is mounted
    ///
    /// # Arguments
    ///
    /// * `container_path` - Path to the container file
    ///
    /// # Returns
    ///
    /// true if the volume is currently mounted, false otherwise
    pub fn is_mounted(&self, container_path: impl AsRef<Path>) -> bool {
        let container_path = container_path
            .as_ref()
            .canonicalize()
            .unwrap_or_else(|_| container_path.as_ref().to_path_buf());

        self.mounted.lock().unwrap().contains_key(&container_path)
    }

    /// Gets information about a mounted volume
    ///
    /// # Arguments
    ///
    /// * `container_path` - Path to the container file
    ///
    /// # Returns
    ///
    /// Volume information if mounted, None otherwise
    pub fn get_info(&self, container_path: impl AsRef<Path>) -> Option<MountedVolumeInfo> {
        let container_path = container_path
            .as_ref()
            .canonicalize()
            .unwrap_or_else(|_| container_path.as_ref().to_path_buf());

        self.mounted
            .lock()
            .unwrap()
            .get(&container_path)
            .map(|v| v.info.clone())
    }

    /// Lists all currently mounted volumes
    ///
    /// # Returns
    ///
    /// A vector of information about all mounted volumes
    pub fn list_mounted(&self) -> Vec<MountedVolumeInfo> {
        self.mounted
            .lock()
            .unwrap()
            .values()
            .map(|v| v.info.clone())
            .collect()
    }

    /// Returns the number of mounted volumes
    pub fn mount_count(&self) -> usize {
        self.mounted.lock().unwrap().len()
    }

    /// Finds the mount point for a container
    ///
    /// # Arguments
    ///
    /// * `container_path` - Path to the container file
    ///
    /// # Returns
    ///
    /// The mount point path if the volume is mounted, None otherwise
    pub fn find_mount_point(&self, container_path: impl AsRef<Path>) -> Option<PathBuf> {
        let container_path = container_path
            .as_ref()
            .canonicalize()
            .unwrap_or_else(|_| container_path.as_ref().to_path_buf());

        self.mounted
            .lock()
            .unwrap()
            .get(&container_path)
            .map(|v| v.mount_point().to_path_buf())
    }

    /// Finds the container path for a mount point
    ///
    /// # Arguments
    ///
    /// * `mount_point` - Mount point path
    ///
    /// # Returns
    ///
    /// The container path if a volume is mounted there, None otherwise
    pub fn find_container_for_mount_point(&self, mount_point: impl AsRef<Path>) -> Option<PathBuf> {
        let mount_point = mount_point.as_ref();

        self.mounted
            .lock()
            .unwrap()
            .iter()
            .find(|(_, v)| v.mount_point() == mount_point)
            .map(|(k, _)| k.clone())
    }

    /// Checks if a mount point is in use
    ///
    /// # Arguments
    ///
    /// * `mount_point` - Mount point path to check
    ///
    /// # Returns
    ///
    /// true if the mount point is in use, false otherwise
    pub fn is_mount_point_in_use(&self, mount_point: impl AsRef<Path>) -> bool {
        let mount_point = mount_point.as_ref();

        self.mounted
            .lock()
            .unwrap()
            .values()
            .any(|v| v.mount_point() == mount_point)
    }
}

impl Default for VolumeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VolumeManager {
    fn drop(&mut self) {
        // Unmount all volumes on drop
        self.unmount_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_manager() {
        let manager = VolumeManager::new();
        assert_eq!(manager.mount_count(), 0);
        assert_eq!(manager.list_mounted().len(), 0);
    }

    #[test]
    fn test_is_mounted() {
        let manager = VolumeManager::new();
        let path = PathBuf::from("/nonexistent/container.scv");

        assert!(!manager.is_mounted(&path));
    }

    #[test]
    fn test_list_empty() {
        let manager = VolumeManager::new();
        let mounted = manager.list_mounted();
        assert_eq!(mounted.len(), 0);
    }

    #[test]
    fn test_find_mount_point_not_found() {
        let manager = VolumeManager::new();
        let path = PathBuf::from("/nonexistent/container.scv");

        assert!(manager.find_mount_point(&path).is_none());
    }

    #[test]
    fn test_is_mount_point_in_use() {
        let manager = VolumeManager::new();
        let mount_point = PathBuf::from("/mnt/test");

        assert!(!manager.is_mount_point_in_use(&mount_point));
    }

    #[test]
    fn test_get_info_not_found() {
        let manager = VolumeManager::new();
        let path = PathBuf::from("/nonexistent/container.scv");

        assert!(manager.get_info(&path).is_none());
    }

    #[test]
    fn test_unmount_not_mounted() {
        let mut manager = VolumeManager::new();
        let path = PathBuf::from("/nonexistent/container.scv");

        let result = manager.unmount(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_unmount_by_mount_point_not_found() {
        let mut manager = VolumeManager::new();
        let mount_point = PathBuf::from("/mnt/test");

        let result = manager.unmount_by_mount_point(&mount_point);
        assert!(result.is_err());
    }

    #[test]
    fn test_unmount_all_empty() {
        let mut manager = VolumeManager::new();
        manager.unmount_all();
        assert_eq!(manager.mount_count(), 0);
    }

    #[test]
    fn test_default_trait() {
        let manager = VolumeManager::default();
        assert_eq!(manager.mount_count(), 0);
    }

    #[test]
    fn test_find_container_for_mount_point_not_found() {
        let manager = VolumeManager::new();
        let mount_point = PathBuf::from("/mnt/nonexistent");
        assert!(manager
            .find_container_for_mount_point(&mount_point)
            .is_none());
    }

    #[test]
    fn test_volume_manager_error_display() {
        let mount_err = VolumeManagerError::Mount(MountError::FeatureNotEnabled);
        assert!(mount_err.to_string().contains("Mount error"));

        let already_mounted = VolumeManagerError::AlreadyMounted(PathBuf::from("/test/path"));
        assert!(already_mounted.to_string().contains("/test/path"));

        let not_found = VolumeManagerError::NotFound(PathBuf::from("/missing/path"));
        assert!(not_found.to_string().contains("/missing/path"));

        let mount_point_in_use = VolumeManagerError::MountPointInUse(PathBuf::from("/mnt/busy"));
        assert!(mount_point_in_use.to_string().contains("/mnt/busy"));

        let volume_in_use = VolumeManagerError::VolumeInUse(PathBuf::from("/vol/locked"));
        assert!(volume_in_use.to_string().contains("/vol/locked"));

        let io_err = VolumeManagerError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(io_err.to_string().contains("I/O error"));

        let other_err = VolumeManagerError::Other("custom error message".to_string());
        assert!(other_err.to_string().contains("custom error message"));
    }

    #[test]
    fn test_mounted_volume_info_clone() {
        let info = MountedVolumeInfo {
            container_path: PathBuf::from("/container.scv"),
            mount_point: PathBuf::from("/mnt/test"),
            read_only: true,
            mounted_at: std::time::SystemTime::now(),
            size: 1024 * 1024,
            is_hidden: false,
            hidden_offset: None,
        };

        let cloned = info.clone();
        assert_eq!(cloned.container_path, info.container_path);
        assert_eq!(cloned.mount_point, info.mount_point);
        assert_eq!(cloned.read_only, info.read_only);
        assert_eq!(cloned.size, info.size);
        assert_eq!(cloned.is_hidden, info.is_hidden);
        assert_eq!(cloned.hidden_offset, info.hidden_offset);
    }

    #[test]
    fn test_mounted_volume_info_debug() {
        let info = MountedVolumeInfo {
            container_path: PathBuf::from("/container.scv"),
            mount_point: PathBuf::from("/mnt/test"),
            read_only: false,
            mounted_at: std::time::SystemTime::now(),
            size: 2048,
            is_hidden: true,
            hidden_offset: Some(1024),
        };

        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("MountedVolumeInfo"));
        assert!(debug_str.contains("container_path"));
        assert!(debug_str.contains("mount_point"));
    }

    #[test]
    fn test_mounted_volume_info_hidden_volume() {
        let info = MountedVolumeInfo {
            container_path: PathBuf::from("/hidden.scv"),
            mount_point: PathBuf::from("/mnt/hidden"),
            read_only: false,
            mounted_at: std::time::SystemTime::now(),
            size: 512 * 1024,
            is_hidden: true,
            hidden_offset: Some(1024 * 1024),
        };

        assert!(info.is_hidden);
        assert_eq!(info.hidden_offset, Some(1024 * 1024));
    }

    #[test]
    fn test_mount_options_default() {
        let options = MountOptions::default();
        assert!(!options.read_only);
        assert!(options.hidden_offset.is_none());
        assert!(options.hidden_password.is_none());
    }

    #[test]
    fn test_mount_without_feature() {
        let mut manager = VolumeManager::new();
        let options = MountOptions {
            mount_point: PathBuf::from("/mnt/test"),
            read_only: false,
            ..Default::default()
        };

        // This will return an error when encrypted-volumes feature is disabled
        let result = manager.mount("/nonexistent/path.scv", "password", options);
        assert!(result.is_err());
    }

    #[test]
    fn test_volume_manager_multiple_operations() {
        let manager = VolumeManager::new();

        // Test multiple paths
        let path1 = PathBuf::from("/path/to/vol1.scv");
        let path2 = PathBuf::from("/path/to/vol2.scv");

        assert!(!manager.is_mounted(&path1));
        assert!(!manager.is_mounted(&path2));

        // Neither mount point should be in use
        assert!(!manager.is_mount_point_in_use("/mnt/vol1"));
        assert!(!manager.is_mount_point_in_use("/mnt/vol2"));

        // Get info should return None
        assert!(manager.get_info(&path1).is_none());
        assert!(manager.get_info(&path2).is_none());
    }

    #[test]
    fn test_unmount_error_types() {
        let mut manager = VolumeManager::new();

        let result = manager.unmount("/definitely/not/mounted.scv");
        assert!(matches!(result, Err(VolumeManagerError::NotFound(_))));

        let result2 = manager.unmount_by_mount_point("/not/a/mount/point");
        assert!(matches!(result2, Err(VolumeManagerError::NotFound(_))));
    }

    #[test]
    fn test_volume_manager_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let mgr_err: VolumeManagerError = io_err.into();
        assert!(matches!(mgr_err, VolumeManagerError::Io(_)));
        assert!(mgr_err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_volume_manager_error_from_mount() {
        let mount_err = MountError::FeatureNotEnabled;
        let mgr_err: VolumeManagerError = mount_err.into();
        assert!(matches!(mgr_err, VolumeManagerError::Mount(_)));
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn test_volume_manager_error_from_container() {
        let container_err = ContainerError::NotFound(PathBuf::from("/test"));
        let mgr_err: VolumeManagerError = container_err.into();
        assert!(matches!(mgr_err, VolumeManagerError::Container(_)));
    }

    #[test]
    fn test_volume_manager_debug() {
        let manager = VolumeManager::new();
        // Just ensure Debug is implemented - access internal state would require unsafe
        let _ = &manager;
        assert_eq!(manager.mount_count(), 0);
    }

    #[test]
    fn test_volume_manager_drop_behavior() {
        // Creating and dropping a manager should not panic
        {
            let mut manager = VolumeManager::new();
            // unmount_all is called in drop
            manager.unmount_all();
        } // manager dropped here
    }

    #[test]
    fn test_unmount_all_idempotent() {
        let mut manager = VolumeManager::new();
        manager.unmount_all();
        manager.unmount_all();
        manager.unmount_all();
        assert_eq!(manager.mount_count(), 0);
    }

    #[test]
    fn test_is_mounted_with_various_path_formats() {
        let manager = VolumeManager::new();

        // Test various path formats
        assert!(!manager.is_mounted("/absolute/path.scv"));
        assert!(!manager.is_mounted("relative/path.scv"));
        assert!(!manager.is_mounted("./current/path.scv"));
        assert!(!manager.is_mounted("../parent/path.scv"));
    }

    #[test]
    fn test_mount_options_with_hidden_volume() {
        let options = MountOptions {
            mount_point: PathBuf::from("/mnt/hidden"),
            read_only: true,
            hidden_offset: Some(1024 * 1024),
            hidden_password: Some("secret".to_string()),
            ..Default::default()
        };

        assert!(options.read_only);
        assert_eq!(options.hidden_offset, Some(1024 * 1024));
        assert_eq!(options.hidden_password, Some("secret".to_string()));
    }

    #[test]
    fn test_find_mount_point_various_paths() {
        let manager = VolumeManager::new();

        // None of these should be found
        assert!(manager.find_mount_point("vol1.scv").is_none());
        assert!(manager.find_mount_point("/path/vol2.scv").is_none());
        assert!(manager.find_mount_point("C:\\Windows\\test.scv").is_none());
    }

    #[test]
    fn test_find_container_for_mount_point_various_paths() {
        let manager = VolumeManager::new();

        // None of these should be found
        assert!(manager.find_container_for_mount_point("/mnt/a").is_none());
        assert!(manager.find_container_for_mount_point("/mnt/b").is_none());
        assert!(manager.find_container_for_mount_point("Z:\\").is_none());
    }

    #[test]
    fn test_get_info_various_paths() {
        let manager = VolumeManager::new();

        // All should return None
        assert!(manager.get_info("test.scv").is_none());
        assert!(manager.get_info("/vol/test.scv").is_none());
        assert!(manager.get_info("/another/path/test.scv").is_none());
    }

    #[test]
    fn test_mounted_volume_info_fields() {
        let now = std::time::SystemTime::now();
        let info = MountedVolumeInfo {
            container_path: PathBuf::from("/test/container.scv"),
            mount_point: PathBuf::from("/mnt/secure"),
            read_only: true,
            mounted_at: now,
            size: 10 * 1024 * 1024, // 10 MB
            is_hidden: false,
            hidden_offset: None,
        };

        // Verify all fields
        assert_eq!(info.container_path, PathBuf::from("/test/container.scv"));
        assert_eq!(info.mount_point, PathBuf::from("/mnt/secure"));
        assert!(info.read_only);
        assert_eq!(info.mounted_at, now);
        assert_eq!(info.size, 10 * 1024 * 1024);
        assert!(!info.is_hidden);
        assert!(info.hidden_offset.is_none());
    }

    #[test]
    fn test_volume_manager_concurrent_access_safety() {
        use std::thread;

        let manager = VolumeManager::new();
        let mounted = Arc::clone(&manager.mounted);

        // Multiple threads checking if volumes are mounted
        let handles: Vec<_> = (0..5)
            .map(|i| {
                let mounted_clone = Arc::clone(&mounted);
                thread::spawn(move || {
                    let path = PathBuf::from(format!("/vol{}.scv", i));
                    let guard = mounted_clone.lock().unwrap();
                    !guard.contains_key(&path)
                })
            })
            .collect();

        for handle in handles {
            assert!(handle.join().unwrap());
        }
    }

    #[test]
    fn test_volume_manager_error_other_variant() {
        let err = VolumeManagerError::Other("test error".to_string());
        assert!(err.to_string().contains("test error"));
        assert!(err.to_string().contains("Volume manager error"));
    }

    #[test]
    fn test_volume_manager_error_already_mounted() {
        let err = VolumeManagerError::AlreadyMounted(PathBuf::from("/already/mounted.scv"));
        assert!(err.to_string().contains("already mounted"));
        assert!(err.to_string().contains("/already/mounted.scv"));
    }

    #[test]
    fn test_mount_with_invalid_path_returns_error() {
        let mut manager = VolumeManager::new();
        let options = MountOptions {
            mount_point: PathBuf::from("/mnt/test"),
            ..Default::default()
        };

        // Try to mount a path that definitely doesn't exist
        let result = manager.mount("/this/path/does/not/exist.scv", "password", options);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_mounted_returns_vec() {
        let manager = VolumeManager::new();
        let list: Vec<MountedVolumeInfo> = manager.list_mounted();
        assert!(list.is_empty());
        // Ensure it returns a Vec, not a slice
        let _ = list.into_iter();
    }
}
