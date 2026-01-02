// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! IPC protocol for daemon communication
//!
//! Uses a simple JSON-based protocol over Unix domain sockets (or named pipes on Windows)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Commands that can be sent to the daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonCommand {
    /// Mount a volume
    Mount {
        /// Path to the container file
        container_path: PathBuf,
        /// Mount point (drive letter or directory)
        mount_point: PathBuf,
        /// Password for unlocking the container
        password: String,
        /// Optional: Read-only mount
        read_only: bool,
        /// Optional: Hidden volume offset
        hidden_offset: Option<u64>,
        /// Optional: Hidden volume password (required if hidden_offset is set)
        hidden_password: Option<String>,
    },

    /// Unmount a volume by container path
    Unmount {
        /// Path to the container file
        container_path: PathBuf,
    },

    /// Unmount a volume by mount point
    UnmountByMountPoint {
        /// Mount point (drive letter or directory)
        mount_point: PathBuf,
    },

    /// List all mounted volumes
    List,

    /// Get information about a specific mount
    GetInfo {
        /// Path to the container file
        container_path: PathBuf,
    },

    /// Unmount all volumes (shutdown preparation)
    UnmountAll,

    /// Ping the daemon to check if it's alive
    Ping,

    /// Shutdown the daemon
    Shutdown,
}

/// Responses from the daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonResponse {
    /// Operation succeeded
    Success,

    /// Mount operation succeeded
    Mounted {
        /// Information about the mounted volume
        info: MountInfo,
    },

    /// Unmount operation succeeded
    Unmounted {
        /// Path to the container that was unmounted
        container_path: PathBuf,
    },

    /// List of mounted volumes
    MountList {
        /// List of all mounted volumes
        mounts: Vec<MountInfo>,
    },

    /// Information about a specific mount
    MountInfo {
        /// Mount information
        info: MountInfo,
    },

    /// Pong response to ping
    Pong,

    /// Operation failed with error
    Error {
        /// Error message
        message: String,
    },
}

/// Information about a mounted volume
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    /// Path to the container file
    pub container_path: PathBuf,

    /// Mount point (drive letter or directory)
    pub mount_point: PathBuf,

    /// Whether the mount is read-only
    pub read_only: bool,

    /// Whether this is a hidden volume
    pub is_hidden: bool,

    /// When the volume was mounted (Unix timestamp)
    pub mounted_at: u64,

    /// Process ID of the mount (for cleanup)
    pub pid: Option<u32>,
}

impl DaemonCommand {
    /// Serialize command to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let json = serde_json::to_string(self)?;
        Ok(json.into_bytes())
    }

    /// Deserialize command from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

impl DaemonResponse {
    /// Serialize response to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let json = serde_json::to_string(self)?;
        Ok(json.into_bytes())
    }

    /// Deserialize response from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Create an error response
    pub fn error<S: Into<String>>(message: S) -> Self {
        DaemonResponse::Error {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_serialization() {
        let cmd = DaemonCommand::Mount {
            container_path: PathBuf::from("/path/to/container.crypt"),
            mount_point: PathBuf::from("/mnt/secure"),
            password: "test123".to_string(),
            read_only: false,
            hidden_offset: None,
            hidden_password: None,
        };

        let bytes = cmd.to_bytes().unwrap();
        let decoded = DaemonCommand::from_bytes(&bytes).unwrap();

        match decoded {
            DaemonCommand::Mount { container_path, .. } => {
                assert_eq!(container_path, PathBuf::from("/path/to/container.crypt"));
            }
            _ => panic!("Wrong command type"),
        }
    }

    #[test]
    fn test_response_serialization() {
        let resp = DaemonResponse::Success;
        let bytes = resp.to_bytes().unwrap();
        let decoded = DaemonResponse::from_bytes(&bytes).unwrap();

        matches!(decoded, DaemonResponse::Success);
    }

    #[test]
    fn test_command_unmount_serialization() {
        let cmd = DaemonCommand::Unmount {
            container_path: PathBuf::from("/path/to/container.crypt"),
        };

        let bytes = cmd.to_bytes().unwrap();
        let decoded = DaemonCommand::from_bytes(&bytes).unwrap();

        match decoded {
            DaemonCommand::Unmount { container_path } => {
                assert_eq!(container_path, PathBuf::from("/path/to/container.crypt"));
            }
            _ => panic!("Wrong command type"),
        }
    }

    #[test]
    fn test_command_list_serialization() {
        let cmd = DaemonCommand::List;
        let bytes = cmd.to_bytes().unwrap();
        let decoded = DaemonCommand::from_bytes(&bytes).unwrap();
        assert!(matches!(decoded, DaemonCommand::List));
    }

    #[test]
    fn test_command_ping_serialization() {
        let cmd = DaemonCommand::Ping;
        let bytes = cmd.to_bytes().unwrap();
        let decoded = DaemonCommand::from_bytes(&bytes).unwrap();
        assert!(matches!(decoded, DaemonCommand::Ping));
    }

    #[test]
    fn test_command_shutdown_serialization() {
        let cmd = DaemonCommand::Shutdown;
        let bytes = cmd.to_bytes().unwrap();
        let decoded = DaemonCommand::from_bytes(&bytes).unwrap();
        assert!(matches!(decoded, DaemonCommand::Shutdown));
    }

    #[test]
    fn test_response_error_helper() {
        let resp = DaemonResponse::error("test error message");
        match resp {
            DaemonResponse::Error { message } => {
                assert_eq!(message, "test error message");
            }
            _ => panic!("Expected Error variant"),
        }
    }

    #[test]
    fn test_response_pong_serialization() {
        let resp = DaemonResponse::Pong;
        let bytes = resp.to_bytes().unwrap();
        let decoded = DaemonResponse::from_bytes(&bytes).unwrap();
        assert!(matches!(decoded, DaemonResponse::Pong));
    }

    #[test]
    fn test_mount_info_serialization() {
        let info = MountInfo {
            container_path: PathBuf::from("/test/container.crypt"),
            mount_point: PathBuf::from("/mnt/secure"),
            read_only: false,
            is_hidden: true,
            mounted_at: 1234567890,
            pid: Some(1234),
        };

        let json = serde_json::to_string(&info).unwrap();
        let decoded: MountInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(
            decoded.container_path,
            PathBuf::from("/test/container.crypt")
        );
        assert_eq!(decoded.mount_point, PathBuf::from("/mnt/secure"));
        assert!(!decoded.read_only);
        assert!(decoded.is_hidden);
        assert_eq!(decoded.mounted_at, 1234567890);
        assert_eq!(decoded.pid, Some(1234));
    }

    #[test]
    fn test_response_mount_list_serialization() {
        let info = MountInfo {
            container_path: PathBuf::from("/test"),
            mount_point: PathBuf::from("/mnt"),
            read_only: true,
            is_hidden: false,
            mounted_at: 12345,
            pid: None,
        };

        let resp = DaemonResponse::MountList { mounts: vec![info] };

        let bytes = resp.to_bytes().unwrap();
        let decoded = DaemonResponse::from_bytes(&bytes).unwrap();

        match decoded {
            DaemonResponse::MountList { mounts } => {
                assert_eq!(mounts.len(), 1);
                assert!(mounts[0].read_only);
            }
            _ => panic!("Expected MountList variant"),
        }
    }
}
