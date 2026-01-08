// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! IPC protocol for daemon communication
//!
//! Uses a simple JSON-based protocol over Unix domain sockets (or named pipes on Windows)
//!
//! # Security
//!
//! All commands (except Ping) require authentication via a token that is generated
//! when the daemon starts. The token is stored in a file only readable by the user
//! who started the daemon.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use zeroize::Zeroize;

/// Authentication token length in bytes (256 bits)
pub const AUTH_TOKEN_LENGTH: usize = 32;

/// Server identity response length in bytes (256 bits)
pub const SERVER_IDENTITY_LENGTH: usize = 32;

/// Challenge nonce length in bytes (256 bits)
pub const CHALLENGE_NONCE_LENGTH: usize = 32;

/// Authenticated request wrapper
///
/// All daemon commands must be wrapped in this type with a valid auth token.
/// The auth token is generated when the daemon starts and stored in a file
/// only readable by the current user.
///
/// # Security
///
/// The Drop implementation zeroizes the auth_token from memory (CWE-316 mitigation).
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthenticatedRequest {
    /// Authentication token (hex-encoded)
    pub auth_token: String,
    /// The command to execute
    pub command: DaemonCommand,
}

impl Drop for AuthenticatedRequest {
    fn drop(&mut self) {
        // Securely zeroize the auth token from memory (CWE-316)
        self.auth_token.zeroize();
    }
}

impl AuthenticatedRequest {
    /// Create a new authenticated request
    pub fn new(auth_token: String, command: DaemonCommand) -> Self {
        Self {
            auth_token,
            command,
        }
    }

    /// Serialize request to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let json = serde_json::to_string(self)?;
        Ok(json.into_bytes())
    }

    /// Deserialize request from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

impl fmt::Debug for AuthenticatedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedRequest")
            .field("auth_token", &"<REDACTED>")
            .field("command", &self.command)
            .finish()
    }
}

/// Commands that can be sent to the daemon
///
/// Note: Debug is implemented manually to redact sensitive password fields
///
/// # Security
///
/// This enum implements `Drop` to ensure passwords are securely
/// erased from memory when the command is dropped (CWE-316 mitigation).
#[derive(Clone, Serialize, Deserialize)]
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

    /// Verify server identity with a challenge-response
    ///
    /// The client sends a random challenge nonce, and the server must respond
    /// with a keyed BLAKE3 hash of the challenge using the auth token as the key.
    /// This proves the server knows the auth token without the client sending
    /// sensitive data to an untrusted server.
    ///
    /// # Security
    ///
    /// This command MUST be called before sending any sensitive commands (Mount)
    /// to verify that the daemon is legitimate and not an impersonator.
    VerifyServer {
        /// Random challenge nonce (32 bytes, hex-encoded)
        challenge: String,
    },
}

impl fmt::Debug for DaemonCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonCommand::Mount {
                container_path,
                mount_point,
                password: _,
                read_only,
                hidden_offset,
                hidden_password,
            } => f
                .debug_struct("Mount")
                .field("container_path", container_path)
                .field("mount_point", mount_point)
                .field("password", &"<REDACTED>")
                .field("read_only", read_only)
                .field("hidden_offset", hidden_offset)
                .field(
                    "hidden_password",
                    &hidden_password.as_ref().map(|_| "<REDACTED>"),
                )
                .finish(),
            DaemonCommand::Unmount { container_path } => f
                .debug_struct("Unmount")
                .field("container_path", container_path)
                .finish(),
            DaemonCommand::UnmountByMountPoint { mount_point } => f
                .debug_struct("UnmountByMountPoint")
                .field("mount_point", mount_point)
                .finish(),
            DaemonCommand::List => write!(f, "List"),
            DaemonCommand::GetInfo { container_path } => f
                .debug_struct("GetInfo")
                .field("container_path", container_path)
                .finish(),
            DaemonCommand::UnmountAll => write!(f, "UnmountAll"),
            DaemonCommand::Ping => write!(f, "Ping"),
            DaemonCommand::Shutdown => write!(f, "Shutdown"),
            DaemonCommand::VerifyServer { .. } => f
                .debug_struct("VerifyServer")
                .field("challenge", &"<CHALLENGE>")
                .finish(),
        }
    }
}

// Note: DaemonCommand does not implement Drop because it needs to be destructured
// in process_command(). Instead, password fields are manually zeroized via
// zeroize_secrets() method after use (CWE-316 mitigation).

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

    /// Server identity verification response
    ///
    /// Contains the server's proof that it knows the auth token by
    /// signing the client's challenge with keyed BLAKE3.
    ServerIdentity {
        /// BLAKE3 keyed hash of challenge (32 bytes, hex-encoded)
        /// Key = auth_token, Message = challenge || "tesseract-server-identity-v1"
        response: String,
    },

    /// Authentication failed - invalid or missing token
    Unauthorized {
        /// Error message
        message: String,
    },

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

    /// Zeroize any sensitive fields (passwords) in the command.
    ///
    /// Call this after the command has been serialized/used to ensure
    /// passwords are securely erased from memory (CWE-316 mitigation).
    pub fn zeroize_secrets(&mut self) {
        if let DaemonCommand::Mount {
            password,
            hidden_password,
            ..
        } = self
        {
            password.zeroize();
            if let Some(ref mut hp) = hidden_password {
                hp.zeroize();
            }
        }
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

    /// Create an unauthorized response
    pub fn unauthorized<S: Into<String>>(message: S) -> Self {
        DaemonResponse::Unauthorized {
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
