// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Daemon client implementation
//!
//! Provides a client interface for communicating with the daemon server.
//!
//! # Authentication
//!
//! The client automatically loads the authentication token from the token file
//! created by the daemon. All commands are wrapped in an authenticated request.

use std::io::{Read, Write};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(windows)]
use std::net::TcpStream;

use super::auth::AuthManager;
use super::protocol::{AuthenticatedRequest, DaemonCommand, DaemonResponse};
use zeroize::Zeroize;

/// Maximum response size to prevent memory exhaustion DoS (16 MB)
const MAX_RESPONSE_SIZE: usize = 16 * 1024 * 1024;

/// Client for communicating with the daemon
///
/// # Security
///
/// The Drop implementation zeroizes the auth_token from memory (CWE-316 mitigation).
pub struct DaemonClient {
    socket_path: PathBuf,
    /// Authentication token (loaded from file)
    auth_token: Option<String>,
}

impl Drop for DaemonClient {
    fn drop(&mut self) {
        // Securely zeroize the auth token from memory (CWE-316)
        if let Some(ref mut token) = self.auth_token {
            token.zeroize();
        }
    }
}

impl DaemonClient {
    /// Create a new daemon client
    ///
    /// This will attempt to load the authentication token from the token file.
    /// If the token cannot be loaded (e.g., daemon not running), authentication
    /// will not be available but the client can still send ping requests.
    pub fn new() -> Self {
        // Try to load auth token
        let auth_token = match AuthManager::load() {
            Ok(auth) => Some(auth.token().to_string()),
            Err(_) => None, // Token not available - daemon may not be running
        };

        Self {
            socket_path: Self::default_socket_path(),
            auth_token,
        }
    }

    /// Create a client with a specific auth token (for testing)
    #[cfg(test)]
    pub fn with_token(token: String) -> Self {
        Self {
            socket_path: Self::default_socket_path(),
            auth_token: Some(token),
        }
    }

    /// Get the default socket path for the platform
    #[cfg(unix)]
    fn default_socket_path() -> PathBuf {
        // Use XDG_RUNTIME_DIR if available (preferred - per-session, auto-cleaned)
        // Otherwise fall back to XDG_DATA_HOME or ~/.local/share/tesseract
        // SECURITY: Never use /tmp to prevent symlink attacks (CWE-377)
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join("tesseract/daemon.sock")
        } else if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
            PathBuf::from(data_home).join("tesseract/daemon.sock")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".local/share/tesseract/daemon.sock")
        } else {
            // Use /var/run/user/{uid} as fallback (user-owned, not world-writable)
            // This is more secure than /tmp which is world-writable
            #[cfg(unix)]
            {
                let uid = unsafe { libc::getuid() };
                PathBuf::from(format!("/var/run/user/{}/tesseract/daemon.sock", uid))
            }
            #[cfg(not(unix))]
            {
                // This branch shouldn't be reached on Unix, but provide a safe default
                PathBuf::from("/var/tmp/tesseract-daemon.sock")
            }
        }
    }

    #[cfg(windows)]
    fn default_socket_path() -> PathBuf {
        // Port is configurable via TESSERACT_DAEMON_PORT environment variable
        let port = std::env::var("TESSERACT_DAEMON_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(37284);
        PathBuf::from(format!("127.0.0.1:{}", port))
    }

    /// Check if the daemon is running
    pub fn is_running(&self) -> bool {
        self.send_command(DaemonCommand::Ping).is_ok()
    }

    /// Reload the authentication token from disk
    ///
    /// Call this if the daemon was restarted and has a new token.
    pub fn reload_token(&mut self) {
        self.auth_token = match AuthManager::load() {
            Ok(auth) => Some(auth.token().to_string()),
            Err(_) => None,
        };
    }

    /// Check if the client has an authentication token
    pub fn has_token(&self) -> bool {
        self.auth_token.is_some()
    }

    /// Send a command to the daemon
    pub fn send_command(
        &self,
        command: DaemonCommand,
    ) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            self.send_command_unix(command)
        }

        #[cfg(windows)]
        {
            self.send_command_windows(command)
        }
    }

    #[cfg(unix)]
    fn send_command_unix(
        &self,
        command: DaemonCommand,
    ) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        self.send_command_impl(&mut stream, command)
    }

    #[cfg(windows)]
    fn send_command_windows(
        &self,
        command: DaemonCommand,
    ) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let addr = self.socket_path.to_string_lossy();
        let mut stream = TcpStream::connect(addr.as_ref())?;
        self.send_command_impl(&mut stream, command)
    }

    /// Implementation of command sending (generic over stream type)
    fn send_command_impl<S: Read + Write>(
        &self,
        stream: &mut S,
        mut command: DaemonCommand,
    ) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        // Wrap command in authenticated request if we have a token
        let request_bytes = if let Some(ref token) = self.auth_token {
            let mut request = AuthenticatedRequest::new(token.clone(), command);
            let bytes = request.to_bytes()?;
            // Zeroize passwords after serialization (CWE-316 mitigation)
            request.command.zeroize_secrets();
            bytes
        } else {
            // Fall back to legacy unauthenticated command (only Ping will work)
            let bytes = command.to_bytes()?;
            // Zeroize passwords after serialization (CWE-316 mitigation)
            command.zeroize_secrets();
            bytes
        };

        // Send request with length prefix
        let len_bytes = (request_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes)?;
        stream.write_all(&request_bytes)?;
        stream.flush()?;

        // Read response (prefixed with 4-byte length)
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes)?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Validate response size to prevent memory exhaustion DoS
        if len > MAX_RESPONSE_SIZE {
            return Err(format!(
                "Response size {} exceeds maximum allowed size {}",
                len, MAX_RESPONSE_SIZE
            )
            .into());
        }

        let mut buffer = vec![0u8; len];
        stream.read_exact(&mut buffer)?;

        // Parse response
        let response = DaemonResponse::from_bytes(&buffer)?;

        Ok(response)
    }

    /// Mount a volume via the daemon
    pub fn mount(
        &self,
        container_path: PathBuf,
        mount_point: PathBuf,
        password: String,
        read_only: bool,
        hidden_offset: Option<u64>,
        hidden_password: Option<String>,
    ) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let command = DaemonCommand::Mount {
            container_path,
            mount_point,
            password,
            read_only,
            hidden_offset,
            hidden_password,
        };

        self.send_command(command)
    }

    /// Unmount a volume by container path
    pub fn unmount(
        &self,
        container_path: PathBuf,
    ) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let command = DaemonCommand::Unmount { container_path };
        self.send_command(command)
    }

    /// Unmount a volume by mount point
    pub fn unmount_by_mount_point(
        &self,
        mount_point: PathBuf,
    ) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let command = DaemonCommand::UnmountByMountPoint { mount_point };
        self.send_command(command)
    }

    /// List all mounted volumes
    pub fn list(&self) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        self.send_command(DaemonCommand::List)
    }

    /// Get information about a specific mount
    pub fn get_info(
        &self,
        container_path: PathBuf,
    ) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let command = DaemonCommand::GetInfo { container_path };
        self.send_command(command)
    }

    /// Unmount all volumes
    pub fn unmount_all(&self) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        self.send_command(DaemonCommand::UnmountAll)
    }

    /// Shutdown the daemon
    pub fn shutdown(&self) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        self.send_command(DaemonCommand::Shutdown)
    }

    /// Verify the server's identity before sending sensitive commands
    ///
    /// This sends a random challenge to the server and verifies that the server
    /// can produce a valid response using the shared auth token. This proves
    /// the server is legitimate and not an impersonator.
    ///
    /// # Security
    ///
    /// IMPORTANT: Call this method before sending any sensitive commands (like Mount)
    /// to verify that you're communicating with the legitimate daemon, not a malicious
    /// process that has taken over the socket/port.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the server's identity was verified successfully
    /// - `Ok(false)` if verification failed (server may be an impersonator)
    /// - `Err(...)` if there was a communication error
    pub fn verify_server(&self) -> Result<bool, Box<dyn std::error::Error>> {
        use super::protocol::CHALLENGE_NONCE_LENGTH;
        use blake3::Hasher;
        use subtle::ConstantTimeEq;

        // We need the token to verify the server's response
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err("No auth token available for server verification".into()),
        };

        // Generate a random challenge
        let mut challenge_bytes = [0u8; CHALLENGE_NONCE_LENGTH];
        getrandom::fill(&mut challenge_bytes)
            .map_err(|e| format!("Failed to generate challenge: {}", e))?;
        let challenge = hex::encode(challenge_bytes);

        // Send VerifyServer command (without authentication wrapper)
        let command = DaemonCommand::VerifyServer {
            challenge: challenge.clone(),
        };
        let request_bytes = command.to_bytes()?;

        // Connect and send (this bypasses the normal send_command which adds auth wrapper)
        #[cfg(unix)]
        let response = {
            use std::os::unix::net::UnixStream;
            let mut stream = UnixStream::connect(&self.socket_path)?;
            self.send_raw_command(&mut stream, &request_bytes)?
        };

        #[cfg(windows)]
        let response = {
            use std::net::TcpStream;
            let addr = self.socket_path.to_string_lossy();
            let mut stream = TcpStream::connect(addr.as_ref())?;
            self.send_raw_command(&mut stream, &request_bytes)?
        };

        // Verify the response
        match response {
            DaemonResponse::ServerIdentity { response: server_response } => {
                // Decode the server's response
                let server_response_bytes = match hex::decode(&server_response) {
                    Ok(bytes) if bytes.len() == 32 => bytes,
                    _ => return Ok(false), // Invalid response format
                };

                // Compute the expected response ourselves
                let token_bytes: [u8; 32] = match hex::decode(token) {
                    Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap_or([0u8; 32]),
                    _ => return Err("Invalid token format".into()),
                };

                let mut hasher = Hasher::new_keyed(&token_bytes);
                hasher.update(&challenge_bytes);
                hasher.update(b"tesseract-server-identity-v1");
                let expected = hasher.finalize();

                // Constant-time comparison
                let is_valid: bool = expected.as_bytes().ct_eq(&server_response_bytes).into();
                Ok(is_valid)
            }
            DaemonResponse::Error { message } => {
                Err(format!("Server verification failed: {}", message).into())
            }
            _ => Ok(false), // Unexpected response type
        }
    }

    /// Send a raw command without authentication wrapper
    fn send_raw_command<S: Read + Write>(
        &self,
        stream: &mut S,
        request_bytes: &[u8],
    ) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        // Send request with length prefix
        let len_bytes = (request_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes)?;
        stream.write_all(request_bytes)?;
        stream.flush()?;

        // Read response (prefixed with 4-byte length)
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes)?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Validate response size
        if len > MAX_RESPONSE_SIZE {
            return Err(format!(
                "Response size {} exceeds maximum allowed size {}",
                len, MAX_RESPONSE_SIZE
            )
            .into());
        }

        let mut buffer = vec![0u8; len];
        stream.read_exact(&mut buffer)?;

        // Parse response
        let response = DaemonResponse::from_bytes(&buffer)?;
        Ok(response)
    }
}

impl Default for DaemonClient {
    fn default() -> Self {
        Self::new()
    }
}
