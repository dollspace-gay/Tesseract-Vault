// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Daemon server implementation
//!
//! Manages mounted volumes and handles IPC requests.
//!
//! # Security
//!
//! All commands require authentication via a token generated at daemon startup.
//! The token is stored in a file only readable by the current user.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum number of concurrent client connections to prevent thread exhaustion DoS
const MAX_CONCURRENT_CONNECTIONS: usize = 32;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

#[cfg(windows)]
use std::net::{TcpListener, TcpStream};

use super::auth::AuthManager;
use super::protocol::{
    AuthenticatedRequest, DaemonCommand, DaemonResponse, DeadManStatusInfo, DeadManStatusType,
    MountInfo,
};
use crate::volume::manager::VolumeManager;
use crate::volume::mount::MountOptions;
use crate::volume::remote_wipe::{DeadMansSwitchStatus, RemoteWipeManager};
use zeroize::Zeroize;

/// Interval for dead man's switch monitoring (check every hour)
const DEAD_MAN_CHECK_INTERVAL_SECS: u64 = 3600;

/// Daemon server state
pub struct DaemonServer {
    /// Volume manager for handling mounts
    volume_manager: Arc<Mutex<VolumeManager>>,

    /// Track mounted volumes
    mounts: Arc<Mutex<HashMap<PathBuf, MountInfo>>>,

    /// Remote wipe managers per volume (for dead man's switch)
    wipe_managers: Arc<Mutex<HashMap<PathBuf, RemoteWipeManager>>>,

    /// Directory for storing wipe configs
    config_dir: PathBuf,

    /// Socket path for IPC
    socket_path: PathBuf,

    /// Counter for active connections (DoS protection)
    active_connections: Arc<AtomicUsize>,

    /// Shutdown signal receiver (optional, for service integration)
    shutdown_rx: Option<mpsc::Receiver<()>>,

    /// Shared shutdown flag for graceful termination
    shutdown_flag: Arc<AtomicBool>,

    /// Authentication manager for validating client tokens
    auth_manager: Option<AuthManager>,
}

impl DaemonServer {
    /// Create a new daemon server
    ///
    /// This initializes authentication by generating a token that clients must use.
    pub fn new() -> Self {
        let socket_path = Self::default_socket_path();
        let config_dir = Self::default_config_dir();

        // Ensure config directory exists
        if let Err(e) = std::fs::create_dir_all(&config_dir) {
            eprintln!(
                "WARNING: Failed to create config directory {:?}: {}",
                config_dir, e
            );
        }

        // Initialize authentication - log warning if it fails but continue
        let auth_manager = match AuthManager::new() {
            Ok(auth) => {
                println!("Authentication token saved to {:?}", auth.token_path());
                Some(auth)
            }
            Err(e) => {
                eprintln!(
                    "WARNING: Failed to initialize authentication: {}. \
                     Daemon will run without authentication!",
                    e
                );
                None
            }
        };

        // Load existing wipe configs
        let wipe_managers = Self::load_wipe_configs(&config_dir);

        Self {
            volume_manager: Arc::new(Mutex::new(VolumeManager::new())),
            mounts: Arc::new(Mutex::new(HashMap::new())),
            wipe_managers: Arc::new(Mutex::new(wipe_managers)),
            config_dir,
            socket_path,
            active_connections: Arc::new(AtomicUsize::new(0)),
            shutdown_rx: None,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            auth_manager,
        }
    }

    /// Create a new daemon server with a shutdown signal receiver
    ///
    /// The receiver will be checked periodically during the accept loop.
    /// When a signal is received, the server will gracefully shut down.
    pub fn new_with_shutdown(shutdown_rx: mpsc::Receiver<()>) -> Self {
        let socket_path = Self::default_socket_path();
        let config_dir = Self::default_config_dir();

        // Ensure config directory exists
        if let Err(e) = std::fs::create_dir_all(&config_dir) {
            eprintln!(
                "WARNING: Failed to create config directory {:?}: {}",
                config_dir, e
            );
        }

        // Initialize authentication - log warning if it fails but continue
        let auth_manager = match AuthManager::new() {
            Ok(auth) => {
                println!("Authentication token saved to {:?}", auth.token_path());
                Some(auth)
            }
            Err(e) => {
                eprintln!(
                    "WARNING: Failed to initialize authentication: {}. \
                     Daemon will run without authentication!",
                    e
                );
                None
            }
        };

        // Load existing wipe configs
        let wipe_managers = Self::load_wipe_configs(&config_dir);

        Self {
            volume_manager: Arc::new(Mutex::new(VolumeManager::new())),
            mounts: Arc::new(Mutex::new(HashMap::new())),
            wipe_managers: Arc::new(Mutex::new(wipe_managers)),
            config_dir,
            socket_path,
            active_connections: Arc::new(AtomicUsize::new(0)),
            shutdown_rx: Some(shutdown_rx),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            auth_manager,
        }
    }

    /// Returns a clone of the shutdown flag for external monitoring
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown_flag)
    }

    /// Get the default socket path for the platform
    #[cfg(unix)]
    fn default_socket_path() -> PathBuf {
        // Use XDG_RUNTIME_DIR if available (preferred - per-session, auto-cleaned)
        // Otherwise fall back to XDG_DATA_HOME or ~/.local/share/tesseract
        // Avoid /tmp to prevent symlink attacks and unauthorized access
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            let dir = PathBuf::from(runtime_dir).join("tesseract");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("daemon.sock")
        } else if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
            let dir = PathBuf::from(data_home).join("tesseract");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("daemon.sock")
        } else if let Ok(home) = std::env::var("HOME") {
            let dir = PathBuf::from(home).join(".local/share/tesseract");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("daemon.sock")
        } else {
            // Last resort - this should rarely happen on Unix systems
            PathBuf::from("/tmp/tesseract-daemon.sock")
        }
    }

    #[cfg(windows)]
    fn default_socket_path() -> PathBuf {
        // On Windows, we use a TCP socket on localhost
        // Port is configurable via TESSERACT_DAEMON_PORT environment variable
        let port = std::env::var("TESSERACT_DAEMON_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(37284);
        PathBuf::from(format!("127.0.0.1:{}", port))
    }

    /// Get the default config directory for storing wipe configs
    #[cfg(unix)]
    fn default_config_dir() -> PathBuf {
        // Use XDG_DATA_HOME or ~/.local/share/tesseract/wipe_configs
        if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
            PathBuf::from(data_home).join("tesseract/wipe_configs")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".local/share/tesseract/wipe_configs")
        } else {
            PathBuf::from("/var/lib/tesseract/wipe_configs")
        }
    }

    #[cfg(windows)]
    fn default_config_dir() -> PathBuf {
        // On Windows, use %LOCALAPPDATA%\Tesseract\wipe_configs
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            PathBuf::from(local_app_data).join("Tesseract\\wipe_configs")
        } else if let Ok(app_data) = std::env::var("APPDATA") {
            PathBuf::from(app_data).join("Tesseract\\wipe_configs")
        } else {
            PathBuf::from("C:\\ProgramData\\Tesseract\\wipe_configs")
        }
    }

    /// Load existing wipe configs from the config directory
    fn load_wipe_configs(config_dir: &Path) -> HashMap<PathBuf, RemoteWipeManager> {
        let mut managers = HashMap::new();

        if !config_dir.exists() {
            return managers;
        }

        // Read all .json files in the config directory
        if let Ok(entries) = std::fs::read_dir(config_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    match RemoteWipeManager::load(&path) {
                        Ok(manager) => {
                            // Extract container path from the config
                            let container_path = PathBuf::from(&manager.config().volume_id);
                            println!("Loaded wipe config for volume: {:?}", container_path);
                            managers.insert(container_path, manager);
                        }
                        Err(e) => {
                            eprintln!("WARNING: Failed to load wipe config {:?}: {}", path, e);
                        }
                    }
                }
            }
        }

        managers
    }

    /// Start the daemon server
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Spawn background monitoring thread for dead man's switch
        self.spawn_dead_man_monitor();

        #[cfg(unix)]
        {
            self.run_unix()
        }

        #[cfg(windows)]
        {
            self.run_windows()
        }
    }

    /// Spawns a background thread that periodically checks dead man's switch status
    ///
    /// This thread runs independently and:
    /// - Checks all registered wipe managers every DEAD_MAN_CHECK_INTERVAL_SECS
    /// - Logs warnings for volumes in Warning or GracePeriod status
    /// - Triggers key destruction for volumes in Expired status
    /// - Persists config changes after enforcement
    fn spawn_dead_man_monitor(&self) {
        let wipe_managers = Arc::clone(&self.wipe_managers);
        let config_dir = self.config_dir.clone();
        let shutdown_flag = Arc::clone(&self.shutdown_flag);

        std::thread::spawn(move || {
            println!("Dead man's switch monitor started");

            loop {
                // Check for shutdown
                if shutdown_flag.load(Ordering::Relaxed) {
                    println!("Dead man's switch monitor shutting down");
                    break;
                }

                // Sleep for the check interval (but check shutdown flag periodically)
                for _ in 0..(DEAD_MAN_CHECK_INTERVAL_SECS / 10) {
                    if shutdown_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(10));
                }

                if shutdown_flag.load(Ordering::Relaxed) {
                    break;
                }

                // Check all wipe managers
                Self::check_all_dead_mans_switches(&wipe_managers, &config_dir);
            }
        });
    }

    /// Check all dead man's switches and enforce expired ones
    fn check_all_dead_mans_switches(
        wipe_managers: &Arc<Mutex<HashMap<PathBuf, RemoteWipeManager>>>,
        config_dir: &Path,
    ) {
        let mut managers = wipe_managers.lock().unwrap();

        for (path, manager) in managers.iter_mut() {
            if !manager.is_dead_mans_switch_enabled() {
                continue;
            }

            match manager.check_and_enforce_dead_mans_switch() {
                Ok((status, wiped_count)) => {
                    match status {
                        DeadMansSwitchStatus::Warning {
                            seconds_remaining, ..
                        } => {
                            let days = seconds_remaining / 86400;
                            let hours = (seconds_remaining % 86400) / 3600;
                            eprintln!(
                                "WARNING: Dead man's switch for {:?} expires in {}d {}h. \
                                 Please check in to prevent key destruction.",
                                path, days, hours
                            );
                        }
                        DeadMansSwitchStatus::GracePeriod {
                            seconds_remaining, ..
                        } => {
                            let hours = seconds_remaining / 3600;
                            let minutes = (seconds_remaining % 3600) / 60;
                            eprintln!(
                                "CRITICAL: Dead man's switch for {:?} is in GRACE PERIOD! \
                                 Keys will be destroyed in {}h {}m. CHECK IN IMMEDIATELY!",
                                path, hours, minutes
                            );
                        }
                        DeadMansSwitchStatus::Expired { .. } => {
                            eprintln!(
                                "ALERT: Dead man's switch EXPIRED for {:?}. \
                                 Destroyed {} keyfiles.",
                                path, wiped_count
                            );
                        }
                        _ => {}
                    }

                    // Persist config after potential state changes
                    let config_path = Self::generate_config_path(config_dir, path);
                    if let Err(e) = manager.save(&config_path) {
                        eprintln!("WARNING: Failed to save config for {:?}: {}", path, e);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "ERROR: Failed to check dead man's switch for {:?}: {}",
                        path, e
                    );
                }
            }
        }
    }

    #[cfg(unix)]
    fn run_unix(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Remove existing socket file if it exists
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        println!("Daemon listening on {:?}", self.socket_path);

        // Set up signal handlers for graceful shutdown
        Self::setup_signal_handlers();

        // Set non-blocking mode for graceful shutdown support
        listener.set_nonblocking(true)?;

        // Get the expected token (if authentication is enabled)
        let expected_token: Option<String> =
            self.auth_manager.as_ref().map(|a| a.token().to_string());

        loop {
            // Check for shutdown signal
            if self.check_shutdown() {
                println!("Received shutdown signal, cleaning up...");
                self.cleanup_on_shutdown();
                break;
            }

            match listener.accept() {
                Ok((stream, _)) => {
                    // Check connection limit to prevent thread exhaustion DoS
                    let current = self.active_connections.load(Ordering::Relaxed);
                    if current >= MAX_CONCURRENT_CONNECTIONS {
                        eprintln!(
                            "Connection limit reached ({}/{}), rejecting connection",
                            current, MAX_CONCURRENT_CONNECTIONS
                        );
                        // Drop the stream to close the connection
                        drop(stream);
                        continue;
                    }

                    // Increment connection counter
                    self.active_connections.fetch_add(1, Ordering::Relaxed);

                    let mounts = Arc::clone(&self.mounts);
                    let volume_manager = Arc::clone(&self.volume_manager);
                    let wipe_managers = Arc::clone(&self.wipe_managers);
                    let config_dir = self.config_dir.clone();
                    let token = expected_token.clone();
                    let conn_counter = Arc::clone(&self.active_connections);

                    // Handle connection in a new thread
                    std::thread::spawn(move || {
                        let result = Self::handle_client(
                            stream,
                            mounts,
                            volume_manager,
                            wipe_managers,
                            config_dir,
                            token,
                        );
                        // Always decrement counter when done
                        conn_counter.fetch_sub(1, Ordering::Relaxed);
                        if let Err(e) = result {
                            eprintln!("Error handling client: {}", e);
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection available, sleep briefly and check shutdown
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    eprintln!("Connection error: {}", e);
                }
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn run_windows(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = self.socket_path.to_string_lossy();
        let listener = TcpListener::bind(addr.as_ref())?;
        println!("Daemon listening on {}", addr);

        // Set up Ctrl+C handler for graceful shutdown
        Self::setup_signal_handlers();

        // Set non-blocking mode for graceful shutdown support
        listener.set_nonblocking(true)?;

        // Get the expected token (if authentication is enabled)
        let expected_token: Option<String> =
            self.auth_manager.as_ref().map(|a| a.token().to_string());

        loop {
            // Check for shutdown signal
            if self.check_shutdown() {
                println!("Received shutdown signal, cleaning up...");
                self.cleanup_on_shutdown();
                break;
            }

            match listener.accept() {
                Ok((stream, _)) => {
                    // Check connection limit to prevent thread exhaustion DoS
                    let current = self.active_connections.load(Ordering::Relaxed);
                    if current >= MAX_CONCURRENT_CONNECTIONS {
                        eprintln!(
                            "Connection limit reached ({}/{}), rejecting connection",
                            current, MAX_CONCURRENT_CONNECTIONS
                        );
                        // Drop the stream to close the connection
                        drop(stream);
                        continue;
                    }

                    // Increment connection counter
                    self.active_connections.fetch_add(1, Ordering::Relaxed);

                    let mounts = Arc::clone(&self.mounts);
                    let volume_manager = Arc::clone(&self.volume_manager);
                    let wipe_managers = Arc::clone(&self.wipe_managers);
                    let config_dir = self.config_dir.clone();
                    let token = expected_token.clone();
                    let conn_counter = Arc::clone(&self.active_connections);

                    // Handle connection in a new thread
                    std::thread::spawn(move || {
                        let result = Self::handle_client(
                            stream,
                            mounts,
                            volume_manager,
                            wipe_managers,
                            config_dir,
                            token,
                        );
                        // Always decrement counter when done
                        conn_counter.fetch_sub(1, Ordering::Relaxed);
                        if let Err(e) = result {
                            eprintln!("Error handling client: {}", e);
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection available, sleep briefly and check shutdown
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    eprintln!("Connection error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Checks if a shutdown signal has been received
    fn check_shutdown(&self) -> bool {
        // Check the atomic shutdown flag first (for external signals)
        if self.shutdown_flag.load(Ordering::Relaxed) {
            return true;
        }

        // Check the mpsc channel (for service integration)
        if let Some(ref rx) = self.shutdown_rx {
            match rx.try_recv() {
                Ok(()) => {
                    self.shutdown_flag.store(true, Ordering::Relaxed);
                    return true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    // Sender dropped, treat as shutdown
                    self.shutdown_flag.store(true, Ordering::Relaxed);
                    return true;
                }
            }
        }

        false
    }

    /// Cleans up all mounted volumes on shutdown
    fn cleanup_on_shutdown(&self) {
        let mut mgr = self.volume_manager.lock().unwrap();
        let container_paths: Vec<PathBuf> = {
            let mounts_guard = self.mounts.lock().unwrap();
            mounts_guard.keys().cloned().collect()
        };

        for container_path in container_paths {
            if let Err(e) = mgr.unmount(&container_path) {
                eprintln!("Failed to unmount {:?}: {}", container_path, e);
            } else {
                println!("Unmounted {:?}", container_path);
            }
            self.mounts.lock().unwrap().remove(&container_path);
        }
    }

    /// Signals the server to shut down gracefully
    pub fn signal_shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
    }

    /// Handle a client connection
    #[cfg(unix)]
    fn handle_client(
        mut stream: UnixStream,
        mounts: Arc<Mutex<HashMap<PathBuf, MountInfo>>>,
        volume_manager: Arc<Mutex<VolumeManager>>,
        wipe_managers: Arc<Mutex<HashMap<PathBuf, RemoteWipeManager>>>,
        config_dir: PathBuf,
        expected_token: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Self::handle_client_impl(
            &mut stream,
            mounts,
            volume_manager,
            wipe_managers,
            config_dir,
            expected_token,
        )
    }

    #[cfg(windows)]
    fn handle_client(
        mut stream: TcpStream,
        mounts: Arc<Mutex<HashMap<PathBuf, MountInfo>>>,
        volume_manager: Arc<Mutex<VolumeManager>>,
        wipe_managers: Arc<Mutex<HashMap<PathBuf, RemoteWipeManager>>>,
        config_dir: PathBuf,
        expected_token: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Self::handle_client_impl(
            &mut stream,
            mounts,
            volume_manager,
            wipe_managers,
            config_dir,
            expected_token,
        )
    }

    /// Maximum allowed message size (16 MB) to prevent DoS via memory exhaustion
    const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

    /// Implementation of client handling (generic over stream type)
    fn handle_client_impl<S: Read + Write>(
        stream: &mut S,
        mounts: Arc<Mutex<HashMap<PathBuf, MountInfo>>>,
        volume_manager: Arc<Mutex<VolumeManager>>,
        wipe_managers: Arc<Mutex<HashMap<PathBuf, RemoteWipeManager>>>,
        config_dir: PathBuf,
        expected_token: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Read request (prefixed with 4-byte length)
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes)?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Prevent DoS via unbounded memory allocation
        if len > Self::MAX_MESSAGE_SIZE {
            return Err(format!(
                "Message size {} exceeds maximum allowed size {}",
                len,
                Self::MAX_MESSAGE_SIZE
            )
            .into());
        }

        let mut buffer = vec![0u8; len];
        stream.read_exact(&mut buffer)?;

        // Parse and authenticate request
        let response = match AuthenticatedRequest::from_bytes(&buffer) {
            Ok(request) => {
                // Validate authentication token if authentication is enabled
                if let Some(ref expected) = expected_token {
                    if !Self::validate_token(expected, &request.auth_token) {
                        DaemonResponse::unauthorized("Invalid authentication token")
                    } else {
                        // Token valid, process the command
                        // Clone command since AuthenticatedRequest implements ZeroizeOnDrop
                        Self::process_command(
                            request.command.clone(),
                            mounts,
                            volume_manager,
                            wipe_managers,
                            config_dir,
                        )
                    }
                } else {
                    // Authentication not enabled (should not happen in production)
                    eprintln!("WARNING: Processing command without authentication");
                    Self::process_command(
                        request.command.clone(),
                        mounts,
                        volume_manager,
                        wipe_managers,
                        config_dir,
                    )
                }
                // request is dropped here, zeroizing the auth_token
            }
            Err(_) => {
                // Try parsing as legacy unauthenticated command for backward compatibility
                // but only allow Ping and VerifyServer commands without auth
                match DaemonCommand::from_bytes(&buffer) {
                    Ok(DaemonCommand::Ping) => DaemonResponse::Pong,
                    Ok(DaemonCommand::VerifyServer { challenge }) => {
                        // Handle VerifyServer - server proves it knows the token
                        Self::handle_verify_server(&challenge, expected_token.as_deref())
                    }
                    Ok(_) => DaemonResponse::unauthorized(
                        "Authentication required. Please use AuthenticatedRequest.",
                    ),
                    Err(e) => DaemonResponse::error(format!("Invalid request format: {}", e)),
                }
            }
        };

        // Send response (prefixed with 4-byte length)
        let response_bytes = response.to_bytes()?;
        let len_bytes = (response_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes)?;
        stream.write_all(&response_bytes)?;
        stream.flush()?;

        Ok(())
    }

    /// Validate authentication token using constant-time comparison
    fn validate_token(expected: &str, provided: &str) -> bool {
        use subtle::ConstantTimeEq;

        let expected_bytes = expected.as_bytes();
        let provided_bytes = provided.as_bytes();

        // Length check is okay to leak
        if expected_bytes.len() != provided_bytes.len() {
            return false;
        }

        // Constant-time comparison
        expected_bytes.ct_eq(provided_bytes).into()
    }

    /// Handle VerifyServer command - server proves it knows the auth token
    ///
    /// The server computes a keyed BLAKE3 hash of the challenge using the auth token
    /// as the key. This proves to the client that the server is legitimate without
    /// requiring the client to send sensitive data first.
    ///
    /// # Security
    ///
    /// This implements server identity verification to prevent man-in-the-middle
    /// attacks where a malicious process impersonates the daemon.
    fn handle_verify_server(challenge: &str, token: Option<&str>) -> DaemonResponse {
        use super::protocol::{CHALLENGE_NONCE_LENGTH, SERVER_IDENTITY_LENGTH};
        use blake3::Hasher;

        // Validate challenge format (should be hex-encoded 32 bytes)
        let challenge_bytes = match hex::decode(challenge) {
            Ok(bytes) if bytes.len() == CHALLENGE_NONCE_LENGTH => bytes,
            Ok(bytes) => {
                return DaemonResponse::error(format!(
                    "Invalid challenge length: expected {} bytes, got {}",
                    CHALLENGE_NONCE_LENGTH,
                    bytes.len()
                ));
            }
            Err(e) => {
                return DaemonResponse::error(format!("Invalid challenge format: {}", e));
            }
        };

        // Get the token
        let token = match token {
            Some(t) => t,
            None => {
                return DaemonResponse::error(
                    "Server identity verification unavailable: authentication not configured",
                );
            }
        };

        // Decode the token from hex
        let token_bytes: [u8; 32] = match hex::decode(token) {
            Ok(bytes) if bytes.len() == SERVER_IDENTITY_LENGTH => {
                bytes.try_into().unwrap_or([0u8; 32])
            }
            _ => {
                return DaemonResponse::error("Internal error: invalid token format");
            }
        };

        // Compute keyed BLAKE3 hash: BLAKE3(token, challenge || domain_separator)
        let mut hasher = Hasher::new_keyed(&token_bytes);
        hasher.update(&challenge_bytes);
        hasher.update(b"tesseract-server-identity-v1");
        let response_bytes = hasher.finalize();

        DaemonResponse::ServerIdentity {
            response: hex::encode(response_bytes.as_bytes()),
        }
    }

    /// Process a daemon command
    fn process_command(
        command: DaemonCommand,
        mounts: Arc<Mutex<HashMap<PathBuf, MountInfo>>>,
        volume_manager: Arc<Mutex<VolumeManager>>,
        wipe_managers: Arc<Mutex<HashMap<PathBuf, RemoteWipeManager>>>,
        config_dir: PathBuf,
    ) -> DaemonResponse {
        match command {
            DaemonCommand::Mount {
                container_path,
                mount_point,
                mut password,
                read_only,
                hidden_offset,
                mut hidden_password,
            } => {
                // Check if already mounted
                {
                    let mounts_guard = mounts.lock().unwrap();
                    if mounts_guard.contains_key(&container_path) {
                        // Zeroize passwords before returning
                        password.zeroize();
                        if let Some(ref mut hp) = hidden_password {
                            hp.zeroize();
                        }
                        return DaemonResponse::error("Volume is already mounted");
                    }
                }

                // Mount the volume
                let mut mgr = volume_manager.lock().unwrap();

                // Clone hidden_password for MountOptions, we'll zeroize our copy
                let options = MountOptions {
                    mount_point: mount_point.clone(),
                    read_only,
                    allow_other: false,
                    auto_unmount: true,
                    fs_name: Some("SecureCryptor".to_string()),
                    hidden_offset,
                    hidden_password: hidden_password.clone(),
                };

                let result = mgr.mount(&container_path, &password, options);

                // Zeroize passwords immediately after use
                password.zeroize();
                if let Some(ref mut hp) = hidden_password {
                    hp.zeroize();
                }

                match result {
                    Ok(_) => {
                        // Track the mount
                        let info = MountInfo {
                            container_path: container_path.clone(),
                            mount_point,
                            read_only,
                            is_hidden: hidden_offset.is_some(),
                            mounted_at: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            pid: Some(std::process::id()),
                        };

                        mounts.lock().unwrap().insert(container_path, info.clone());

                        DaemonResponse::Mounted { info }
                    }
                    Err(e) => DaemonResponse::error(format!("Mount failed: {}", e)),
                }
            }

            DaemonCommand::Unmount { container_path } => {
                let mut mgr = volume_manager.lock().unwrap();

                match mgr.unmount(&container_path) {
                    Ok(_) => {
                        mounts.lock().unwrap().remove(&container_path);
                        DaemonResponse::Unmounted { container_path }
                    }
                    Err(e) => DaemonResponse::error(format!("Unmount failed: {}", e)),
                }
            }

            DaemonCommand::UnmountByMountPoint { mount_point } => {
                // Find container by mount point
                let container_path = {
                    let mounts_guard = mounts.lock().unwrap();
                    mounts_guard
                        .iter()
                        .find(|(_, info)| info.mount_point == mount_point)
                        .map(|(path, _)| path.clone())
                };

                if let Some(container_path) = container_path {
                    let mut mgr = volume_manager.lock().unwrap();

                    match mgr.unmount(&container_path) {
                        Ok(_) => {
                            mounts.lock().unwrap().remove(&container_path);
                            DaemonResponse::Unmounted { container_path }
                        }
                        Err(e) => DaemonResponse::error(format!("Unmount failed: {}", e)),
                    }
                } else {
                    DaemonResponse::error("No volume mounted at that mount point")
                }
            }

            DaemonCommand::List => {
                let mounts_guard = mounts.lock().unwrap();
                let mount_list: Vec<MountInfo> = mounts_guard.values().cloned().collect();

                DaemonResponse::MountList { mounts: mount_list }
            }

            DaemonCommand::GetInfo { container_path } => {
                let mounts_guard = mounts.lock().unwrap();

                if let Some(info) = mounts_guard.get(&container_path) {
                    DaemonResponse::MountInfo { info: info.clone() }
                } else {
                    DaemonResponse::error("Volume is not mounted")
                }
            }

            DaemonCommand::UnmountAll => {
                let mut mgr = volume_manager.lock().unwrap();
                let container_paths: Vec<PathBuf> = {
                    let mounts_guard = mounts.lock().unwrap();
                    mounts_guard.keys().cloned().collect()
                };

                for container_path in container_paths {
                    let _ = mgr.unmount(&container_path);
                    mounts.lock().unwrap().remove(&container_path);
                }

                DaemonResponse::Success
            }

            DaemonCommand::Ping => DaemonResponse::Pong,

            DaemonCommand::VerifyServer { .. } => {
                // This should be handled in handle_client_impl, not here
                // If we get here, it means it was wrapped in AuthenticatedRequest
                // which is unusual but not an error
                DaemonResponse::error("VerifyServer should be sent without authentication wrapper")
            }

            DaemonCommand::Shutdown => {
                // Unmount all volumes
                let mut mgr = volume_manager.lock().unwrap();
                let container_paths: Vec<PathBuf> = {
                    let mounts_guard = mounts.lock().unwrap();
                    mounts_guard.keys().cloned().collect()
                };

                for container_path in container_paths {
                    let _ = mgr.unmount(&container_path);
                }

                // Exit the process
                std::process::exit(0);
            }

            // Dead Man's Switch commands
            DaemonCommand::DeadManEnable {
                container_path,
                timeout_days,
                warning_days,
                grace_period_days,
            } => Self::handle_dead_man_enable(
                container_path,
                timeout_days,
                warning_days,
                grace_period_days,
                wipe_managers,
                config_dir,
            ),

            DaemonCommand::DeadManDisable { container_path } => {
                Self::handle_dead_man_disable(container_path, wipe_managers, config_dir)
            }

            DaemonCommand::DeadManCheckin { container_path } => {
                Self::handle_dead_man_checkin(container_path, wipe_managers, config_dir)
            }

            DaemonCommand::DeadManStatus { container_path } => {
                Self::handle_dead_man_status(container_path, wipe_managers)
            }
        }
    }

    /// Handle DeadManEnable command
    fn handle_dead_man_enable(
        container_path: PathBuf,
        timeout_days: u32,
        warning_days: Option<u32>,
        grace_period_days: Option<u32>,
        wipe_managers: Arc<Mutex<HashMap<PathBuf, RemoteWipeManager>>>,
        config_dir: PathBuf,
    ) -> DaemonResponse {
        let mut managers = wipe_managers.lock().unwrap();

        // Check if we already have a manager for this volume
        if let Some(manager) = managers.get_mut(&container_path) {
            // Update existing configuration
            manager.enable_dead_mans_switch(timeout_days);
            if let Some(days) = warning_days {
                manager.set_warning_days(days);
            }
            if let Some(days) = grace_period_days {
                manager.set_grace_period_days(days);
            }

            // Persist the config
            let config_path = Self::generate_config_path(&config_dir, &container_path);
            if let Err(e) = manager.save(&config_path) {
                return DaemonResponse::error(format!("Failed to save config: {}", e));
            }

            let status_info = Self::manager_to_status_info(&container_path, manager);
            DaemonResponse::DeadManConfigured {
                container_path,
                enabled: true,
                config: Some(status_info),
            }
        } else {
            // Create a new manager for this volume
            let volume_id = container_path.to_string_lossy().to_string();
            let (mut manager, _token) = RemoteWipeManager::new(&volume_id);

            // Configure the dead man's switch
            manager.enable_dead_mans_switch(timeout_days);
            if let Some(days) = warning_days {
                manager.set_warning_days(days);
            }
            if let Some(days) = grace_period_days {
                manager.set_grace_period_days(days);
            }

            // Add keyfile paths (container path and potential key files)
            manager.add_keyfile_path(&container_path.to_string_lossy());

            // Persist the config
            let config_path = Self::generate_config_path(&config_dir, &container_path);
            if let Err(e) = manager.save(&config_path) {
                return DaemonResponse::error(format!("Failed to save config: {}", e));
            }

            let status_info = Self::manager_to_status_info(&container_path, &mut manager);
            managers.insert(container_path.clone(), manager);

            DaemonResponse::DeadManConfigured {
                container_path,
                enabled: true,
                config: Some(status_info),
            }
        }
    }

    /// Handle DeadManDisable command
    fn handle_dead_man_disable(
        container_path: PathBuf,
        wipe_managers: Arc<Mutex<HashMap<PathBuf, RemoteWipeManager>>>,
        config_dir: PathBuf,
    ) -> DaemonResponse {
        let mut managers = wipe_managers.lock().unwrap();

        if let Some(manager) = managers.get_mut(&container_path) {
            manager.disable_dead_mans_switch();

            // Persist the config
            let config_path = Self::generate_config_path(&config_dir, &container_path);
            if let Err(e) = manager.save(&config_path) {
                return DaemonResponse::error(format!("Failed to save config: {}", e));
            }

            DaemonResponse::DeadManConfigured {
                container_path,
                enabled: false,
                config: None,
            }
        } else {
            DaemonResponse::error(format!(
                "No dead man's switch configured for {:?}",
                container_path
            ))
        }
    }

    /// Handle DeadManCheckin command
    fn handle_dead_man_checkin(
        container_path: Option<PathBuf>,
        wipe_managers: Arc<Mutex<HashMap<PathBuf, RemoteWipeManager>>>,
        config_dir: PathBuf,
    ) -> DaemonResponse {
        let mut managers = wipe_managers.lock().unwrap();
        let mut checked_in = 0;
        let mut new_deadlines = Vec::new();

        if let Some(path) = container_path {
            // Check in for a specific volume
            if let Some(manager) = managers.get_mut(&path) {
                if manager.is_dead_mans_switch_enabled() {
                    manager.checkin();
                    checked_in = 1;
                    let deadline = manager.dead_mans_switch_config().deadline();
                    new_deadlines.push((path.clone(), deadline));

                    // Persist the config
                    let config_path = Self::generate_config_path(&config_dir, &path);
                    if let Err(e) = manager.save(&config_path) {
                        eprintln!("WARNING: Failed to save config after checkin: {}", e);
                    }
                }
            } else {
                return DaemonResponse::error(format!(
                    "No dead man's switch configured for {:?}",
                    path
                ));
            }
        } else {
            // Check in for all volumes
            for (path, manager) in managers.iter_mut() {
                if manager.is_dead_mans_switch_enabled() {
                    manager.checkin();
                    checked_in += 1;
                    let deadline = manager.dead_mans_switch_config().deadline();
                    new_deadlines.push((path.clone(), deadline));

                    // Persist the config
                    let config_path = Self::generate_config_path(&config_dir, path);
                    if let Err(e) = manager.save(&config_path) {
                        eprintln!("WARNING: Failed to save config after checkin: {}", e);
                    }
                }
            }
        }

        DaemonResponse::DeadManCheckedIn {
            volumes_checked_in: checked_in,
            new_deadlines,
        }
    }

    /// Handle DeadManStatus command
    fn handle_dead_man_status(
        container_path: Option<PathBuf>,
        wipe_managers: Arc<Mutex<HashMap<PathBuf, RemoteWipeManager>>>,
    ) -> DaemonResponse {
        let mut managers = wipe_managers.lock().unwrap();
        let mut statuses = Vec::new();

        if let Some(path) = container_path {
            // Get status for a specific volume
            if let Some(manager) = managers.get_mut(&path) {
                statuses.push(Self::manager_to_status_info(&path, manager));
            } else {
                return DaemonResponse::error(format!(
                    "No dead man's switch configured for {:?}",
                    path
                ));
            }
        } else {
            // Get status for all volumes
            for (path, manager) in managers.iter_mut() {
                statuses.push(Self::manager_to_status_info(path, manager));
            }
        }

        DaemonResponse::DeadManStatus { statuses }
    }

    /// Convert a RemoteWipeManager to DeadManStatusInfo
    fn manager_to_status_info(
        container_path: &Path,
        manager: &mut RemoteWipeManager,
    ) -> DeadManStatusInfo {
        // Get status first (this mutably borrows manager temporarily)
        let status = manager.check_dead_mans_switch();

        let status_type = match status {
            DeadMansSwitchStatus::Disabled => DeadManStatusType::Disabled,
            DeadMansSwitchStatus::Ok { .. } => DeadManStatusType::Ok,
            DeadMansSwitchStatus::Warning { .. } => DeadManStatusType::Warning,
            DeadMansSwitchStatus::GracePeriod { .. } => DeadManStatusType::GracePeriod,
            DeadMansSwitchStatus::Expired { .. } => DeadManStatusType::Expired,
        };

        // Now get config (immutable borrow)
        let config = manager.dead_mans_switch_config();

        DeadManStatusInfo {
            container_path: container_path.to_path_buf(),
            enabled: config.enabled,
            status: status_type,
            last_checkin: config.last_checkin,
            deadline: config.deadline(),
            seconds_remaining: config.seconds_until_deadline(),
            timeout_days: config.timeout_days,
            warning_days: config.warning_days,
            grace_period_days: config.grace_period_days,
        }
    }

    /// Generate a config file path for a container (helper for command handlers)
    fn generate_config_path(config_dir: &Path, container_path: &Path) -> PathBuf {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        container_path.hash(&mut hasher);
        let hash = hasher.finish();

        config_dir.join(format!("wipe_{:016x}.json", hash))
    }

    /// Set up signal handlers for graceful shutdown
    #[cfg(feature = "ctrlc")]
    fn setup_signal_handlers() {
        // Use ctrlc crate for cross-platform Ctrl+C handling
        ctrlc::set_handler(move || {
            println!("Received shutdown signal, cleaning up...");
            std::process::exit(0);
        })
        .expect("Error setting Ctrl-C handler");
    }

    /// Fallback when ctrlc feature is not available
    #[cfg(not(feature = "ctrlc"))]
    fn setup_signal_handlers() {
        // Signal handling not available without ctrlc feature
    }
}

impl Default for DaemonServer {
    fn default() -> Self {
        Self::new()
    }
}
