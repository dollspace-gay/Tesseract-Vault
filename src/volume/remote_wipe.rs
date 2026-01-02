// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Remote wipe functionality for cloud-synced volumes
//!
//! Provides cloud-triggered destruction of encryption keys across all devices.
//! When a wipe command is received and authenticated, all local keyfiles and
//! key material are securely destroyed.
//!
//! # Security Model
//!
//! - Wipe tokens are generated using CSPRNG and stored as salted Blake3 hashes
//! - Commands require HMAC authentication with the original token
//! - Replay protection via timestamps and nonces
//! - Rate limiting prevents brute force attempts
//! - Optional confirmation requirement for additional safety
//!
//! # Usage
//!
//! ```ignore
//! // Setup remote wipe on device
//! let mut wipe_manager = RemoteWipeManager::new(volume_id);
//! let token = wipe_manager.generate_wipe_token()?;
//! // Store token securely - this is the only way to trigger wipe
//!
//! // On another device or service, create wipe command
//! let command = WipeCommand::new(&token, volume_id);
//!
//! // When command is received via cloud sync
//! if wipe_manager.verify_and_execute(&command)? {
//!     // Keys have been destroyed
//! }
//! ```

use blake3::Hasher;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CryptorError, Result};

/// Size of the wipe token in bytes (256 bits)
pub const WIPE_TOKEN_SIZE: usize = 32;

/// Size of the token salt in bytes
pub const TOKEN_SALT_SIZE: usize = 16;

/// Size of the command nonce in bytes
pub const COMMAND_NONCE_SIZE: usize = 16;

/// Maximum age of a wipe command in seconds (prevent replay after 5 minutes)
pub const MAX_COMMAND_AGE_SECS: u64 = 300;

/// Rate limit: minimum seconds between wipe attempts
pub const RATE_LIMIT_SECS: u64 = 5;

/// Maximum failed attempts before lockout
pub const MAX_FAILED_ATTEMPTS: u32 = 5;

/// Lockout duration after max failed attempts (1 hour)
pub const LOCKOUT_DURATION_SECS: u64 = 3600;

/// Type of remote command
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WipeCommandType {
    /// Immediately destroy all keys (irreversible)
    DestroyKeys,
    /// Lock volume (keys preserved but inaccessible until unlock)
    Lock,
    /// Request device check-in (for dead man's switch)
    CheckIn,
    /// Revoke wipe capability (requires token regeneration)
    RevokeToken,
}

/// A wipe token that can trigger remote destruction
///
/// This token is generated once and must be stored securely by the user.
/// It is the only way to authenticate a wipe command.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct WipeToken {
    /// The raw token bytes (secret)
    token: [u8; WIPE_TOKEN_SIZE],
}

impl WipeToken {
    /// Generates a new cryptographically secure wipe token
    pub fn generate() -> Self {
        let mut token = [0u8; WIPE_TOKEN_SIZE];
        rand::rng().fill_bytes(&mut token);
        Self { token }
    }

    /// Creates a WipeToken from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != WIPE_TOKEN_SIZE {
            return Err(CryptorError::InvalidInput(format!(
                "Invalid wipe token size: expected {}, got {}",
                WIPE_TOKEN_SIZE,
                bytes.len()
            )));
        }
        let mut token = [0u8; WIPE_TOKEN_SIZE];
        token.copy_from_slice(bytes);
        Ok(Self { token })
    }

    /// Returns the token as a hex string for storage
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.token))
    }

    /// Creates a WipeToken from a hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| CryptorError::InvalidInput(format!("Invalid hex token: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    /// Computes the verification hash for storage (token is never stored directly)
    pub fn compute_verification_hash(&self, salt: &[u8; TOKEN_SALT_SIZE]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(salt);
        hasher.update(&self.token);
        hasher.update(b"tesseract-wipe-verification");
        *hasher.finalize().as_bytes()
    }

    /// Signs a wipe command with this token
    pub fn sign_command(&self, command: &WipeCommandData) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.token);
        hasher.update(command.volume_id.as_bytes());
        hasher.update(&command.timestamp.to_le_bytes());
        hasher.update(&command.nonce);
        hasher.update(&[command.command_type as u8]);
        hasher.update(b"tesseract-wipe-command");
        *hasher.finalize().as_bytes()
    }
}

/// Data portion of a wipe command (without signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeCommandData {
    /// Volume ID this command targets
    pub volume_id: String,
    /// Unix timestamp when command was created
    pub timestamp: u64,
    /// Random nonce for replay protection
    pub nonce: [u8; COMMAND_NONCE_SIZE],
    /// Type of command
    pub command_type: WipeCommandType,
    /// Optional message (e.g., reason for wipe)
    pub message: Option<String>,
}

/// A signed wipe command ready for transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeCommand {
    /// The command data
    pub data: WipeCommandData,
    /// HMAC signature using the wipe token
    pub signature: [u8; 32],
}

impl WipeCommand {
    /// Creates a new signed wipe command
    pub fn new(token: &WipeToken, volume_id: &str, command_type: WipeCommandType) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut nonce = [0u8; COMMAND_NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce);

        let data = WipeCommandData {
            volume_id: volume_id.to_string(),
            timestamp: now,
            nonce,
            command_type,
            message: None,
        };

        let signature = token.sign_command(&data);

        Self { data, signature }
    }

    /// Creates a wipe command with a message
    pub fn with_message(
        token: &WipeToken,
        volume_id: &str,
        command_type: WipeCommandType,
        message: &str,
    ) -> Self {
        let mut cmd = Self::new(token, volume_id, command_type);
        cmd.data.message = Some(message.to_string());
        // Re-sign after adding message
        cmd.signature = token.sign_command(&cmd.data);
        cmd
    }

    /// Verifies the command signature
    pub fn verify(&self, token: &WipeToken) -> bool {
        let expected = token.sign_command(&self.data);
        // Constant-time comparison
        subtle::ConstantTimeEq::ct_eq(&self.signature[..], &expected[..]).into()
    }

    /// Checks if the command is within the valid time window
    pub fn is_fresh(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Command must not be in the future (with 30s tolerance for clock skew)
        if self.data.timestamp > now + 30 {
            return false;
        }

        // Command must not be too old
        now.saturating_sub(self.data.timestamp) <= MAX_COMMAND_AGE_SECS
    }

    /// Serializes command to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| CryptorError::Cryptography(format!("Failed to serialize command: {}", e)))
    }

    /// Deserializes command from JSON bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| {
            CryptorError::Cryptography(format!("Failed to deserialize command: {}", e))
        })
    }
}

/// Stored verification data for a wipe token (token itself is never stored)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWipeConfig {
    /// Salt used for token verification hash
    pub token_salt: [u8; TOKEN_SALT_SIZE],
    /// Blake3 hash of (salt || token || domain-separator)
    pub token_hash: [u8; 32],
    /// Volume ID this config belongs to
    pub volume_id: String,
    /// Whether wipe capability is enabled
    pub enabled: bool,
    /// Whether confirmation is required before wipe
    pub require_confirmation: bool,
    /// Paths to keyfiles that should be destroyed on wipe
    pub keyfile_paths: Vec<String>,
    /// Failed attempt counter
    pub failed_attempts: u32,
    /// Timestamp of last attempt (for rate limiting)
    pub last_attempt: u64,
    /// Lockout end timestamp (0 if not locked out)
    pub lockout_until: u64,
    /// Used nonces with timestamps (for replay protection)
    /// Each entry is (timestamp_seconds, nonce) - nonces older than MAX_COMMAND_AGE_SECS are pruned
    pub used_nonces: Vec<(u64, [u8; COMMAND_NONCE_SIZE])>,
    /// When the config was created
    pub created_at: u64,
}

impl StoredWipeConfig {
    /// Creates a new stored config from a wipe token
    pub fn new(token: &WipeToken, volume_id: &str) -> Self {
        let mut token_salt = [0u8; TOKEN_SALT_SIZE];
        rand::rng().fill_bytes(&mut token_salt);

        let token_hash = token.compute_verification_hash(&token_salt);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            token_salt,
            token_hash,
            volume_id: volume_id.to_string(),
            enabled: true,
            require_confirmation: true,
            keyfile_paths: Vec::new(),
            failed_attempts: 0,
            last_attempt: 0,
            lockout_until: 0,
            used_nonces: Vec::new(),
            created_at: now,
        }
    }

    /// Verifies that a token matches the stored hash
    pub fn verify_token(&self, token: &WipeToken) -> bool {
        let computed = token.compute_verification_hash(&self.token_salt);
        subtle::ConstantTimeEq::ct_eq(&computed[..], &self.token_hash[..]).into()
    }

    /// Checks if currently locked out
    pub fn is_locked_out(&self) -> bool {
        if self.lockout_until == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now < self.lockout_until
    }

    /// Checks if rate limited
    pub fn is_rate_limited(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.last_attempt) < RATE_LIMIT_SECS
    }

    /// Records a failed attempt
    pub fn record_failure(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.failed_attempts += 1;
        self.last_attempt = now;

        if self.failed_attempts >= MAX_FAILED_ATTEMPTS {
            self.lockout_until = now + LOCKOUT_DURATION_SECS;
        }
    }

    /// Records a successful verification (resets failure counter)
    pub fn record_success(&mut self) {
        self.failed_attempts = 0;
        self.lockout_until = 0;
        self.last_attempt = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Checks if a nonce has been used (replay protection)
    ///
    /// Only checks nonces within the valid time window (MAX_COMMAND_AGE_SECS).
    /// Expired nonces are not checked since commands with those timestamps would
    /// fail the freshness check anyway.
    pub fn is_nonce_used(&self, nonce: &[u8; COMMAND_NONCE_SIZE]) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(MAX_COMMAND_AGE_SECS);

        self.used_nonces
            .iter()
            .filter(|(ts, _)| *ts >= cutoff) // Only check non-expired nonces
            .any(|(_, n)| n == nonce)
    }

    /// Records a used nonce with current timestamp
    ///
    /// Automatically prunes nonces older than the command validity window.
    /// This eliminates the fixed 1000-nonce limit - storage is naturally bounded
    /// by the time window (typically only a handful of commands per 5 minutes).
    pub fn record_nonce(&mut self, nonce: [u8; COMMAND_NONCE_SIZE]) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Prune expired nonces (older than validity window)
        let cutoff = now.saturating_sub(MAX_COMMAND_AGE_SECS);
        self.used_nonces.retain(|(ts, _)| *ts >= cutoff);

        // Add the new nonce with timestamp
        self.used_nonces.push((now, nonce));
    }

    /// Serializes config to JSON
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| CryptorError::Cryptography(format!("Failed to serialize config: {}", e)))
    }

    /// Deserializes config from JSON
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| CryptorError::Cryptography(format!("Failed to deserialize config: {}", e)))
    }
}

/// Result of wipe command execution
#[derive(Debug, Clone)]
pub enum WipeResult {
    /// Keys successfully destroyed
    Destroyed {
        keyfiles_wiped: usize,
        timestamp: u64,
    },
    /// Volume locked (keys preserved but inaccessible)
    Locked { timestamp: u64 },
    /// Check-in acknowledged
    CheckedIn { timestamp: u64 },
    /// Token revoked
    TokenRevoked { timestamp: u64 },
    /// Confirmation required before execution
    ConfirmationRequired { command: WipeCommand },
}

/// Error type for remote wipe operations
#[derive(Debug, thiserror::Error)]
pub enum WipeError {
    #[error("Wipe capability not enabled")]
    NotEnabled,

    #[error("Invalid wipe token")]
    InvalidToken,

    #[error("Command signature verification failed")]
    InvalidSignature,

    #[error("Command expired or timestamp invalid")]
    CommandExpired,

    #[error("Volume ID mismatch")]
    VolumeMismatch,

    #[error("Replay detected: command nonce already used")]
    ReplayDetected,

    #[error("Rate limited: please wait before retrying")]
    RateLimited,

    #[error("Account locked out due to too many failed attempts")]
    LockedOut,

    #[error("Confirmation required")]
    ConfirmationRequired,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),
}

/// Manager for remote wipe operations
pub struct RemoteWipeManager {
    /// Stored wipe configuration
    config: StoredWipeConfig,
    /// Path where config is persisted
    config_path: Option<std::path::PathBuf>,
    /// Pending confirmation (if any)
    pending_confirmation: Option<WipeCommand>,
}

impl RemoteWipeManager {
    /// Creates a new RemoteWipeManager and generates a wipe token
    ///
    /// Returns the manager and the generated token.
    /// **IMPORTANT**: Store the returned token securely - it cannot be recovered!
    pub fn new(volume_id: &str) -> (Self, WipeToken) {
        let token = WipeToken::generate();
        let config = StoredWipeConfig::new(&token, volume_id);

        let manager = Self {
            config,
            config_path: None,
            pending_confirmation: None,
        };

        (manager, token)
    }

    /// Creates a RemoteWipeManager from an existing config
    pub fn from_config(config: StoredWipeConfig) -> Self {
        Self {
            config,
            config_path: None,
            pending_confirmation: None,
        }
    }

    /// Loads a RemoteWipeManager from a config file
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        let config = StoredWipeConfig::from_bytes(&data)?;
        Ok(Self {
            config,
            config_path: Some(path.to_path_buf()),
            pending_confirmation: None,
        })
    }

    /// Saves the config to disk
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = self.config.to_bytes()?;
        std::fs::write(path, data)?;
        Ok(())
    }

    /// Saves to the previously loaded path
    pub fn persist(&self) -> Result<()> {
        if let Some(ref path) = self.config_path {
            self.save(path)
        } else {
            Err(CryptorError::InvalidInput("No config path set".into()))
        }
    }

    /// Adds a keyfile path to be destroyed on wipe
    pub fn add_keyfile_path(&mut self, path: &str) {
        if !self.config.keyfile_paths.contains(&path.to_string()) {
            self.config.keyfile_paths.push(path.to_string());
        }
    }

    /// Removes a keyfile path
    pub fn remove_keyfile_path(&mut self, path: &str) {
        self.config.keyfile_paths.retain(|p| p != path);
    }

    /// Sets whether confirmation is required
    pub fn set_require_confirmation(&mut self, require: bool) {
        self.config.require_confirmation = require;
    }

    /// Enables or disables wipe capability
    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    /// Returns the stored config (for cloud sync)
    pub fn config(&self) -> &StoredWipeConfig {
        &self.config
    }

    /// Verifies a wipe token against the stored hash
    pub fn verify_token(&self, token: &WipeToken) -> bool {
        self.config.verify_token(token)
    }

    /// Regenerates the wipe token (revokes old token)
    ///
    /// Returns the new token. Old token will no longer work.
    pub fn regenerate_token(&mut self) -> WipeToken {
        let token = WipeToken::generate();
        let mut token_salt = [0u8; TOKEN_SALT_SIZE];
        rand::rng().fill_bytes(&mut token_salt);

        self.config.token_salt = token_salt;
        self.config.token_hash = token.compute_verification_hash(&token_salt);
        self.config.failed_attempts = 0;
        self.config.lockout_until = 0;
        self.config.used_nonces.clear();

        token
    }

    /// Processes a wipe command
    ///
    /// Returns the result of the command execution.
    pub fn process_command(
        &mut self,
        command: &WipeCommand,
    ) -> std::result::Result<WipeResult, WipeError> {
        // Check if wipe is enabled
        if !self.config.enabled {
            return Err(WipeError::NotEnabled);
        }

        // Check lockout
        if self.config.is_locked_out() {
            return Err(WipeError::LockedOut);
        }

        // Check rate limit
        if self.config.is_rate_limited() {
            return Err(WipeError::RateLimited);
        }

        // Check volume ID
        if command.data.volume_id != self.config.volume_id {
            self.config.record_failure();
            return Err(WipeError::VolumeMismatch);
        }

        // Check timestamp freshness
        if !command.is_fresh() {
            self.config.record_failure();
            return Err(WipeError::CommandExpired);
        }

        // Check replay
        if self.config.is_nonce_used(&command.data.nonce) {
            self.config.record_failure();
            return Err(WipeError::ReplayDetected);
        }

        // Note: We can't verify the signature here without the token
        // The caller must provide the token for verification
        // This method assumes the token has already been verified

        Ok(WipeResult::ConfirmationRequired {
            command: command.clone(),
        })
    }

    /// Verifies and executes a wipe command with the token
    ///
    /// This is the main entry point for processing wipe commands.
    pub fn verify_and_execute(
        &mut self,
        command: &WipeCommand,
        token: &WipeToken,
    ) -> std::result::Result<WipeResult, WipeError> {
        // Check if wipe is enabled
        if !self.config.enabled {
            return Err(WipeError::NotEnabled);
        }

        // Check lockout
        if self.config.is_locked_out() {
            return Err(WipeError::LockedOut);
        }

        // Check rate limit
        if self.config.is_rate_limited() {
            return Err(WipeError::RateLimited);
        }

        // Verify token matches stored hash
        if !self.config.verify_token(token) {
            self.config.record_failure();
            return Err(WipeError::InvalidToken);
        }

        // Verify command signature
        if !command.verify(token) {
            self.config.record_failure();
            return Err(WipeError::InvalidSignature);
        }

        // Check volume ID
        if command.data.volume_id != self.config.volume_id {
            self.config.record_failure();
            return Err(WipeError::VolumeMismatch);
        }

        // Check timestamp freshness
        if !command.is_fresh() {
            self.config.record_failure();
            return Err(WipeError::CommandExpired);
        }

        // Check replay
        if self.config.is_nonce_used(&command.data.nonce) {
            self.config.record_failure();
            return Err(WipeError::ReplayDetected);
        }

        // Record success and nonce
        self.config.record_success();
        self.config.record_nonce(command.data.nonce);

        // Check if confirmation is required
        if self.config.require_confirmation
            && command.data.command_type == WipeCommandType::DestroyKeys
        {
            if self.pending_confirmation.is_none() {
                self.pending_confirmation = Some(command.clone());
                return Err(WipeError::ConfirmationRequired);
            } else {
                // This is the confirmation
                self.pending_confirmation = None;
            }
        }

        // Execute the command
        self.execute_command(command)
    }

    /// Confirms and executes a pending command
    pub fn confirm_and_execute(
        &mut self,
        token: &WipeToken,
    ) -> std::result::Result<WipeResult, WipeError> {
        let command = self
            .pending_confirmation
            .take()
            .ok_or(WipeError::Crypto("No pending command to confirm".into()))?;

        // Create confirmation command with new nonce
        let confirm_cmd =
            WipeCommand::new(token, &command.data.volume_id, command.data.command_type);

        self.verify_and_execute(&confirm_cmd, token)
    }

    /// Executes the command (called after all verification passes)
    fn execute_command(
        &mut self,
        command: &WipeCommand,
    ) -> std::result::Result<WipeResult, WipeError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match command.data.command_type {
            WipeCommandType::DestroyKeys => {
                let wiped = self.destroy_all_keyfiles()?;
                Ok(WipeResult::Destroyed {
                    keyfiles_wiped: wiped,
                    timestamp: now,
                })
            }
            WipeCommandType::Lock => {
                // Lock functionality would integrate with volume manager
                Ok(WipeResult::Locked { timestamp: now })
            }
            WipeCommandType::CheckIn => Ok(WipeResult::CheckedIn { timestamp: now }),
            WipeCommandType::RevokeToken => {
                self.config.enabled = false;
                Ok(WipeResult::TokenRevoked { timestamp: now })
            }
        }
    }

    /// Destroys all registered keyfiles
    ///
    /// # SSD Limitation Warning
    ///
    /// **IMPORTANT**: The multi-pass overwrite technique used here is **ineffective on SSDs**
    /// due to wear leveling. SSD controllers write data to new physical blocks rather than
    /// overwriting existing ones, meaning the original key material may persist in:
    ///
    /// - Unmapped blocks awaiting garbage collection
    /// - Over-provisioned reserve space (7-28% of SSD capacity)
    /// - Wear-leveled spare blocks
    ///
    /// For SSDs, the overwrite passes provide **defense-in-depth only**, not guaranteed
    /// secure deletion. The actual security comes from Tesseract's encryption-first design:
    ///
    /// 1. All sensitive data is encrypted before being written to disk
    /// 2. Deleting the encryption key renders all ciphertext unreadable
    /// 3. Even if key material persists on SSD blocks, it requires physical extraction
    ///
    /// For complete assurance on SSDs, consider:
    /// - Hardware Secure Erase (ATA/NVMe)
    /// - Physical destruction of the drive
    ///
    /// See `docs/SSD_SECURE_DELETION.md` for detailed guidance.
    fn destroy_all_keyfiles(&self) -> std::result::Result<usize, WipeError> {
        let mut wiped = 0;

        for path_str in &self.config.keyfile_paths {
            let path = Path::new(path_str);
            if path.exists() {
                // Securely wipe the file before deletion
                // NOTE: Effective on HDDs only. On SSDs, this provides defense-in-depth
                // but does not guarantee secure deletion due to wear leveling.
                if let Ok(metadata) = std::fs::metadata(path) {
                    let size = metadata.len() as usize;
                    if size > 0 {
                        // Overwrite with random data multiple times
                        for _ in 0..3 {
                            let mut random_data = vec![0u8; size];
                            rand::rng().fill_bytes(&mut random_data);
                            if std::fs::write(path, &random_data).is_err() {
                                break;
                            }
                        }
                        // Overwrite with zeros
                        let _ = std::fs::write(path, vec![0u8; size]);
                    }
                }
                // Delete the file
                if std::fs::remove_file(path).is_ok() {
                    wiped += 1;
                }
            }
        }

        Ok(wiped)
    }

    /// Clears the pending confirmation
    pub fn cancel_pending(&mut self) {
        self.pending_confirmation = None;
    }

    /// Returns whether there's a pending confirmation
    pub fn has_pending_confirmation(&self) -> bool {
        self.pending_confirmation.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wipe_token_generation() {
        let token1 = WipeToken::generate();
        let token2 = WipeToken::generate();

        // Tokens should be different
        assert_ne!(token1.token, token2.token);
    }

    #[test]
    fn test_wipe_token_hex_roundtrip() {
        let token = WipeToken::generate();
        let hex = token.to_hex();
        let recovered = WipeToken::from_hex(&hex).unwrap();

        assert_eq!(token.token, recovered.token);
    }

    #[test]
    fn test_stored_config_verification() {
        let (_, token) = RemoteWipeManager::new("test-volume");
        let config = StoredWipeConfig::new(&token, "test-volume");

        assert!(config.verify_token(&token));

        let wrong_token = WipeToken::generate();
        assert!(!config.verify_token(&wrong_token));
    }

    #[test]
    fn test_wipe_command_creation_and_verification() {
        let token = WipeToken::generate();
        let command = WipeCommand::new(&token, "test-volume", WipeCommandType::DestroyKeys);

        assert!(command.verify(&token));
        assert!(command.is_fresh());

        let wrong_token = WipeToken::generate();
        assert!(!command.verify(&wrong_token));
    }

    #[test]
    fn test_command_expiry() {
        let token = WipeToken::generate();
        let mut command = WipeCommand::new(&token, "test-volume", WipeCommandType::DestroyKeys);

        // Make command old
        command.data.timestamp = 0;
        assert!(!command.is_fresh());
    }

    #[test]
    fn test_rate_limiting() {
        let mut config = StoredWipeConfig::new(&WipeToken::generate(), "test");
        config.last_attempt = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(config.is_rate_limited());
    }

    #[test]
    fn test_lockout() {
        let mut config = StoredWipeConfig::new(&WipeToken::generate(), "test");

        // Record max failures
        for _ in 0..MAX_FAILED_ATTEMPTS {
            config.record_failure();
        }

        assert!(config.is_locked_out());
    }

    #[test]
    fn test_nonce_replay_protection() {
        let mut config = StoredWipeConfig::new(&WipeToken::generate(), "test");
        let nonce = [1u8; COMMAND_NONCE_SIZE];

        assert!(!config.is_nonce_used(&nonce));
        config.record_nonce(nonce);
        assert!(config.is_nonce_used(&nonce));
    }

    #[test]
    fn test_manager_verify_and_execute() {
        let (mut manager, token) = RemoteWipeManager::new("test-volume");
        manager.set_require_confirmation(false);

        let command = WipeCommand::new(&token, "test-volume", WipeCommandType::CheckIn);
        let result = manager.verify_and_execute(&command, &token);

        assert!(matches!(result, Ok(WipeResult::CheckedIn { .. })));
    }

    #[test]
    fn test_manager_wrong_token() {
        let (mut manager, _token) = RemoteWipeManager::new("test-volume");
        let wrong_token = WipeToken::generate();

        let command = WipeCommand::new(&wrong_token, "test-volume", WipeCommandType::CheckIn);
        let result = manager.verify_and_execute(&command, &wrong_token);

        assert!(matches!(result, Err(WipeError::InvalidToken)));
    }

    #[test]
    fn test_manager_volume_mismatch() {
        let (mut manager, token) = RemoteWipeManager::new("volume-a");

        let command = WipeCommand::new(&token, "volume-b", WipeCommandType::CheckIn);
        let result = manager.verify_and_execute(&command, &token);

        assert!(matches!(result, Err(WipeError::VolumeMismatch)));
    }

    #[test]
    fn test_manager_confirmation_required() {
        let (mut manager, token) = RemoteWipeManager::new("test-volume");
        manager.set_require_confirmation(true);

        let command = WipeCommand::new(&token, "test-volume", WipeCommandType::DestroyKeys);
        let result = manager.verify_and_execute(&command, &token);

        assert!(matches!(result, Err(WipeError::ConfirmationRequired)));
        assert!(manager.has_pending_confirmation());
    }

    #[test]
    fn test_token_regeneration() {
        let (mut manager, old_token) = RemoteWipeManager::new("test-volume");
        let new_token = manager.regenerate_token();

        assert!(!manager.verify_token(&old_token));
        assert!(manager.verify_token(&new_token));
    }

    #[test]
    fn test_keyfile_paths() {
        let (mut manager, _) = RemoteWipeManager::new("test");

        manager.add_keyfile_path("/etc/tesseract/key1");
        manager.add_keyfile_path("/etc/tesseract/key2");
        assert_eq!(manager.config.keyfile_paths.len(), 2);

        manager.remove_keyfile_path("/etc/tesseract/key1");
        assert_eq!(manager.config.keyfile_paths.len(), 1);
    }

    // ========================================================================
    // Additional WipeToken Tests
    // ========================================================================

    #[test]
    fn test_wipe_token_from_bytes_valid() {
        let bytes = [42u8; WIPE_TOKEN_SIZE];
        let token = WipeToken::from_bytes(&bytes).unwrap();
        assert_eq!(token.token, bytes);
    }

    #[test]
    fn test_wipe_token_from_bytes_wrong_size() {
        let bytes = [42u8; 16]; // Too short
        let result = WipeToken::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_wipe_token_from_hex_invalid() {
        let result = WipeToken::from_hex("not-valid-hex!");
        assert!(result.is_err());
    }

    #[test]
    fn test_wipe_token_verification_hash() {
        let token = WipeToken::generate();
        let salt = [1u8; TOKEN_SALT_SIZE];

        let hash1 = token.compute_verification_hash(&salt);
        let hash2 = token.compute_verification_hash(&salt);

        // Same inputs produce same hash
        assert_eq!(hash1, hash2);

        // Different salt produces different hash
        let other_salt = [2u8; TOKEN_SALT_SIZE];
        let hash3 = token.compute_verification_hash(&other_salt);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_wipe_token_sign_command() {
        let token = WipeToken::generate();
        let data = WipeCommandData {
            volume_id: "test-vol".to_string(),
            timestamp: 12345,
            nonce: [0u8; COMMAND_NONCE_SIZE],
            command_type: WipeCommandType::Lock,
            message: None,
        };

        let sig1 = token.sign_command(&data);
        let sig2 = token.sign_command(&data);
        assert_eq!(sig1, sig2);

        // Different token produces different signature
        let other_token = WipeToken::generate();
        let sig3 = other_token.sign_command(&data);
        assert_ne!(sig1, sig3);
    }

    // ========================================================================
    // Additional WipeCommand Tests
    // ========================================================================

    #[test]
    fn test_wipe_command_with_message() {
        let token = WipeToken::generate();
        let cmd = WipeCommand::with_message(
            &token,
            "test-vol",
            WipeCommandType::DestroyKeys,
            "Emergency wipe initiated",
        );

        assert_eq!(
            cmd.data.message,
            Some("Emergency wipe initiated".to_string())
        );
        assert!(cmd.verify(&token));
    }

    #[test]
    fn test_wipe_command_serialization() {
        let token = WipeToken::generate();
        let cmd = WipeCommand::new(&token, "test-vol", WipeCommandType::Lock);

        let bytes = cmd.to_bytes().unwrap();
        let restored = WipeCommand::from_bytes(&bytes).unwrap();

        assert_eq!(restored.data.volume_id, cmd.data.volume_id);
        assert_eq!(restored.data.timestamp, cmd.data.timestamp);
        assert_eq!(restored.signature, cmd.signature);
    }

    #[test]
    fn test_wipe_command_from_bytes_invalid() {
        let result = WipeCommand::from_bytes(b"not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_wipe_command_future_timestamp() {
        let token = WipeToken::generate();
        let mut cmd = WipeCommand::new(&token, "test-vol", WipeCommandType::CheckIn);

        // Set timestamp far in the future
        cmd.data.timestamp = u64::MAX;
        assert!(!cmd.is_fresh());
    }

    // ========================================================================
    // Additional WipeCommandType Tests
    // ========================================================================

    #[test]
    fn test_wipe_command_type_clone() {
        let cmd_type = WipeCommandType::DestroyKeys;
        let cloned = cmd_type;
        assert_eq!(cmd_type, cloned);
    }

    #[test]
    fn test_wipe_command_type_debug() {
        let cmd_type = WipeCommandType::Lock;
        let debug_str = format!("{:?}", cmd_type);
        assert!(debug_str.contains("Lock"));
    }

    #[test]
    fn test_wipe_command_type_serialize() {
        let cmd_type = WipeCommandType::CheckIn;
        let json = serde_json::to_string(&cmd_type).unwrap();
        let restored: WipeCommandType = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, cmd_type);
    }

    // ========================================================================
    // Additional StoredWipeConfig Tests
    // ========================================================================

    #[test]
    fn test_stored_config_serialization() {
        let token = WipeToken::generate();
        let config = StoredWipeConfig::new(&token, "test-vol");

        let bytes = config.to_bytes().unwrap();
        let restored = StoredWipeConfig::from_bytes(&bytes).unwrap();

        assert_eq!(restored.volume_id, config.volume_id);
        assert_eq!(restored.token_hash, config.token_hash);
    }

    #[test]
    fn test_stored_config_from_bytes_invalid() {
        let result = StoredWipeConfig::from_bytes(b"invalid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_stored_config_lockout_expired() {
        let token = WipeToken::generate();
        let mut config = StoredWipeConfig::new(&token, "test");

        // Set lockout to past time
        config.lockout_until = 1;
        assert!(!config.is_locked_out());
    }

    #[test]
    fn test_stored_config_record_success_resets_failure() {
        let token = WipeToken::generate();
        let mut config = StoredWipeConfig::new(&token, "test");

        // Record some failures
        config.record_failure();
        config.record_failure();
        assert_eq!(config.failed_attempts, 2);

        // Success should reset
        config.record_success();
        assert_eq!(config.failed_attempts, 0);
        assert_eq!(config.lockout_until, 0);
    }

    #[test]
    fn test_stored_config_nonce_pruning() {
        let token = WipeToken::generate();
        let mut config = StoredWipeConfig::new(&token, "test");

        // Add old nonces with past timestamps
        config.used_nonces.push((0, [1u8; COMMAND_NONCE_SIZE])); // Very old
        config.used_nonces.push((0, [2u8; COMMAND_NONCE_SIZE])); // Very old

        // Add a new nonce - should prune old ones
        config.record_nonce([3u8; COMMAND_NONCE_SIZE]);

        // Old nonces should be pruned, only new one remains
        assert_eq!(config.used_nonces.len(), 1);
    }

    #[test]
    fn test_stored_config_rate_limit_not_active() {
        let token = WipeToken::generate();
        let mut config = StoredWipeConfig::new(&token, "test");

        // Set last attempt to far past
        config.last_attempt = 0;
        assert!(!config.is_rate_limited());
    }

    // ========================================================================
    // Additional WipeResult Tests
    // ========================================================================

    #[test]
    fn test_wipe_result_destroyed_debug() {
        let result = WipeResult::Destroyed {
            keyfiles_wiped: 5,
            timestamp: 12345,
        };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("Destroyed"));
        assert!(debug_str.contains("5"));
    }

    #[test]
    fn test_wipe_result_locked_clone() {
        let result = WipeResult::Locked { timestamp: 12345 };
        let cloned = result.clone();
        if let (WipeResult::Locked { timestamp: t1 }, WipeResult::Locked { timestamp: t2 }) =
            (result, cloned)
        {
            assert_eq!(t1, t2);
        } else {
            panic!("Clone produced different variant");
        }
    }

    #[test]
    fn test_wipe_result_variants() {
        let _ = WipeResult::CheckedIn { timestamp: 100 };
        let _ = WipeResult::TokenRevoked { timestamp: 200 };

        let token = WipeToken::generate();
        let cmd = WipeCommand::new(&token, "vol", WipeCommandType::Lock);
        let _ = WipeResult::ConfirmationRequired { command: cmd };
    }

    // ========================================================================
    // Additional WipeError Tests
    // ========================================================================

    #[test]
    fn test_wipe_error_display() {
        let errors = [
            WipeError::NotEnabled,
            WipeError::InvalidToken,
            WipeError::InvalidSignature,
            WipeError::CommandExpired,
            WipeError::VolumeMismatch,
            WipeError::ReplayDetected,
            WipeError::RateLimited,
            WipeError::LockedOut,
            WipeError::ConfirmationRequired,
            WipeError::Crypto("test error".to_string()),
        ];

        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_wipe_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let wipe_err: WipeError = io_err.into();
        assert!(matches!(wipe_err, WipeError::Io(_)));
    }

    #[test]
    fn test_wipe_error_debug() {
        let err = WipeError::InvalidToken;
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidToken"));
    }

    // ========================================================================
    // Additional RemoteWipeManager Tests
    // ========================================================================

    #[test]
    fn test_manager_from_config() {
        let token = WipeToken::generate();
        let config = StoredWipeConfig::new(&token, "test-vol");
        let manager = RemoteWipeManager::from_config(config);

        assert!(manager.verify_token(&token));
    }

    #[test]
    fn test_manager_set_enabled() {
        let (mut manager, _) = RemoteWipeManager::new("test");

        manager.set_enabled(false);
        assert!(!manager.config().enabled);

        manager.set_enabled(true);
        assert!(manager.config().enabled);
    }

    #[test]
    fn test_manager_add_duplicate_keyfile() {
        let (mut manager, _) = RemoteWipeManager::new("test");

        manager.add_keyfile_path("/key1");
        manager.add_keyfile_path("/key1"); // Duplicate
        manager.add_keyfile_path("/key2");

        // Should not add duplicates
        assert_eq!(manager.config.keyfile_paths.len(), 2);
    }

    #[test]
    fn test_manager_persist_no_path() {
        let (manager, _) = RemoteWipeManager::new("test");
        let result = manager.persist();
        assert!(result.is_err());
    }

    #[test]
    fn test_manager_save_and_load() {
        use tempfile::NamedTempFile;

        let (manager, token) = RemoteWipeManager::new("test-vol");
        let temp_file = NamedTempFile::new().unwrap();

        // Save
        manager.save(temp_file.path()).unwrap();

        // Load
        let loaded = RemoteWipeManager::load(temp_file.path()).unwrap();
        assert!(loaded.verify_token(&token));
        assert_eq!(loaded.config().volume_id, "test-vol");
    }

    #[test]
    fn test_manager_load_invalid_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"invalid json data").unwrap();

        let result = RemoteWipeManager::load(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_manager_not_enabled() {
        let (mut manager, token) = RemoteWipeManager::new("test-vol");
        manager.set_enabled(false);

        let cmd = WipeCommand::new(&token, "test-vol", WipeCommandType::CheckIn);
        let result = manager.verify_and_execute(&cmd, &token);

        assert!(matches!(result, Err(WipeError::NotEnabled)));
    }

    #[test]
    fn test_manager_replay_detection() {
        let (mut manager, token) = RemoteWipeManager::new("test-vol");
        manager.set_require_confirmation(false);

        let cmd = WipeCommand::new(&token, "test-vol", WipeCommandType::CheckIn);

        // First execution should succeed
        let result1 = manager.verify_and_execute(&cmd, &token);
        assert!(result1.is_ok());

        // Wait for rate limit to pass
        std::thread::sleep(std::time::Duration::from_secs(RATE_LIMIT_SECS + 1));

        // Second execution with same nonce should fail with replay
        let result2 = manager.verify_and_execute(&cmd, &token);
        assert!(matches!(result2, Err(WipeError::ReplayDetected)));
    }

    #[test]
    fn test_manager_command_expired_via_process() {
        let (mut manager, _) = RemoteWipeManager::new("test-vol");

        // Use process_command which doesn't verify signature
        let token = WipeToken::generate();
        let mut cmd = WipeCommand::new(&token, "test-vol", WipeCommandType::CheckIn);
        cmd.data.timestamp = 0; // Very old (signature is invalid but process_command doesn't check)

        let result = manager.process_command(&cmd);
        assert!(matches!(result, Err(WipeError::CommandExpired)));
    }

    #[test]
    fn test_manager_has_pending_confirmation() {
        let (mut manager, token) = RemoteWipeManager::new("test-vol");
        manager.set_require_confirmation(true);

        assert!(!manager.has_pending_confirmation());

        let cmd = WipeCommand::new(&token, "test-vol", WipeCommandType::DestroyKeys);
        let _ = manager.verify_and_execute(&cmd, &token);

        assert!(manager.has_pending_confirmation());
    }

    // ========================================================================
    // Constant Tests
    // ========================================================================

    #[test]
    fn test_constants() {
        assert_eq!(WIPE_TOKEN_SIZE, 32);
        assert_eq!(TOKEN_SALT_SIZE, 16);
        assert_eq!(COMMAND_NONCE_SIZE, 16);
        assert_eq!(MAX_COMMAND_AGE_SECS, 300);
        assert_eq!(RATE_LIMIT_SECS, 5);
        assert_eq!(MAX_FAILED_ATTEMPTS, 5);
        assert_eq!(LOCKOUT_DURATION_SECS, 3600);
    }
}
