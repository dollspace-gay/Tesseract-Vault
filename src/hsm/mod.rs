// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Hardware Security Module (HSM) integration
//!
//! This module provides integration with various hardware security devices for
//! two-factor authentication and secure key storage.
//!
//! # Supported Devices
//!
//! - YubiKey (HMAC-SHA1 challenge-response)
//! - TPM 2.0 (key sealing with PCR binding)
//! - FIDO2/WebAuthn (planned)
//! - Intel SGX (planned)
//!
//! # Features
//!
//! - Two-factor authentication for encryption keys
//! - Hardware-backed key derivation
//! - TPM-based key sealing with platform integrity verification
//! - Backup key mechanisms
//! - Multi-device support

#[cfg(feature = "yubikey")]
pub mod yubikey;

#[cfg(feature = "yubikey")]
pub use yubikey::*;

// TPM 2.0 support (always available, detection at runtime)
#[cfg(not(target_arch = "wasm32"))]
pub mod tpm;

/// Pure utility functions for TPM operations, testable without hardware.
#[cfg(not(target_arch = "wasm32"))]
pub mod tpm_utils;

use crate::error::Result;
use zeroize::Zeroizing;

/// Trait for hardware security module integration
pub trait HardwareSecurityModule {
    /// Get the name of the HSM device
    fn name(&self) -> &str;

    /// Check if the device is available
    fn is_available(&self) -> bool;

    /// Derive a key using the hardware device
    ///
    /// # Arguments
    ///
    /// * `password` - User password
    /// * `salt` - Salt for key derivation
    /// * `challenge` - Challenge data for the device
    ///
    /// # Returns
    ///
    /// Derived key material
    fn derive_key(
        &self,
        password: &[u8],
        salt: &[u8],
        challenge: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;

    /// Verify that the device can be used
    fn verify(&self) -> Result<()>;
}

/// Configuration for HSM-based authentication
#[derive(Debug, Clone)]
pub struct HsmConfig {
    /// Require hardware device for encryption
    pub require_device: bool,

    /// Allow backup key if device is unavailable
    pub allow_backup: bool,

    /// Maximum authentication attempts
    pub max_attempts: u32,

    /// Timeout for device operations in milliseconds
    pub timeout_ms: u64,
}

impl Default for HsmConfig {
    fn default() -> Self {
        Self {
            require_device: false,
            allow_backup: true,
            max_attempts: 3,
            timeout_ms: 5000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hsm_config_default() {
        let config = HsmConfig::default();
        assert!(!config.require_device);
        assert!(config.allow_backup);
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.timeout_ms, 5000);
    }

    #[test]
    fn test_hsm_config_clone() {
        let config = HsmConfig {
            require_device: true,
            allow_backup: false,
            max_attempts: 5,
            timeout_ms: 10000,
        };

        let cloned = config.clone();
        assert!(cloned.require_device);
        assert!(!cloned.allow_backup);
        assert_eq!(cloned.max_attempts, 5);
        assert_eq!(cloned.timeout_ms, 10000);
    }

    #[test]
    fn test_hsm_config_debug() {
        let config = HsmConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("HsmConfig"));
        assert!(debug_str.contains("require_device"));
        assert!(debug_str.contains("allow_backup"));
    }
}
