// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Error types for the Secure Cryptor library.
//!
//! This module defines all error types used throughout the application,
//! providing clear, actionable error messages for users and developers.

use thiserror::Error;

/// Main error type for all cryptor operations.
///
/// This enum encapsulates all possible errors that can occur during
/// encryption, decryption, key derivation, and file operations.
#[derive(Error, Debug)]
pub enum CryptorError {
    /// I/O error occurred during file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Password validation failed.
    #[error("Password validation failed: {0}")]
    PasswordValidation(String),

    /// Cryptography operation failed.
    #[error("Cryptography error: {0}")]
    Cryptography(String),

    /// Password hashing error.
    #[error("Password hashing error: {0}")]
    PasswordHash(String),

    /// Argon2 key derivation error.
    #[error("Argon2 error: {0}")]
    Argon2(String),

    /// Decryption failed - file may be corrupt or password incorrect.
    #[error("Decryption failed. The file may be corrupt or the password incorrect.")]
    Decryption,

    /// Invalid file format or header.
    #[error("Invalid file format or header.")]
    InvalidFormat,

    /// Failed to persist temporary file.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("Failed to persist temporary file: {0}")]
    TempFilePersist(#[from] tempfile::PersistError),

    /// Output file path is invalid.
    #[error("Output file path is invalid.")]
    InvalidOutputPath,

    /// Key derivation error.
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    /// Invalid input data.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Hardware security module error.
    #[error("Hardware security module error: {0}")]
    HardwareError(String),
}

/// Manual implementation to handle the non-standard error type from argon2.
impl From<argon2::Error> for CryptorError {
    fn from(err: argon2::Error) -> Self {
        CryptorError::Argon2(err.to_string())
    }
}

/// Type alias for Results using CryptorError.
pub type Result<T> = std::result::Result<T, CryptorError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CryptorError::PasswordValidation("too short".to_string());
        assert_eq!(err.to_string(), "Password validation failed: too short");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let cryptor_err: CryptorError = io_err.into();
        assert!(cryptor_err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_decryption_error() {
        let err = CryptorError::Decryption;
        assert!(err.to_string().contains("Decryption failed"));
    }

    #[test]
    fn test_cryptography_error() {
        let err = CryptorError::Cryptography("cipher failed".to_string());
        assert!(err.to_string().contains("Cryptography error"));
        assert!(err.to_string().contains("cipher failed"));
    }

    #[test]
    fn test_password_hash_error() {
        let err = CryptorError::PasswordHash("hash mismatch".to_string());
        assert!(err.to_string().contains("Password hashing error"));
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn test_argon2_error() {
        let err = CryptorError::Argon2("memory limit exceeded".to_string());
        assert!(err.to_string().contains("Argon2 error"));
        assert!(err.to_string().contains("memory limit exceeded"));
    }

    #[test]
    fn test_invalid_format_error() {
        let err = CryptorError::InvalidFormat;
        assert!(err.to_string().contains("Invalid file format"));
    }

    #[test]
    fn test_invalid_output_path_error() {
        let err = CryptorError::InvalidOutputPath;
        assert!(err.to_string().contains("Output file path is invalid"));
    }

    #[test]
    fn test_key_derivation_error() {
        let err = CryptorError::KeyDerivation("salt too short".to_string());
        assert!(err.to_string().contains("Key derivation error"));
        assert!(err.to_string().contains("salt too short"));
    }

    #[test]
    fn test_invalid_input_error() {
        let err = CryptorError::InvalidInput("empty buffer".to_string());
        assert!(err.to_string().contains("Invalid input"));
        assert!(err.to_string().contains("empty buffer"));
    }

    #[test]
    fn test_hardware_error() {
        let err = CryptorError::HardwareError("TPM not found".to_string());
        assert!(err.to_string().contains("Hardware security module error"));
        assert!(err.to_string().contains("TPM not found"));
    }

    #[test]
    fn test_argon2_from_impl() {
        // Test the From<argon2::Error> implementation
        let argon2_err = argon2::Error::AdTooLong;
        let cryptor_err: CryptorError = argon2_err.into();
        assert!(matches!(cryptor_err, CryptorError::Argon2(_)));
    }
}
