// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Tesseract - A secure file encryption library
//!
//! This library provides secure file encryption and decryption using
//! AES-256-GCM with Argon2id key derivation.
//!
//! # Features
//!
//! - **Strong encryption**: AES-256-GCM (authenticated encryption)
//! - **Memory-hard KDF**: Argon2id key derivation
//! - **Password validation**: Enforces strong password requirements
//! - **Atomic operations**: Prevents partial file writes
//! - **Memory safety**: Zeroizes sensitive data
//! - **Timing-attack resistance**: Constant-time password comparison
//!
//! # Example
//!
//! ```no_run
//! use tesseract_lib::{encrypt_file, decrypt_file};
//! use std::path::Path;
//!
//! // Encrypt a file
//! encrypt_file(Path::new("secret.txt"), Path::new("secret.enc"), "MyStr0ng!Pass").unwrap();
//!
//! // Decrypt a file
//! decrypt_file(Path::new("secret.enc"), Path::new("secret.txt"), "MyStr0ng!Pass").unwrap();
//! ```

pub mod config;
#[cfg(kani)]
mod config_kani;
pub mod crypto;
pub mod error;
pub mod memory;

// Modules excluded from Creusot verification due to unsupported patterns
// (enumerate/zip return tuples which Creusot v0.8.0 can't handle)
#[cfg(not(creusot))]
pub mod daemon;
#[cfg(not(creusot))]
pub mod metadata;
#[cfg(not(creusot))]
pub mod power;
#[cfg(not(creusot))]
pub mod progress;
#[cfg(not(creusot))]
pub mod storage;
#[cfg(not(creusot))]
pub mod validation;
#[cfg(not(creusot))]
pub mod volume;

#[cfg(all(target_arch = "wasm32", not(creusot)))]
pub mod wasm;

#[cfg(all(not(target_arch = "wasm32"), not(creusot)))]
pub mod hsm;

#[cfg(all(target_os = "linux", not(creusot)))]
pub mod luks;

// Re-export commonly used types
pub use config::{CryptoConfig, MAGIC_BYTES, NONCE_LEN};
pub use crypto::aes_gcm::AesGcmEncryptor;
pub use crypto::kdf::{generate_salt_string, Argon2Kdf};
pub use crypto::streaming::{
    ChunkedDecryptor, ChunkedEncryptor, ChunkedReader, StreamConfig, StreamHeader, MAGIC_BYTES_V3,
};
pub use crypto::{Encryptor, KeyDerivation};
pub use error::{CryptorError, Result};
pub use memory::allocator::{AllocatorStats, SecureAllocator};
#[cfg(feature = "post-quantum")]
pub use memory::pool::{EncryptedAllocation, EncryptedMemoryPool, SecurityLevel};
pub use memory::scrub::{
    scrub_and_verify, scrub_bytes, scrub_bytes_pattern, ScrubGuard, ScrubPattern, ScrubStats,
};
pub use memory::LockedMemory;
#[cfg(not(creusot))]
pub use progress::{
    format_bytes, format_duration, ProgressCallback, ProgressReporter, ProgressTracker,
};
#[cfg(not(creusot))]
pub use validation::validate_password;
#[cfg(all(not(target_arch = "wasm32"), not(creusot)))]
pub use validation::{get_and_validate_password, get_password};

use rand::rngs::OsRng;
use rand_core::TryRngCore;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

/// Encrypts a file with a password using streaming (chunked) encryption.
///
/// This is the high-level API for file encryption. It:
/// 1. Opens the input file for streaming
/// 2. Derives a key from the password using Argon2id
/// 3. Encrypts the data in chunks using AES-256-GCM (memory-efficient)
/// 4. Writes the encrypted file atomically
///
/// Uses the V3 file format with chunked encryption and NIST-compliant nonce
/// construction, which allows encrypting files of any size without loading
/// the entire file into memory.
///
/// # Arguments
///
/// * `input_path` - Path to the file to encrypt
/// * `output_path` - Path where the encrypted file will be written
/// * `password` - Password for encryption
///
/// # Errors
///
/// Returns an error if:
/// - Input file cannot be read
/// - Password is invalid (for validation, use `encrypt_file_validated`)
/// - Encryption fails
/// - Output file cannot be written
///
/// # Examples
///
/// ```no_run
/// # use tesseract_lib::encrypt_file;
/// # use std::path::Path;
/// encrypt_file(
///     Path::new("document.pdf"),
///     Path::new("document.pdf.enc"),
///     "MyStrongPassword123!"
/// ).unwrap();
/// ```
#[cfg(not(creusot))]
pub fn encrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    // Derive encryption key from password
    let salt = generate_salt_string();
    let kdf = Argon2Kdf::default();
    let key = kdf.derive_key_with_salt_string(password.as_bytes(), &salt)?;

    // Generate base nonce for chunk nonce derivation
    let mut base_nonce = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut base_nonce)
        .map_err(|e| CryptorError::Cryptography(format!("RNG error: {}", e)))?;

    // Open input file for chunked reading
    let config = StreamConfig::default();
    let reader = ChunkedReader::open(input_path, config)?;

    // Create chunked encryptor
    let encryptor = Box::new(AesGcmEncryptor::new());
    let salt_string = salt.as_str().to_string();

    #[cfg(feature = "post-quantum")]
    let chunked_encryptor = {
        let key_clone = key.clone();
        ChunkedEncryptor::new(reader, encryptor, key, base_nonce, salt_string)
            .with_pqc_enabled(&key_clone)? // Enable post-quantum hybrid encryption
    };

    #[cfg(not(feature = "post-quantum"))]
    let chunked_encryptor = ChunkedEncryptor::new(reader, encryptor, key, base_nonce, salt_string);

    // Encrypt to output file atomically
    storage::write_atomically(output_path, |file| {
        chunked_encryptor
            .encrypt_to(file)
            .map_err(|e| std::io::Error::other(e.to_string()))
    })?;

    Ok(())
}

/// Encrypts a file with password validation.
///
/// Same as `encrypt_file` but validates password strength first.
///
/// # Arguments
///
/// * `input_path` - Path to the file to encrypt
/// * `output_path` - Path where the encrypted file will be written
/// * `password` - Password for encryption (will be validated)
///
/// # Errors
///
/// Returns an error if:
/// - Password fails validation
/// - Any error from `encrypt_file`
#[cfg(not(creusot))]
pub fn encrypt_file_validated(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    validation::validate_password(password)?;
    encrypt_file(input_path, output_path, password)
}

/// Encrypts a file using a Hardware Security Module for two-factor key derivation.
///
/// This combines password-based encryption with hardware-backed authentication.
/// The HSM (e.g., YubiKey) participates in key derivation, making decryption
/// require both the password AND the hardware device.
///
/// # Arguments
///
/// * `input_path` - Path to the file to encrypt
/// * `output_path` - Path where the encrypted file will be written
/// * `password` - Password for encryption
/// * `hsm` - Hardware Security Module implementation
///
/// # Errors
///
/// Returns an error if:
/// - HSM is not available
/// - Input file cannot be read
/// - Encryption fails
/// - Output file cannot be written
#[cfg(all(not(target_arch = "wasm32"), not(creusot)))]
pub fn encrypt_file_with_hsm<H: hsm::HardwareSecurityModule>(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    hsm: &H,
) -> Result<()> {
    use zeroize::Zeroizing;

    // Generate salt (also used as HSM challenge)
    let salt = generate_salt_string();
    let salt_bytes = salt.as_str().as_bytes();

    // Derive key using HSM (combines password + hardware response)
    let key = hsm.derive_key(password.as_bytes(), salt_bytes, salt_bytes)?;

    // Convert to fixed-size array for encryptor
    let mut key_array = Zeroizing::new([0u8; 32]);
    key_array.copy_from_slice(&key[..32]);

    // Generate base nonce for chunk nonce derivation
    let mut base_nonce = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut base_nonce)
        .map_err(|e| CryptorError::Cryptography(format!("RNG error: {}", e)))?;

    // Open input file for chunked reading
    let config = StreamConfig::default();
    let reader = ChunkedReader::open(input_path, config)?;

    // Create chunked encryptor
    let encryptor = Box::new(AesGcmEncryptor::new());
    let salt_string = salt.as_str().to_string();

    #[cfg(feature = "post-quantum")]
    let chunked_encryptor = {
        let key_clone = key_array.clone();
        ChunkedEncryptor::new(reader, encryptor, key_array, base_nonce, salt_string)
            .with_pqc_enabled(&key_clone)?
    };

    #[cfg(not(feature = "post-quantum"))]
    let chunked_encryptor =
        ChunkedEncryptor::new(reader, encryptor, key_array, base_nonce, salt_string);

    // Encrypt to output file atomically
    storage::write_atomically(output_path, |file| {
        chunked_encryptor
            .encrypt_to(file)
            .map_err(|e| std::io::Error::other(e.to_string()))
    })?;

    Ok(())
}

/// Decrypts a file using a Hardware Security Module for two-factor key derivation.
///
/// Requires the same HSM device that was used during encryption.
///
/// # Arguments
///
/// * `input_path` - Path to the encrypted file
/// * `output_path` - Path where the decrypted file will be written
/// * `password` - Password for decryption
/// * `hsm` - Hardware Security Module implementation (must be the same device used for encryption)
///
/// # Errors
///
/// Returns an error if:
/// - HSM is not available or wrong device
/// - Input file cannot be read or has invalid format
/// - Password is incorrect
/// - Decryption or authentication fails
#[cfg(all(not(target_arch = "wasm32"), not(creusot)))]
pub fn decrypt_file_with_hsm<H: hsm::HardwareSecurityModule>(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    hsm: &H,
) -> Result<()> {
    use zeroize::Zeroizing;

    // Read header to get salt
    let mut file = File::open(input_path)?;
    let header = StreamHeader::read_from(&mut file)?;

    // Use salt as HSM challenge
    let salt_bytes = header.salt.as_bytes();

    // Derive key using HSM (combines password + hardware response)
    let key = hsm.derive_key(password.as_bytes(), salt_bytes, salt_bytes)?;

    // Convert to fixed-size array for decryptor
    let mut key_array = Zeroizing::new([0u8; 32]);
    key_array.copy_from_slice(&key[..32]);

    // Reopen file for full decryption
    let file = File::open(input_path)?;
    let encryptor = Box::new(AesGcmEncryptor::new());
    let mut chunked_decryptor = ChunkedDecryptor::new(file, encryptor, key_array)?;

    // Decrypt to output file atomically
    storage::write_atomically(output_path, |output_file| {
        chunked_decryptor
            .decrypt_to(output_file)
            .map_err(|e| std::io::Error::other(e.to_string()))
    })?;

    Ok(())
}

/// Decrypts a file with a password.
///
/// This is the high-level API for file decryption. It:
/// 1. Detects the file format (v1 or v3)
/// 2. Reads and parses the encrypted file header
/// 3. Derives the key from the password
/// 4. Decrypts and authenticates the data (streaming for v3, in-memory for v1)
/// 5. Writes the plaintext atomically
///
/// Supports both v1 (legacy, in-memory) and v3 (streaming, memory-efficient) formats.
///
/// # Arguments
///
/// * `input_path` - Path to the encrypted file
/// * `output_path` - Path where the decrypted file will be written
/// * `password` - Password for decryption
///
/// # Errors
///
/// Returns an error if:
/// - Input file cannot be read or has invalid format
/// - Password is incorrect
/// - Decryption or authentication fails
/// - Output file cannot be written
///
/// # Examples
///
/// ```no_run
/// # use tesseract_lib::decrypt_file;
/// # use std::path::Path;
/// decrypt_file(
///     Path::new("document.pdf.enc"),
///     Path::new("document.pdf"),
///     "MyStrongPassword123!"
/// ).unwrap();
/// ```
#[cfg(not(creusot))]
pub fn decrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    use crate::config::MAGIC_BYTES;

    let mut file = File::open(input_path)?;

    // Read magic bytes to detect format version
    let mut magic_buf = [0u8; 8];
    file.read_exact(&mut magic_buf)?;

    // Check which format version
    if magic_buf == MAGIC_BYTES_V3 {
        // V3 format: Use streaming decryption with NIST-compliant nonces
        decrypt_file_v3(input_path, output_path, password)
    } else if magic_buf == MAGIC_BYTES {
        // V1 format: Use legacy in-memory decryption
        // Reset file to beginning for v1 parsing
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(0))?;
        decrypt_file_v1(file, output_path, password)
    } else {
        Err(CryptorError::InvalidFormat)
    }
}

/// Decrypts a v1 format file (legacy, in-memory).
fn decrypt_file_v1(mut file: File, output_path: &Path, password: &str) -> Result<()> {
    let header = storage::format::read_encrypted_header(&mut file)?;

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;

    let kdf = Argon2Kdf::default();
    let key = kdf.derive_key_with_salt_string(password.as_bytes(), &header.salt)?;

    let encryptor = AesGcmEncryptor::new();
    let plaintext = encryptor.decrypt(&key, &header.nonce, &ciphertext)?;

    storage::write_file_atomic(output_path, &plaintext)?;

    Ok(())
}

/// Decrypts a v3 format file (streaming, memory-efficient, NIST-compliant).
fn decrypt_file_v3(input_path: &Path, output_path: &Path, password: &str) -> Result<()> {
    // First, read just the header to get the salt for key derivation
    let mut file = File::open(input_path)?;
    let header = StreamHeader::read_from(&mut file)?;

    // Derive key from password using salt from header
    let kdf = Argon2Kdf::default();
    let salt = argon2::password_hash::SaltString::from_b64(&header.salt)
        .map_err(|e| CryptorError::PasswordHash(e.to_string()))?;
    let key = kdf.derive_key_with_salt_string(password.as_bytes(), &salt)?;

    // Reopen file for full decryption with correct key
    let file = File::open(input_path)?;
    let encryptor = Box::new(AesGcmEncryptor::new());
    let mut chunked_decryptor = ChunkedDecryptor::new(file, encryptor, key)?;

    // Decrypt to output file atomically
    storage::write_atomically(output_path, |output_file| {
        chunked_decryptor
            .decrypt_to(output_file)
            .map_err(|e| std::io::Error::other(e.to_string()))
    })?;

    Ok(())
}

/// Encrypts data in memory (without file I/O).
///
/// Useful for encrypting data that's already in memory.
///
/// # Returns
///
/// A tuple of `(salt, nonce, ciphertext)` needed for decryption.
pub fn encrypt_bytes(plaintext: &[u8], password: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let salt = generate_salt_string();
    let kdf = Argon2Kdf::default();
    let key = kdf.derive_key_with_salt_string(password.as_bytes(), &salt)?;

    let encryptor = AesGcmEncryptor::new();
    let mut nonce = vec![0u8; encryptor.nonce_len()];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CryptorError::Cryptography(format!("RNG error: {}", e)))?;

    let ciphertext = encryptor.encrypt(&key, &nonce, plaintext)?;

    Ok((salt.as_str().as_bytes().to_vec(), nonce, ciphertext))
}

/// Decrypts data in memory (without file I/O).
///
/// # Arguments
///
/// * `salt` - Salt bytes (from encryption)
/// * `nonce` - Nonce bytes (from encryption)
/// * `ciphertext` - Encrypted data
/// * `password` - Password for decryption
///
/// # Security
///
/// Returns plaintext in zeroizing memory that is automatically cleared when dropped.
pub fn decrypt_bytes(
    salt: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    password: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let salt_str = std::str::from_utf8(salt).map_err(|_| CryptorError::InvalidFormat)?;
    let salt_string = argon2::password_hash::SaltString::from_b64(salt_str)
        .map_err(|e| CryptorError::PasswordHash(e.to_string()))?;

    let kdf = Argon2Kdf::default();
    let key = kdf.derive_key_with_salt_string(password.as_bytes(), &salt_string)?;

    let encryptor = AesGcmEncryptor::new();
    encryptor.decrypt(&key, nonce, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_file_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_path = temp_dir.path().join("encrypted.bin");
        let output_path = temp_dir.path().join("output.txt");

        let test_data = b"This is a secret message!";
        std::fs::write(&input_path, test_data).unwrap();

        let password = "TestPassword123!";

        encrypt_file(&input_path, &encrypted_path, password).unwrap();
        decrypt_file(&encrypted_path, &output_path, password).unwrap();

        let decrypted_data = std::fs::read(&output_path).unwrap();
        assert_eq!(decrypted_data, test_data);
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_path = temp_dir.path().join("encrypted.bin");
        let output_path = temp_dir.path().join("output.txt");

        let test_data = b"Secret";
        std::fs::write(&input_path, test_data).unwrap();

        encrypt_file(&input_path, &encrypted_path, "CorrectPass123!").unwrap();
        let result = decrypt_file(&encrypted_path, &output_path, "WrongPass123!");

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_bytes_decrypt_bytes() {
        let plaintext = b"Memory encryption test";
        let password = "TestPassword123!";

        let (salt, nonce, ciphertext) = encrypt_bytes(plaintext, password).unwrap();
        let decrypted = decrypt_bytes(&salt, &nonce, &ciphertext, password).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_file_validated() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_path = temp_dir.path().join("encrypted.bin");

        std::fs::write(&input_path, b"test data").unwrap();

        // Weak password should fail
        let result = encrypt_file_validated(&input_path, &encrypted_path, "weak");
        assert!(result.is_err());

        // Strong password should succeed
        let result = encrypt_file_validated(&input_path, &encrypted_path, "StrongPass123!");
        assert!(result.is_ok());
    }

    #[test]
    fn test_decrypt_file_invalid_format() {
        let temp_dir = tempfile::tempdir().unwrap();
        let invalid_path = temp_dir.path().join("invalid.bin");
        let output_path = temp_dir.path().join("output.txt");

        // Write random data that doesn't match any magic bytes
        std::fs::write(&invalid_path, b"RANDOMXX12345678901234567890").unwrap();

        let result = decrypt_file(&invalid_path, &output_path, "password123");
        assert!(result.is_err());
        if let Err(CryptorError::InvalidFormat) = result {
            // Expected
        } else {
            panic!("Expected InvalidFormat error");
        }
    }

    #[test]
    fn test_decrypt_bytes_invalid_salt_utf8() {
        let result = decrypt_bytes(&[0xFF, 0xFE], &[0u8; 12], &[0u8; 32], "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_bytes_invalid_salt_base64() {
        let result = decrypt_bytes(b"not-valid-base64!!", &[0u8; 12], &[0u8; 32], "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_empty_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("empty.txt");
        let encrypted_path = temp_dir.path().join("encrypted.bin");
        let output_path = temp_dir.path().join("output.txt");

        std::fs::write(&input_path, b"").unwrap();

        let password = "TestPassword123!";

        encrypt_file(&input_path, &encrypted_path, password).unwrap();
        decrypt_file(&encrypted_path, &output_path, password).unwrap();

        let decrypted_data = std::fs::read(&output_path).unwrap();
        assert!(decrypted_data.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_large_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("large.bin");
        let encrypted_path = temp_dir.path().join("encrypted.bin");
        let output_path = temp_dir.path().join("output.bin");

        // Create 1MB file with pattern data
        let test_data: Vec<u8> = (0u8..=255).cycle().take(1024 * 1024).collect();
        std::fs::write(&input_path, &test_data).unwrap();

        let password = "TestPassword123!";

        encrypt_file(&input_path, &encrypted_path, password).unwrap();
        decrypt_file(&encrypted_path, &output_path, password).unwrap();

        let decrypted_data = std::fs::read(&output_path).unwrap();
        assert_eq!(decrypted_data, test_data);
    }

    #[test]
    fn test_encrypt_bytes_empty() {
        let (salt, nonce, ciphertext) = encrypt_bytes(&[], "TestPassword123!").unwrap();
        assert!(!salt.is_empty());
        assert!(!nonce.is_empty());
        // Ciphertext has auth tag even for empty plaintext
        assert!(!ciphertext.is_empty());

        let decrypted = decrypt_bytes(&salt, &nonce, &ciphertext, "TestPassword123!").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_bytes_large() {
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(100_000).collect();
        let password = "TestPassword123!";

        let (salt, nonce, ciphertext) = encrypt_bytes(&plaintext, password).unwrap();
        let decrypted = decrypt_bytes(&salt, &nonce, &ciphertext, password).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_decrypt_bytes_wrong_password() {
        let plaintext = b"secret data";
        let (salt, nonce, ciphertext) = encrypt_bytes(plaintext, "CorrectPass123!").unwrap();
        let result = decrypt_bytes(&salt, &nonce, &ciphertext, "WrongPassword!");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_file_nonexistent_input() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("nonexistent.txt");
        let encrypted_path = temp_dir.path().join("encrypted.bin");

        let result = encrypt_file(&input_path, &encrypted_path, "TestPassword123!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_file_nonexistent_input() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("nonexistent.bin");
        let output_path = temp_dir.path().join("output.txt");

        let result = decrypt_file(&input_path, &output_path, "TestPassword123!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_bytes_tampered_ciphertext() {
        let plaintext = b"important data";
        let (salt, nonce, mut ciphertext) = encrypt_bytes(plaintext, "TestPassword123!").unwrap();

        // Tamper with ciphertext
        if let Some(byte) = ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }

        let result = decrypt_bytes(&salt, &nonce, &ciphertext, "TestPassword123!");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_unicode_content() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("unicode.txt");
        let encrypted_path = temp_dir.path().join("encrypted.bin");
        let output_path = temp_dir.path().join("output.txt");

        let test_data = "Hello 世界 🌍 Привет мир 你好".as_bytes();
        std::fs::write(&input_path, test_data).unwrap();

        let password = "TestPassword123!";

        encrypt_file(&input_path, &encrypted_path, password).unwrap();
        decrypt_file(&encrypted_path, &output_path, password).unwrap();

        let decrypted_data = std::fs::read(&output_path).unwrap();
        assert_eq!(decrypted_data, test_data);
    }

    #[test]
    fn test_decrypt_file_truncated() {
        let temp_dir = tempfile::tempdir().unwrap();
        let truncated_path = temp_dir.path().join("truncated.bin");
        let output_path = temp_dir.path().join("output.txt");

        // Write file shorter than magic bytes (8 bytes)
        std::fs::write(&truncated_path, b"SHORT").unwrap();

        let result = decrypt_file(&truncated_path, &output_path, "password123");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_bytes_special_password() {
        let plaintext = b"test data";
        // Password with special characters
        let password = "P@$$w0rd!#$%^&*()_+-=[]{}|;':\",./<>?`~";

        let (salt, nonce, ciphertext) = encrypt_bytes(plaintext, password).unwrap();
        let decrypted = decrypt_bytes(&salt, &nonce, &ciphertext, password).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_bytes_unicode_password() {
        let plaintext = b"test data";
        let password = "пароль密码パスワード🔐";

        let (salt, nonce, ciphertext) = encrypt_bytes(plaintext, password).unwrap();
        let decrypted = decrypt_bytes(&salt, &nonce, &ciphertext, password).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_decrypt_bytes_wrong_nonce() {
        let plaintext = b"secret data";
        let password = "TestPassword123!";

        let (salt, _, ciphertext) = encrypt_bytes(plaintext, password).unwrap();

        // Use wrong nonce
        let wrong_nonce = vec![0xFF; 12];
        let result = decrypt_bytes(&salt, &wrong_nonce, &ciphertext, password);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_bytes_truncated_ciphertext() {
        let plaintext = b"secret data";
        let password = "TestPassword123!";

        let (salt, nonce, ciphertext) = encrypt_bytes(plaintext, password).unwrap();

        // Truncate ciphertext (remove auth tag)
        let truncated: Vec<u8> = ciphertext.iter().take(5).cloned().collect();
        let result = decrypt_bytes(&salt, &nonce, &truncated, password);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_file_validated_strong_password() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_path = temp_dir.path().join("encrypted.bin");
        let output_path = temp_dir.path().join("output.txt");

        std::fs::write(&input_path, b"test data").unwrap();

        // Strong password should pass validation and encrypt
        encrypt_file_validated(&input_path, &encrypted_path, "VeryStr0ng!Pass#2024").unwrap();

        // Verify it can be decrypted
        decrypt_file(&encrypted_path, &output_path, "VeryStr0ng!Pass#2024").unwrap();
        let decrypted = std::fs::read(&output_path).unwrap();
        assert_eq!(decrypted, b"test data");
    }

    #[test]
    fn test_encrypt_file_validated_various_weak_passwords() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_path = temp_dir.path().join("encrypted.bin");

        std::fs::write(&input_path, b"test data").unwrap();

        // Too short
        assert!(encrypt_file_validated(&input_path, &encrypted_path, "Ab1!").is_err());

        // No uppercase
        assert!(encrypt_file_validated(&input_path, &encrypted_path, "password123!").is_err());

        // No lowercase
        assert!(encrypt_file_validated(&input_path, &encrypted_path, "PASSWORD123!").is_err());

        // No digit
        assert!(encrypt_file_validated(&input_path, &encrypted_path, "Password!!!").is_err());
    }

    #[test]
    fn test_re_exports_available() {
        // Verify key re-exports are accessible
        let _ = MAGIC_BYTES;
        let _ = NONCE_LEN;
        let _ = MAGIC_BYTES_V3;

        // Verify type re-exports work
        let _encryptor = AesGcmEncryptor::new();
        let _kdf = Argon2Kdf::default();
        let _salt = generate_salt_string();
    }

    #[test]
    fn test_stream_config_re_export() {
        let config = StreamConfig::default();
        assert!(config.chunk_size > 0);
    }

    #[test]
    fn test_crypto_config_re_export() {
        let config = CryptoConfig::default();
        assert!(config.argon2_mem_cost_kib > 0);
        assert!(config.argon2_time_cost > 0);
    }

    #[test]
    fn test_scrub_functions_re_export() {
        let mut data = vec![0xABu8; 32];
        scrub_bytes(&mut data);
        // After scrub, data should be zeroed
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_scrub_pattern_re_export() {
        let mut data = vec![0xABu8; 32];
        scrub_bytes_pattern(&mut data, ScrubPattern::Dod522022M);
        // After scrub with DoD pattern, data should not be original
        assert!(!data.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_progress_format_helpers_re_export() {
        let bytes_str = format_bytes(1024 * 1024);
        assert!(bytes_str.contains("MiB") || bytes_str.contains("MB") || bytes_str.contains("1"));

        let duration_str = format_duration(std::time::Duration::from_secs(65));
        assert!(!duration_str.is_empty());
    }

    #[test]
    fn test_validate_password_re_export() {
        // Weak password should fail
        assert!(validate_password("weak").is_err());

        // Strong password should pass
        assert!(validate_password("StrongP@ss123!").is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_binary_content() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("binary.bin");
        let encrypted_path = temp_dir.path().join("encrypted.bin");
        let output_path = temp_dir.path().join("output.bin");

        // Binary content with null bytes and all byte values
        let test_data: Vec<u8> = (0u8..=255).collect();
        std::fs::write(&input_path, &test_data).unwrap();

        let password = "TestPassword123!";

        encrypt_file(&input_path, &encrypted_path, password).unwrap();
        decrypt_file(&encrypted_path, &output_path, password).unwrap();

        let decrypted_data = std::fs::read(&output_path).unwrap();
        assert_eq!(decrypted_data, test_data);
    }

    #[test]
    fn test_encrypt_bytes_binary_content() {
        // Binary content with null bytes
        let plaintext: Vec<u8> = vec![0x00, 0x01, 0xFF, 0xFE, 0x00, 0x00, 0xAB, 0xCD];
        let password = "TestPassword123!";

        let (salt, nonce, ciphertext) = encrypt_bytes(&plaintext, password).unwrap();
        let decrypted = decrypt_bytes(&salt, &nonce, &ciphertext, password).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_multiple_encryptions_different_salts() {
        let plaintext = b"test data";
        let password = "TestPassword123!";

        let (salt1, _, _) = encrypt_bytes(plaintext, password).unwrap();
        let (salt2, _, _) = encrypt_bytes(plaintext, password).unwrap();
        let (salt3, _, _) = encrypt_bytes(plaintext, password).unwrap();

        // Each encryption should use a different salt
        assert_ne!(salt1, salt2);
        assert_ne!(salt2, salt3);
        assert_ne!(salt1, salt3);
    }

    #[test]
    fn test_multiple_encryptions_different_nonces() {
        let plaintext = b"test data";
        let password = "TestPassword123!";

        let (_, nonce1, _) = encrypt_bytes(plaintext, password).unwrap();
        let (_, nonce2, _) = encrypt_bytes(plaintext, password).unwrap();
        let (_, nonce3, _) = encrypt_bytes(plaintext, password).unwrap();

        // Each encryption should use a different nonce
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        assert_ne!(nonce1, nonce3);
    }

    #[test]
    fn test_ciphertext_different_for_same_plaintext() {
        let plaintext = b"test data";
        let password = "TestPassword123!";

        let (_, _, ciphertext1) = encrypt_bytes(plaintext, password).unwrap();
        let (_, _, ciphertext2) = encrypt_bytes(plaintext, password).unwrap();

        // Same plaintext should produce different ciphertext due to random salt/nonce
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_secure_allocator_re_export() {
        let allocator = SecureAllocator::new();
        let stats = allocator.stats();
        assert_eq!(stats.allocation_count, 0);
        assert_eq!(stats.bytes_allocated, 0);
    }

    #[test]
    fn test_locked_memory_re_export() {
        let locked = LockedMemory::new(vec![1, 2, 3, 4]).unwrap();
        assert_eq!(locked.len(), 4);
    }
}
