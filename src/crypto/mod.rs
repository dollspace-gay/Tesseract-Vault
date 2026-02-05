// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Cryptographic operations for encryption, decryption, and key derivation.
//!
//! This module provides trait-based abstractions for cryptographic operations,
//! allowing for pluggable implementations of different encryption algorithms.

pub mod aes_gcm;
pub mod hardware;
pub mod kdf;
#[cfg(feature = "post-quantum")]
pub mod keyfile;
#[cfg(feature = "post-quantum")]
pub mod pqc;
#[cfg(feature = "post-quantum")]
pub mod signatures;
pub mod streaming;

#[cfg(all(test, feature = "post-quantum"))]
mod pqc_tests;

// Kani formal verification harnesses
#[cfg(kani)]
mod aes_gcm_kani;
#[cfg(kani)]
mod kdf_kani;
#[cfg(kani)]
mod streaming_kani;

use crate::error::Result;
use zeroize::Zeroizing;

/// Trait for symmetric encryption and decryption operations.
///
/// Implementors provide authenticated encryption using AEAD algorithms.
pub trait Encryptor: Send + Sync {
    /// Encrypt plaintext with a given key and nonce.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte encryption key
    /// * `nonce` - Nonce (size depends on algorithm)
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// Ciphertext with authentication tag appended.
    fn encrypt(&self, key: &[u8; 32], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext with a given key and nonce.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte encryption key
    /// * `nonce` - Nonce (size depends on algorithm)
    /// * `ciphertext` - Data to decrypt (includes authentication tag)
    ///
    /// # Returns
    ///
    /// Decrypted plaintext in zeroizing memory if authentication succeeds.
    fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;

    /// Returns the required nonce length for this encryptor.
    fn nonce_len(&self) -> usize;
}

/// Trait for password-based key derivation.
///
/// Implementors derive cryptographic keys from passwords using KDFs.
pub trait KeyDerivation: Send + Sync {
    /// Derive a 32-byte key from a password and salt.
    ///
    /// # Arguments
    ///
    /// * `password` - User password
    /// * `salt` - Cryptographic salt
    ///
    /// # Returns
    ///
    /// 32-byte derived key in zeroizing memory.
    fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>>;

    /// Generate a new random salt.
    fn generate_salt(&self) -> Vec<u8>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aes_gcm::AesGcmEncryptor;
    use crate::crypto::kdf::Argon2Kdf;

    /// Verify Encryptor can be used as a trait object and roundtrips correctly.
    #[test]
    fn test_encryptor_as_trait_object() {
        let encryptor: Box<dyn Encryptor> = Box::new(AesGcmEncryptor::new());
        let key = [0u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"trait object test";

        let ciphertext = encryptor.encrypt(&key, &nonce, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

        let decrypted = encryptor.decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    /// Verify KeyDerivation can be used as a trait object and is deterministic.
    #[test]
    fn test_kdf_as_trait_object() {
        let kdf: Box<dyn KeyDerivation> = Box::new(Argon2Kdf::default());
        let password = b"test_password";
        let salt = b"test_salt_123456";

        let key = kdf.derive_key(password, salt).unwrap();
        assert_eq!(key.len(), 32);

        let key2 = kdf.derive_key(password, salt).unwrap();
        assert_eq!(*key, *key2);
    }
}
