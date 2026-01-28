// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! PQC Keyfile support for true quantum-resistant encryption.
//!
//! This module provides ML-KEM-1024 keyfile generation, serialization, and management.
//! Keyfiles enable true quantum resistance by keeping the decapsulation key external
//! to the encrypted volume, avoiding the chicken-and-egg problem where PQC keys
//! are protected by classical cryptography.
//!
//! # Security Model
//!
//! | Mode | Key Derivation | Quantum Security |
//! |------|---------------|------------------|
//! | Password only | Argon2id → AES-256 | ~128-bit (Grover) |
//! | Password + Keyfile | Argon2id + ML-KEM → AES-256 | NIST Level 5 |
//!
//! # File Format
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │ Magic: "TESS-KF1"                       │  8 bytes
//! │ Version: 1                              │  1 byte
//! │ Algorithm: 0 = ML-KEM-1024              │  1 byte
//! │ Protected: 0/1                          │  1 byte
//! ├─────────────────────────────────────────┤
//! │ Encapsulation key (public)              │  1568 bytes
//! ├─────────────────────────────────────────┤
//! │ If protected:                           │
//! │   Salt (22 bytes, base64)               │
//! │   Nonce (12 bytes)                      │
//! │   Encrypted dk + tag (3168 + 16 bytes)  │
//! │ Else:                                   │
//! │   Raw decapsulation key (3168 bytes)    │
//! └─────────────────────────────────────────┘
//! ```

use crate::crypto::aes_gcm::AesGcmEncryptor;
use crate::crypto::kdf::{generate_salt_string, Argon2Kdf};
use crate::crypto::pqc::{MlKemKeyPair, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SHARED_SECRET_SIZE};
use crate::crypto::Encryptor;
use crate::error::{CryptorError, Result};
use rand::rngs::SysRng;
use rand_core::TryRng;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Magic bytes identifying a Tesseract keyfile.
pub const KEYFILE_MAGIC: &[u8; 8] = b"TESS-KF1";

/// Current keyfile format version.
pub const KEYFILE_VERSION: u8 = 1;

/// Algorithm identifier for ML-KEM-1024.
pub const ALGORITHM_MLKEM1024: u8 = 0;

/// Salt size for Argon2 (base64 encoded).
const SALT_SIZE: usize = 22;

/// Nonce size for AES-256-GCM.
const NONCE_SIZE: usize = 12;

/// Authentication tag size for AES-256-GCM.
const TAG_SIZE: usize = 16;

/// Header size: magic (8) + version (1) + algorithm (1) + protected (1) = 11 bytes.
const HEADER_SIZE: usize = 11;

/// Unprotected keyfile size: header + ek + dk.
const UNPROTECTED_SIZE: usize = HEADER_SIZE + PUBLIC_KEY_SIZE + SECRET_KEY_SIZE;

/// Protected keyfile size: header + ek + salt + nonce + encrypted_dk + tag.
const PROTECTED_SIZE: usize =
    HEADER_SIZE + PUBLIC_KEY_SIZE + SALT_SIZE + NONCE_SIZE + SECRET_KEY_SIZE + TAG_SIZE;

/// A Tesseract PQC keyfile containing an ML-KEM-1024 keypair.
///
/// The keyfile can be optionally password-protected using AES-256-GCM with
/// Argon2id key derivation, providing defense-in-depth if the keyfile is stolen.
#[derive(Clone)]
pub struct PqcKeyfile {
    /// The ML-KEM-1024 keypair.
    keypair: MlKemKeyPair,
    /// Whether the keyfile was loaded from a protected file.
    was_protected: bool,
}

impl Zeroize for PqcKeyfile {
    fn zeroize(&mut self) {
        self.keypair.zeroize();
    }
}

impl Drop for PqcKeyfile {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PqcKeyfile {
    /// Generate a new PQC keyfile with a fresh ML-KEM-1024 keypair.
    ///
    /// # Example
    ///
    /// ```
    /// use tesseract_lib::crypto::keyfile::PqcKeyfile;
    ///
    /// let keyfile = PqcKeyfile::generate();
    /// ```
    pub fn generate() -> Self {
        Self {
            keypair: MlKemKeyPair::generate(),
            was_protected: false,
        }
    }

    /// Get the public encapsulation key.
    ///
    /// This key is used to encapsulate shared secrets during encryption.
    pub fn encapsulation_key(&self) -> &[u8] {
        self.keypair.encapsulation_key()
    }

    /// Get the private decapsulation key.
    ///
    /// This key is used to decapsulate shared secrets during decryption.
    pub fn decapsulation_key(&self) -> &[u8] {
        self.keypair.decapsulation_key()
    }

    /// Encapsulate a shared secret using this keyfile's public key.
    ///
    /// # Returns
    ///
    /// A tuple of (ciphertext, shared_secret) where:
    /// - `ciphertext` should be stored in the volume header (1568 bytes)
    /// - `shared_secret` is combined with the password-derived key (32 bytes)
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_SIZE]>)> {
        crate::crypto::pqc::encapsulate(self.keypair.encapsulation_key())
    }

    /// Decapsulate a shared secret using this keyfile's private key.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext from the volume header (1568 bytes)
    ///
    /// # Returns
    ///
    /// The shared secret (32 bytes) for combining with password-derived key.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; SHARED_SECRET_SIZE]>> {
        self.keypair.decapsulate(ciphertext)
    }

    /// Save the keyfile to disk without password protection.
    ///
    /// # Warning
    ///
    /// The decapsulation key will be stored in plaintext. Consider using
    /// [`save_protected`] for better security.
    ///
    /// # Arguments
    ///
    /// * `path` - Path where the keyfile will be saved
    pub fn save_unprotected(&self, path: &Path) -> Result<()> {
        let mut data = Vec::with_capacity(UNPROTECTED_SIZE);

        // Header
        data.extend_from_slice(KEYFILE_MAGIC);
        data.push(KEYFILE_VERSION);
        data.push(ALGORITHM_MLKEM1024);
        data.push(0); // Not protected

        // Encapsulation key (public)
        data.extend_from_slice(self.keypair.encapsulation_key());

        // Decapsulation key (private, unprotected)
        data.extend_from_slice(self.keypair.decapsulation_key());

        // Write atomically
        crate::storage::write_file_atomic(path, &data)?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    /// Save the keyfile to disk with password protection.
    ///
    /// The decapsulation key is encrypted using AES-256-GCM with a key
    /// derived from the password via Argon2id.
    ///
    /// # Arguments
    ///
    /// * `path` - Path where the keyfile will be saved
    /// * `password` - Password to protect the keyfile
    pub fn save_protected(&self, path: &Path, password: &str) -> Result<()> {
        // Generate salt and derive key
        let salt = generate_salt_string();
        let salt_str = salt.as_ref();
        let kdf = Argon2Kdf::default();
        let key = kdf.derive_key_with_salt_string(password.as_bytes(), &salt)?;

        // Generate nonce
        let mut nonce = [0u8; NONCE_SIZE];
        SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| CryptorError::Cryptography(format!("RNG error: {}", e)))?;

        // Encrypt the decapsulation key
        let encryptor = AesGcmEncryptor::new();
        let encrypted_dk = encryptor.encrypt(&key, &nonce, self.keypair.decapsulation_key())?;

        // Build the file
        let mut data = Vec::with_capacity(PROTECTED_SIZE);

        // Header
        data.extend_from_slice(KEYFILE_MAGIC);
        data.push(KEYFILE_VERSION);
        data.push(ALGORITHM_MLKEM1024);
        data.push(1); // Protected

        // Encapsulation key (public, unencrypted)
        data.extend_from_slice(self.keypair.encapsulation_key());

        // Salt (22 bytes, padded if needed)
        let salt_bytes = salt_str.as_bytes();
        if salt_bytes.len() != SALT_SIZE {
            return Err(CryptorError::Cryptography(format!(
                "Unexpected salt size: {} (expected {})",
                salt_bytes.len(),
                SALT_SIZE
            )));
        }
        data.extend_from_slice(salt_bytes);

        // Nonce
        data.extend_from_slice(&nonce);

        // Encrypted decapsulation key + auth tag
        data.extend_from_slice(&encrypted_dk);

        // Write atomically
        crate::storage::write_file_atomic(path, &data)?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    /// Load a keyfile from disk.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the keyfile
    /// * `password` - Password if the keyfile is protected (None for unprotected)
    ///
    /// # Returns
    ///
    /// The loaded keyfile, or an error if loading fails.
    pub fn load(path: &Path, password: Option<&str>) -> Result<Self> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len() as usize;

        // Read the entire file
        let mut data = vec![0u8; file_size];
        file.read_exact(&mut data)?;

        // Validate minimum size
        if file_size < HEADER_SIZE {
            return Err(CryptorError::InvalidFormat);
        }

        // Check magic
        if &data[0..8] != KEYFILE_MAGIC {
            return Err(CryptorError::InvalidFormat);
        }

        // Check version
        let version = data[8];
        if version != KEYFILE_VERSION {
            return Err(CryptorError::Cryptography(format!(
                "Unsupported keyfile version: {} (expected {})",
                version, KEYFILE_VERSION
            )));
        }

        // Check algorithm
        let algorithm = data[9];
        if algorithm != ALGORITHM_MLKEM1024 {
            return Err(CryptorError::Cryptography(format!(
                "Unsupported keyfile algorithm: {}",
                algorithm
            )));
        }

        // Check protection flag
        let is_protected = data[10] != 0;

        // Extract encapsulation key
        let ek_start = HEADER_SIZE;
        let ek_end = ek_start + PUBLIC_KEY_SIZE;
        if file_size < ek_end {
            return Err(CryptorError::InvalidFormat);
        }
        let encapsulation_key = &data[ek_start..ek_end];

        // Extract decapsulation key based on protection
        let decapsulation_key = if is_protected {
            // Validate protected file size
            if file_size != PROTECTED_SIZE {
                return Err(CryptorError::Cryptography(format!(
                    "Invalid protected keyfile size: {} (expected {})",
                    file_size, PROTECTED_SIZE
                )));
            }

            // Get password
            let password = password.ok_or_else(|| {
                CryptorError::Cryptography("Keyfile is password-protected".to_string())
            })?;

            // Extract salt
            let salt_start = ek_end;
            let salt_end = salt_start + SALT_SIZE;
            let salt_bytes = &data[salt_start..salt_end];
            let salt_str = std::str::from_utf8(salt_bytes)
                .map_err(|_| CryptorError::Cryptography("Invalid salt encoding".to_string()))?;
            let salt = argon2::password_hash::phc::SaltString::from_b64(salt_str)
                .map_err(|e| CryptorError::PasswordHash(e.to_string()))?;

            // Extract nonce
            let nonce_start = salt_end;
            let nonce_end = nonce_start + NONCE_SIZE;
            let nonce = &data[nonce_start..nonce_end];

            // Extract encrypted dk
            let encrypted_dk = &data[nonce_end..];

            // Derive key and decrypt
            let kdf = Argon2Kdf::default();
            let key = kdf.derive_key_with_salt_string(password.as_bytes(), &salt)?;

            let encryptor = AesGcmEncryptor::new();
            let dk = encryptor.decrypt(&key, nonce, encrypted_dk)?;

            dk.to_vec()
        } else {
            // Validate unprotected file size
            if file_size != UNPROTECTED_SIZE {
                return Err(CryptorError::Cryptography(format!(
                    "Invalid unprotected keyfile size: {} (expected {})",
                    file_size, UNPROTECTED_SIZE
                )));
            }

            // Extract raw dk
            let dk_start = ek_end;
            data[dk_start..].to_vec()
        };

        // Reconstruct keypair
        let keypair = MlKemKeyPair::from_bytes(encapsulation_key, &decapsulation_key)?;

        Ok(Self {
            keypair,
            was_protected: is_protected,
        })
    }

    /// Check if the keyfile was loaded from a password-protected file.
    pub fn was_protected(&self) -> bool {
        self.was_protected
    }

    /// Check if a keyfile at the given path is password-protected.
    ///
    /// This reads only the header to determine protection status without
    /// loading the full keyfile.
    pub fn is_protected(path: &Path) -> Result<bool> {
        let mut file = File::open(path)?;
        let mut header = [0u8; HEADER_SIZE];
        file.read_exact(&mut header)?;

        // Check magic
        if &header[0..8] != KEYFILE_MAGIC {
            return Err(CryptorError::InvalidFormat);
        }

        Ok(header[10] != 0)
    }

    /// Get the underlying keypair reference.
    pub fn keypair(&self) -> &MlKemKeyPair {
        &self.keypair
    }
}

/// Derive a hybrid encryption key combining password and PQC keyfile.
///
/// This function combines:
/// 1. Classical key derivation: Argon2id(password, salt) → 32 bytes
/// 2. PQC shared secret: ML-KEM.Decapsulate(dk, ciphertext) → 32 bytes
/// 3. Final key: HKDF(classical_key || pqc_shared_secret) → 32 bytes
///
/// # Arguments
///
/// * `password` - User password
/// * `salt` - Salt for Argon2id (from volume header)
/// * `keyfile` - PQC keyfile containing decapsulation key
/// * `pqc_ciphertext` - ML-KEM ciphertext (from volume header)
///
/// # Returns
///
/// A 32-byte hybrid key suitable for AES-256-GCM encryption.
pub fn derive_hybrid_key(
    password: &str,
    salt: &argon2::password_hash::phc::SaltString,
    keyfile: &PqcKeyfile,
    pqc_ciphertext: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    // Step 1: Classical key derivation
    let kdf = Argon2Kdf::default();
    let classical_key = kdf.derive_key_with_salt_string(password.as_bytes(), salt)?;

    // Step 2: PQC decapsulation
    let pqc_shared_secret = keyfile.decapsulate(pqc_ciphertext)?;

    // Step 3: Combine using HKDF
    combine_keys_hkdf(&classical_key, &pqc_shared_secret)
}

/// Combine two 32-byte keys using HKDF-SHA256.
///
/// # Arguments
///
/// * `classical_key` - Key from password derivation
/// * `pqc_key` - Key from ML-KEM decapsulation
///
/// # Returns
///
/// A 32-byte combined key.
pub fn combine_keys_hkdf(
    classical_key: &[u8; 32],
    pqc_key: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    // Concatenate the input keys
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(classical_key);
    ikm[32..].copy_from_slice(pqc_key);

    // HKDF with domain separation
    let hk = Hkdf::<Sha256>::new(Some(b"tesseract-hybrid-v1"), ikm.as_ref());

    let mut output = Zeroizing::new([0u8; 32]);
    hk.expand(b"encryption-key", output.as_mut())
        .map_err(|_| CryptorError::KeyDerivation("HKDF expansion failed".to_string()))?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pqc::CIPHERTEXT_SIZE;
    use tempfile::tempdir;

    #[test]
    fn test_generate_keyfile() {
        let keyfile = PqcKeyfile::generate();
        assert_eq!(keyfile.encapsulation_key().len(), PUBLIC_KEY_SIZE);
        assert_eq!(keyfile.decapsulation_key().len(), SECRET_KEY_SIZE);
    }

    #[test]
    fn test_encapsulate_decapsulate_roundtrip() {
        let keyfile = PqcKeyfile::generate();

        let (ciphertext, shared_secret1) = keyfile.encapsulate().unwrap();
        assert_eq!(ciphertext.len(), CIPHERTEXT_SIZE);

        let shared_secret2 = keyfile.decapsulate(&ciphertext).unwrap();
        assert_eq!(*shared_secret1, *shared_secret2);
    }

    #[test]
    fn test_save_load_unprotected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.tkf");

        let keyfile1 = PqcKeyfile::generate();
        keyfile1.save_unprotected(&path).unwrap();

        let keyfile2 = PqcKeyfile::load(&path, None).unwrap();
        assert!(!keyfile2.was_protected());
        assert_eq!(keyfile1.encapsulation_key(), keyfile2.encapsulation_key());
        assert_eq!(keyfile1.decapsulation_key(), keyfile2.decapsulation_key());
    }

    #[test]
    fn test_save_load_protected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.tkf");
        let password = "TestPassword123!";

        let keyfile1 = PqcKeyfile::generate();
        keyfile1.save_protected(&path, password).unwrap();

        // Should fail without password
        let result = PqcKeyfile::load(&path, None);
        assert!(result.is_err());

        // Should fail with wrong password
        let result = PqcKeyfile::load(&path, Some("WrongPassword!"));
        assert!(result.is_err());

        // Should succeed with correct password
        let keyfile2 = PqcKeyfile::load(&path, Some(password)).unwrap();
        assert!(keyfile2.was_protected());
        assert_eq!(keyfile1.encapsulation_key(), keyfile2.encapsulation_key());
        assert_eq!(keyfile1.decapsulation_key(), keyfile2.decapsulation_key());
    }

    #[test]
    fn test_is_protected() {
        let dir = tempdir().unwrap();

        let unprotected_path = dir.path().join("unprotected.tkf");
        let protected_path = dir.path().join("protected.tkf");

        let keyfile = PqcKeyfile::generate();
        keyfile.save_unprotected(&unprotected_path).unwrap();
        keyfile.save_protected(&protected_path, "password").unwrap();

        assert!(!PqcKeyfile::is_protected(&unprotected_path).unwrap());
        assert!(PqcKeyfile::is_protected(&protected_path).unwrap());
    }

    #[test]
    fn test_invalid_magic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("invalid.tkf");

        std::fs::write(&path, b"INVALID!").unwrap();

        let result = PqcKeyfile::load(&path, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_combine_keys_hkdf() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let combined = combine_keys_hkdf(&key1, &key2).unwrap();
        assert_eq!(combined.len(), 32);

        // Same inputs should produce same output
        let combined2 = combine_keys_hkdf(&key1, &key2).unwrap();
        assert_eq!(*combined, *combined2);

        // Different inputs should produce different output
        let key3 = [3u8; 32];
        let combined3 = combine_keys_hkdf(&key1, &key3).unwrap();
        assert_ne!(*combined, *combined3);
    }

    #[test]
    fn test_derive_hybrid_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.tkf");

        let keyfile = PqcKeyfile::generate();
        keyfile.save_unprotected(&path).unwrap();

        // Simulate encryption: encapsulate and store ciphertext
        let (ciphertext, _) = keyfile.encapsulate().unwrap();

        // Derive hybrid key
        let salt = generate_salt_string();
        let loaded_keyfile = PqcKeyfile::load(&path, None).unwrap();
        let key = derive_hybrid_key("TestPassword123!", &salt, &loaded_keyfile, &ciphertext);

        assert!(key.is_ok());
        assert_eq!(key.unwrap().len(), 32);
    }

    #[test]
    fn test_different_keyfiles_different_shared_secrets() {
        let keyfile1 = PqcKeyfile::generate();
        let keyfile2 = PqcKeyfile::generate();

        let (_, ss1) = keyfile1.encapsulate().unwrap();
        let (_, ss2) = keyfile2.encapsulate().unwrap();

        // Different keyfiles should produce different shared secrets
        assert_ne!(*ss1, *ss2);
    }

    #[test]
    fn test_cross_keyfile_decapsulation_fails() {
        let keyfile1 = PqcKeyfile::generate();
        let keyfile2 = PqcKeyfile::generate();

        // Encapsulate with keyfile1
        let (ciphertext, ss1) = keyfile1.encapsulate().unwrap();

        // Decapsulate with keyfile2 (wrong key)
        let ss2 = keyfile2.decapsulate(&ciphertext).unwrap();

        // Shared secrets should NOT match (this is expected ML-KEM behavior)
        assert_ne!(*ss1, *ss2);
    }

    #[test]
    fn test_protected_keyfile_sizes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("protected.tkf");

        let keyfile = PqcKeyfile::generate();
        keyfile.save_protected(&path, "password").unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.len() as usize, PROTECTED_SIZE);
    }

    #[test]
    fn test_unprotected_keyfile_sizes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unprotected.tkf");

        let keyfile = PqcKeyfile::generate();
        keyfile.save_unprotected(&path).unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.len() as usize, UNPROTECTED_SIZE);
    }
}
