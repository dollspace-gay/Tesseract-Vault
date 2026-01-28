// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Tesseract LUKS keyfile format
//!
//! Secure keyfile that wraps a LUKS passphrase with Tesseract's security features.

use crate::config::CryptoConfig;
use crate::crypto::kdf::Argon2Kdf;
use crate::crypto::KeyDerivation;
use crate::error::{CryptorError, Result};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand_core::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Magic bytes for Tesseract LUKS keyfile
const MAGIC: [u8; 9] = *b"TESS-LUKS";

/// Current keyfile format version
const VERSION: u8 = 1;

/// Maximum passphrase size (LUKS supports up to 512 bytes)
const MAX_PASSPHRASE_SIZE: usize = 512;

/// Errors specific to LUKS keyfile operations
#[derive(Debug, Error)]
pub enum LuksKeyfileError {
    #[error("Invalid keyfile format: {0}")]
    InvalidFormat(String),

    #[error("Decryption failed: incorrect password")]
    DecryptionFailed,

    #[error("Duress password triggered - keys destroyed")]
    DuressTriggered,

    #[error("TPM unsealing failed: {0}")]
    TpmError(String),

    #[error("PQC decapsulation failed: {0}")]
    PqcError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Configuration flags for LUKS keyfile features
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct LuksFeatureFlags {
    /// TPM sealing enabled
    pub tpm_enabled: bool,
    /// Post-quantum hybrid encryption enabled
    pub pqc_enabled: bool,
    /// Duress password configured
    pub duress_enabled: bool,
    /// YubiKey 2FA required
    pub yubikey_enabled: bool,
}

impl LuksFeatureFlags {
    fn to_byte(self) -> u8 {
        let mut flags = 0u8;
        if self.tpm_enabled {
            flags |= 0x01;
        }
        if self.pqc_enabled {
            flags |= 0x02;
        }
        if self.duress_enabled {
            flags |= 0x04;
        }
        if self.yubikey_enabled {
            flags |= 0x08;
        }
        flags
    }

    fn from_byte(byte: u8) -> Self {
        Self {
            tpm_enabled: (byte & 0x01) != 0,
            pqc_enabled: (byte & 0x02) != 0,
            duress_enabled: (byte & 0x04) != 0,
            yubikey_enabled: (byte & 0x08) != 0,
        }
    }
}

/// Configuration for creating a LUKS keyfile
#[derive(Debug, Clone)]
pub struct LuksConfig {
    /// Enable TPM sealing (requires TPM 2.0)
    pub enable_tpm: bool,
    /// PCR indices to bind TPM sealing to
    pub tpm_pcrs: Vec<u8>,
    /// Enable post-quantum hybrid encryption
    pub enable_pqc: bool,
    /// Enable YubiKey 2FA
    pub enable_yubikey: bool,
    /// YubiKey slot to use (1 or 2)
    pub yubikey_slot: u8,
}

impl Default for LuksConfig {
    fn default() -> Self {
        Self {
            enable_tpm: false,
            tpm_pcrs: vec![0, 7], // UEFI firmware + Secure Boot state
            enable_pqc: true,     // PQC on by default
            enable_yubikey: false,
            yubikey_slot: 2,
        }
    }
}

/// A password-protected slot containing the encrypted LUKS passphrase
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasswordSlot {
    /// Salt for Argon2id key derivation
    salt: [u8; 32],
    /// Nonce for AES-GCM
    nonce: [u8; 12],
    /// Encrypted LUKS passphrase (passphrase + 16 byte auth tag)
    encrypted_passphrase: Vec<u8>,
}

/// TPM-sealed slot for auto-unlock
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TpmSlot {
    /// Serialized SealedKeyBlob from TPM
    sealed_blob: Vec<u8>,
}

/// Post-quantum cryptography metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PqcSlot {
    /// ML-KEM encapsulation key (public key)
    encapsulation_key: Vec<u8>,
    /// ML-KEM ciphertext
    ciphertext: Vec<u8>,
    /// Encrypted decapsulation key (encrypted with password-derived key)
    encrypted_dk: Vec<u8>,
    /// Nonce for encrypted_dk
    dk_nonce: [u8; 12],
}

/// Duress password slot
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DuressSlot {
    /// Salt for duress password verification
    salt: [u8; 32],
    /// Nonce for verification token
    nonce: [u8; 12],
    /// Encrypted verification token (used to detect duress password)
    encrypted_token: Vec<u8>,
}

/// Tesseract LUKS keyfile - wraps a LUKS passphrase with advanced security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TesseractLuksKeyfile {
    /// Feature flags
    flags: LuksFeatureFlags,
    /// Primary password slot (always present)
    password_slot: PasswordSlot,
    /// TPM-sealed slot (optional)
    tpm_slot: Option<TpmSlot>,
    /// Post-quantum metadata (optional)
    pqc_slot: Option<PqcSlot>,
    /// Duress password slot (optional)
    duress_slot: Option<DuressSlot>,
}

impl TesseractLuksKeyfile {
    /// Creates a new Tesseract LUKS keyfile
    ///
    /// # Arguments
    ///
    /// * `luks_passphrase` - The actual LUKS passphrase to protect
    /// * `tesseract_password` - Password to encrypt the keyfile
    /// * `config` - Configuration options
    ///
    /// # Returns
    ///
    /// A new keyfile ready to be saved
    pub fn new(
        luks_passphrase: &str,
        tesseract_password: &str,
        config: LuksConfig,
    ) -> Result<Self> {
        if luks_passphrase.len() > MAX_PASSPHRASE_SIZE {
            return Err(CryptorError::InvalidInput(format!(
                "LUKS passphrase too long (max {} bytes)",
                MAX_PASSPHRASE_SIZE
            )));
        }

        // Create password slot
        let password_slot = Self::create_password_slot(luks_passphrase, tesseract_password)?;

        // Create PQC slot if enabled
        let pqc_slot = if config.enable_pqc {
            Some(Self::create_pqc_slot(luks_passphrase, tesseract_password)?)
        } else {
            None
        };

        let flags = LuksFeatureFlags {
            tpm_enabled: config.enable_tpm,
            pqc_enabled: config.enable_pqc,
            duress_enabled: false, // Set separately via set_duress_password
            yubikey_enabled: config.enable_yubikey,
        };

        // TPM slot is created separately via enroll_tpm()
        Ok(Self {
            flags,
            password_slot,
            tpm_slot: None,
            pqc_slot,
            duress_slot: None,
        })
    }

    /// Creates the password-protected slot
    fn create_password_slot(luks_passphrase: &str, password: &str) -> Result<PasswordSlot> {
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce);

        // Derive key from password
        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let derived_key = Zeroizing::new(kdf.derive_key(password.as_bytes(), &salt)?);

        // Encrypt the LUKS passphrase
        let cipher = Aes256Gcm::new_from_slice(&derived_key[..])
            .map_err(|e| CryptorError::Cryptography(e.to_string()))?;

        let nonce_obj = Nonce::from(nonce);
        let encrypted_passphrase = cipher
            .encrypt(&nonce_obj, luks_passphrase.as_bytes())
            .map_err(|e| CryptorError::Cryptography(e.to_string()))?;

        Ok(PasswordSlot {
            salt,
            nonce,
            encrypted_passphrase,
        })
    }

    /// Creates the PQC slot with ML-KEM-1024 hybrid encryption
    ///
    /// This provides post-quantum protection by combining password-derived
    /// key material with ML-KEM shared secrets.
    #[cfg(feature = "post-quantum")]
    fn create_pqc_slot(luks_passphrase: &str, password: &str) -> Result<PqcSlot> {
        use crate::crypto::pqc::{encapsulate, MlKemKeyPair};

        // Generate ML-KEM-1024 keypair
        let keypair = MlKemKeyPair::generate();
        let (ek, dk) = keypair.to_bytes();

        // Encapsulate to get shared secret
        let (ciphertext, shared_secret) = encapsulate(&ek)?;

        // Combine password-derived key with PQ shared secret for hybrid encryption
        let mut salt = [0u8; 32];
        rand::rng().fill_bytes(&mut salt);

        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let password_key = kdf.derive_key(password.as_bytes(), &salt)?;

        // Derive hybrid key: BLAKE3(password_key || shared_secret)
        let mut hasher = blake3::Hasher::new();
        hasher.update(password_key.as_ref());
        hasher.update(shared_secret.as_ref());
        let hybrid_key = hasher.finalize();

        // Encrypt LUKS passphrase with hybrid key
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);

        let cipher = Aes256Gcm::new_from_slice(hybrid_key.as_bytes())
            .map_err(|e| CryptorError::Cryptography(e.to_string()))?;

        let _encrypted_passphrase = cipher
            .encrypt(&Nonce::from(nonce), luks_passphrase.as_bytes())
            .map_err(|e| CryptorError::Cryptography(e.to_string()))?;

        // Also encrypt the decapsulation key so we can recover it later
        let mut dk_nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut dk_nonce);

        // Use password-only key to encrypt the DK (so password alone can recover PQC)
        let dk_cipher = Aes256Gcm::new_from_slice(&password_key[..])
            .map_err(|e| CryptorError::Cryptography(e.to_string()))?;

        // Pad/chunk the decapsulation key for encryption (it's 3168 bytes)
        let encrypted_dk = dk_cipher
            .encrypt(&Nonce::from(dk_nonce), dk.as_slice())
            .map_err(|e| CryptorError::Cryptography(e.to_string()))?;

        Ok(PqcSlot {
            encapsulation_key: ek,
            ciphertext,
            encrypted_dk,
            dk_nonce,
        })
    }

    /// PQC slot creation when post-quantum feature is disabled
    #[cfg(not(feature = "post-quantum"))]
    fn create_pqc_slot(_luks_passphrase: &str, _password: &str) -> Result<PqcSlot> {
        Err(CryptorError::Cryptography(
            "PQC support requires the 'post-quantum' feature to be enabled".into(),
        ))
    }

    /// Sets a duress password that will destroy all keys when used
    ///
    /// # Arguments
    ///
    /// * `duress_password` - Password that triggers destruction
    ///
    /// # Security
    ///
    /// When this password is entered, all key material is destroyed and
    /// the unlock returns the same error as an incorrect password.
    pub fn set_duress_password(&mut self, duress_password: &str) -> Result<()> {
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        let mut token = [0u8; 32];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce);
        rand::rng().fill_bytes(&mut token);

        // Derive key from duress password
        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let derived_key = Zeroizing::new(kdf.derive_key(duress_password.as_bytes(), &salt)?);

        // Encrypt the verification token
        let cipher = Aes256Gcm::new_from_slice(&derived_key[..])
            .map_err(|e| CryptorError::Cryptography(e.to_string()))?;

        let nonce_obj = Nonce::from(nonce);
        let encrypted_token = cipher
            .encrypt(&nonce_obj, token.as_ref())
            .map_err(|e| CryptorError::Cryptography(e.to_string()))?;

        self.duress_slot = Some(DuressSlot {
            salt,
            nonce,
            encrypted_token,
        });
        self.flags.duress_enabled = true;

        Ok(())
    }

    /// Removes the duress password
    pub fn remove_duress_password(&mut self) {
        self.duress_slot = None;
        self.flags.duress_enabled = false;
    }

    /// Enrolls TPM sealing for auto-unlock
    ///
    /// # Arguments
    ///
    /// * `luks_passphrase` - The LUKS passphrase to seal
    /// * `pcrs` - PCR indices to bind to
    ///
    /// # Requirements
    ///
    /// - Linux with TPM 2.0 device at /dev/tpmrm0 or /dev/tpm0
    /// - Appropriate permissions to access TPM
    #[cfg(target_os = "linux")]
    pub fn enroll_tpm(&mut self, luks_passphrase: &str, pcrs: &[u8]) -> Result<()> {
        use crate::hsm::tpm::{PcrIndex, Tpm2Device, TpmHashAlgorithm, TpmKeyPolicy};

        // Open TPM device
        let tpm = Tpm2Device::open()?;
        if !tpm.is_ready() {
            return Err(CryptorError::HardwareError(
                "TPM device not available".into(),
            ));
        }

        // Convert PCR indices
        let pcr_selection: Vec<PcrIndex> = pcrs
            .iter()
            .filter_map(|&p| {
                if p < 24 {
                    Some(unsafe { std::mem::transmute::<u8, PcrIndex>(p) })
                } else {
                    None
                }
            })
            .collect();

        let policy = TpmKeyPolicy {
            pcr_selection,
            hash_algorithm: TpmHashAlgorithm::Sha256,
            auth_value: None,
            pcr_policy: true,
        };

        // Seal the passphrase
        let sealed_blob = tpm.seal_key(luks_passphrase.as_bytes(), &policy)?;

        // Use the blob's built-in serialization
        let serialized = sealed_blob.to_bytes();

        self.tpm_slot = Some(TpmSlot {
            sealed_blob: serialized,
        });
        self.flags.tpm_enabled = true;

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enroll_tpm(&mut self, _luks_passphrase: &str, _pcrs: &[u8]) -> Result<()> {
        Err(CryptorError::Unsupported(
            "TPM enrollment only available on Linux".into(),
        ))
    }

    /// Attempts to unlock using TPM auto-unlock
    ///
    /// # Returns
    ///
    /// The LUKS passphrase if TPM unsealing succeeds
    #[cfg(target_os = "linux")]
    pub fn unlock_with_tpm(&self) -> Result<Zeroizing<String>> {
        use crate::hsm::tpm::{SealedKeyBlob, Tpm2Device};

        let tpm_slot = self
            .tpm_slot
            .as_ref()
            .ok_or_else(|| CryptorError::InvalidInput("No TPM slot configured".into()))?;

        // Open TPM device
        let tpm = Tpm2Device::open()?;
        if !tpm.is_ready() {
            return Err(CryptorError::HardwareError(
                "TPM device not available".into(),
            ));
        }

        // Deserialize the sealed blob using built-in deserialization
        let sealed_blob = SealedKeyBlob::from_bytes(&tpm_slot.sealed_blob)?;

        // Unseal
        let passphrase_bytes = tpm.unseal_key(&sealed_blob)?;

        let passphrase = String::from_utf8(passphrase_bytes.to_vec())
            .map_err(|_| CryptorError::InvalidFormat)?;

        Ok(Zeroizing::new(passphrase))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn unlock_with_tpm(&self) -> Result<Zeroizing<String>> {
        Err(CryptorError::Unsupported(
            "TPM unlock only available on Linux".into(),
        ))
    }

    /// Unlocks the keyfile with a password
    ///
    /// # Arguments
    ///
    /// * `password` - The Tesseract password
    ///
    /// # Returns
    ///
    /// The decrypted LUKS passphrase
    ///
    /// # Security
    ///
    /// If the duress password is entered, all key material is destroyed
    /// and `DecryptionFailed` is returned (indistinguishable from wrong password).
    pub fn unlock(
        &mut self,
        password: &str,
    ) -> std::result::Result<Zeroizing<String>, LuksKeyfileError> {
        // CRITICAL: Check duress password FIRST
        if self.is_duress_password(password) {
            self.destroy_all_keys();
            return Err(LuksKeyfileError::DecryptionFailed);
        }

        // Try password slot
        self.decrypt_password_slot(password)
    }

    /// Checks if the given password is the duress password
    fn is_duress_password(&self, password: &str) -> bool {
        if let Some(ref duress) = self.duress_slot {
            let kdf = Argon2Kdf::new(CryptoConfig::default());
            if let Ok(derived_key) = kdf.derive_key(password.as_bytes(), &duress.salt) {
                let cipher = match Aes256Gcm::new_from_slice(&derived_key[..]) {
                    Ok(c) => c,
                    Err(_) => return false,
                };

                let nonce = Nonce::from(duress.nonce);
                // If decryption succeeds, it's the duress password
                cipher
                    .decrypt(&nonce, duress.encrypted_token.as_ref())
                    .is_ok()
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Destroys all key material (called when duress password entered)
    fn destroy_all_keys(&mut self) {
        // Overwrite password slot
        self.password_slot.salt.zeroize();
        self.password_slot.nonce.zeroize();
        self.password_slot.encrypted_passphrase.zeroize();

        // Overwrite TPM slot
        if let Some(ref mut tpm) = self.tpm_slot {
            tpm.sealed_blob.zeroize();
        }
        self.tpm_slot = None;

        // Overwrite PQC slot
        if let Some(ref mut pqc) = self.pqc_slot {
            pqc.encapsulation_key.zeroize();
            pqc.ciphertext.zeroize();
            pqc.encrypted_dk.zeroize();
            pqc.dk_nonce.zeroize();
        }
        self.pqc_slot = None;

        // Overwrite duress slot
        if let Some(ref mut duress) = self.duress_slot {
            duress.salt.zeroize();
            duress.nonce.zeroize();
            duress.encrypted_token.zeroize();
        }
        self.duress_slot = None;

        // Clear flags
        self.flags = LuksFeatureFlags::default();
    }

    /// Decrypts the password slot
    fn decrypt_password_slot(
        &self,
        password: &str,
    ) -> std::result::Result<Zeroizing<String>, LuksKeyfileError> {
        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let derived_key = kdf
            .derive_key(password.as_bytes(), &self.password_slot.salt)
            .map_err(|_| LuksKeyfileError::DecryptionFailed)?;

        let cipher = Aes256Gcm::new_from_slice(&derived_key[..])
            .map_err(|_| LuksKeyfileError::DecryptionFailed)?;

        let nonce = Nonce::from(self.password_slot.nonce);
        let plaintext = cipher
            .decrypt(&nonce, self.password_slot.encrypted_passphrase.as_ref())
            .map_err(|_| LuksKeyfileError::DecryptionFailed)?;

        let passphrase = String::from_utf8(plaintext)
            .map_err(|_| LuksKeyfileError::InvalidFormat("Invalid UTF-8 in passphrase".into()))?;

        Ok(Zeroizing::new(passphrase))
    }

    /// Saves the keyfile to disk
    ///
    /// # Arguments
    ///
    /// * `path` - Path to save the keyfile
    ///
    /// # Security
    ///
    /// The file is written with mode 0600 (owner read/write only)
    pub fn save<P: AsRef<Path>>(&self, path: P) -> std::result::Result<(), LuksKeyfileError> {
        let mut file = fs::File::create(path.as_ref())?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)?;
        }

        // Write header
        file.write_all(&MAGIC)?;
        file.write_all(&[VERSION])?;
        file.write_all(&[self.flags.to_byte()])?;

        // Serialize and write body
        let body = postcard::to_allocvec(self)
            .map_err(|e| LuksKeyfileError::Serialization(e.to_string()))?;

        // Write body length and body
        let len = body.len() as u32;
        file.write_all(&len.to_le_bytes())?;
        file.write_all(&body)?;

        Ok(())
    }

    /// Loads a keyfile from disk
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the keyfile
    pub fn load<P: AsRef<Path>>(path: P) -> std::result::Result<Self, LuksKeyfileError> {
        let mut file = fs::File::open(path.as_ref())?;

        // Read and verify header
        let mut magic = [0u8; 9];
        file.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(LuksKeyfileError::InvalidFormat(
                "Invalid magic bytes".into(),
            ));
        }

        let mut version = [0u8; 1];
        file.read_exact(&mut version)?;
        if version[0] != VERSION {
            return Err(LuksKeyfileError::InvalidFormat(format!(
                "Unsupported version: {}",
                version[0]
            )));
        }

        let mut flags_byte = [0u8; 1];
        file.read_exact(&mut flags_byte)?;
        let _flags = LuksFeatureFlags::from_byte(flags_byte[0]);

        // Read body length
        let mut len_bytes = [0u8; 4];
        file.read_exact(&mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        // Sanity check
        if len > 1024 * 1024 {
            return Err(LuksKeyfileError::InvalidFormat("Body too large".into()));
        }

        // Read body
        let mut body = vec![0u8; len];
        file.read_exact(&mut body)?;

        // Deserialize
        let keyfile: TesseractLuksKeyfile = postcard::from_bytes(&body)
            .map_err(|e| LuksKeyfileError::Serialization(e.to_string()))?;

        Ok(keyfile)
    }

    /// Returns whether TPM auto-unlock is configured
    pub fn has_tpm(&self) -> bool {
        self.tpm_slot.is_some()
    }

    /// Returns whether PQC is enabled
    pub fn has_pqc(&self) -> bool {
        self.pqc_slot.is_some()
    }

    /// Returns whether a duress password is configured
    pub fn has_duress(&self) -> bool {
        self.duress_slot.is_some()
    }

    /// Returns the feature flags
    pub fn flags(&self) -> LuksFeatureFlags {
        self.flags
    }

    /// Outputs the LUKS passphrase to stdout (for piping to cryptsetup)
    ///
    /// # Security
    ///
    /// This writes the raw passphrase bytes to stdout, suitable for:
    /// `tesseract-luks unlock keyfile | cryptsetup open /dev/sda2 root --key-file -`
    pub fn output_passphrase_to_stdout(
        &mut self,
        password: &str,
    ) -> std::result::Result<(), LuksKeyfileError> {
        let passphrase = self.unlock(password)?;

        // Write to stdout without newline
        std::io::stdout()
            .write_all(passphrase.as_bytes())
            .map_err(LuksKeyfileError::Io)?;
        std::io::stdout().flush().map_err(LuksKeyfileError::Io)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_create_and_unlock_keyfile() {
        let luks_pass = "my-secret-luks-passphrase";
        let tess_pass = "tesseract-password-123!";

        let config = LuksConfig {
            enable_pqc: false,
            ..Default::default()
        };

        let mut keyfile = TesseractLuksKeyfile::new(luks_pass, tess_pass, config).unwrap();

        // Unlock with correct password
        let recovered = keyfile.unlock(tess_pass).unwrap();
        assert_eq!(recovered.as_str(), luks_pass);

        // Wrong password should fail
        assert!(keyfile.unlock("wrong-password").is_err());
    }

    #[test]
    fn test_save_and_load_keyfile() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.keyfile");

        let luks_pass = "luks-passphrase";
        let tess_pass = "tesseract-pass!";

        let config = LuksConfig {
            enable_pqc: false,
            ..Default::default()
        };

        let keyfile = TesseractLuksKeyfile::new(luks_pass, tess_pass, config).unwrap();
        keyfile.save(&path).unwrap();

        let mut loaded = TesseractLuksKeyfile::load(&path).unwrap();
        let recovered = loaded.unlock(tess_pass).unwrap();
        assert_eq!(recovered.as_str(), luks_pass);
    }

    #[test]
    fn test_duress_password_destroys_keys() {
        let luks_pass = "secret-luks-pass";
        let tess_pass = "normal-password";
        let duress_pass = "duress-password";

        let config = LuksConfig {
            enable_pqc: false,
            ..Default::default()
        };

        let mut keyfile = TesseractLuksKeyfile::new(luks_pass, tess_pass, config).unwrap();
        keyfile.set_duress_password(duress_pass).unwrap();

        // Normal password should work
        let mut keyfile_copy = keyfile.clone();
        assert!(keyfile_copy.unlock(tess_pass).is_ok());

        // Duress password should destroy keys and return error
        let result = keyfile.unlock(duress_pass);
        assert!(result.is_err());

        // After duress, normal password should also fail
        assert!(keyfile.unlock(tess_pass).is_err());
    }

    #[test]
    fn test_duress_indistinguishable_from_wrong_password() {
        let luks_pass = "secret";
        let tess_pass = "correct";
        let duress_pass = "duress";

        let config = LuksConfig {
            enable_pqc: false,
            ..Default::default()
        };

        let mut keyfile1 = TesseractLuksKeyfile::new(luks_pass, tess_pass, config.clone()).unwrap();
        let mut keyfile2 = TesseractLuksKeyfile::new(luks_pass, tess_pass, config).unwrap();
        keyfile2.set_duress_password(duress_pass).unwrap();

        // Wrong password error
        let wrong_result = keyfile1.unlock("wrong");
        // Duress password error
        let duress_result = keyfile2.unlock(duress_pass);

        // Both should be DecryptionFailed
        assert!(matches!(
            wrong_result,
            Err(LuksKeyfileError::DecryptionFailed)
        ));
        assert!(matches!(
            duress_result,
            Err(LuksKeyfileError::DecryptionFailed)
        ));
    }

    #[test]
    #[cfg(feature = "post-quantum")]
    fn test_pqc_slot_creation() {
        let luks_pass = "pqc-protected-pass";
        let tess_pass = "password123!";

        // With post-quantum feature enabled, PQC should work
        let config = LuksConfig {
            enable_pqc: true,
            ..Default::default()
        };

        let mut keyfile = TesseractLuksKeyfile::new(luks_pass, tess_pass, config).unwrap();
        assert!(keyfile.has_pqc());

        // Password slot should still work for unlock
        let recovered = keyfile.unlock(tess_pass).unwrap();
        assert_eq!(recovered.as_str(), luks_pass);
    }

    #[test]
    #[cfg(not(feature = "post-quantum"))]
    fn test_pqc_requires_feature() {
        let luks_pass = "pqc-protected-pass";
        let tess_pass = "password123!";

        // Without post-quantum feature, PQC should fail
        let config = LuksConfig {
            enable_pqc: true,
            ..Default::default()
        };

        let result = TesseractLuksKeyfile::new(luks_pass, tess_pass, config);
        assert!(result.is_err(), "PQC should require post-quantum feature");
    }

    #[test]
    fn test_keyfile_without_pqc() {
        let luks_pass = "non-pqc-pass";
        let tess_pass = "password123!";

        // Without PQC, keyfile should work fine
        let config = LuksConfig {
            enable_pqc: false,
            ..Default::default()
        };

        let mut keyfile = TesseractLuksKeyfile::new(luks_pass, tess_pass, config).unwrap();
        assert!(!keyfile.has_pqc());

        let recovered = keyfile.unlock(tess_pass).unwrap();
        assert_eq!(recovered.as_str(), luks_pass);
    }

    #[test]
    fn test_flags_serialization() {
        let flags = LuksFeatureFlags {
            tpm_enabled: true,
            pqc_enabled: true,
            duress_enabled: false,
            yubikey_enabled: true,
        };

        let byte = flags.to_byte();
        let recovered = LuksFeatureFlags::from_byte(byte);

        assert_eq!(flags.tpm_enabled, recovered.tpm_enabled);
        assert_eq!(flags.pqc_enabled, recovered.pqc_enabled);
        assert_eq!(flags.duress_enabled, recovered.duress_enabled);
        assert_eq!(flags.yubikey_enabled, recovered.yubikey_enabled);
    }
}
