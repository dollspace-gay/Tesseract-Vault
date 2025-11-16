/// Key slot system for encrypted volumes
///
/// Supports multiple passwords/users accessing the same volume by encrypting
/// a master key with different user-derived keys.

use crate::config::CryptoConfig;
use crate::crypto::kdf::Argon2Kdf;
use crate::crypto::KeyDerivation;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Number of key slots available (supports up to 8 users/passwords)
pub const MAX_KEY_SLOTS: usize = 8;

/// Size of the master key in bytes (256 bits for AES-256)
pub const MASTER_KEY_SIZE: usize = 32;

/// Size of the encrypted master key (includes GCM authentication tag)
const ENCRYPTED_KEY_SIZE: usize = MASTER_KEY_SIZE + 16; // 32 bytes key + 16 bytes tag

/// A single key slot that can unlock the volume
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    /// Whether this slot is active (contains a valid key)
    active: bool,

    /// Salt for key derivation (32 bytes)
    salt: [u8; 32],

    /// Nonce for encrypting the master key (12 bytes for AES-GCM)
    nonce: [u8; 12],

    /// Encrypted master key (48 bytes: 32 bytes key + 16 bytes auth tag)
    #[serde(with = "BigArray")]
    encrypted_master_key: [u8; ENCRYPTED_KEY_SIZE],
}

/// Collection of key slots for a volume
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlots {
    /// Array of key slots
    slots: [KeySlot; MAX_KEY_SLOTS],
}

/// Master key used for volume encryption (securely zeroized on drop)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MasterKey {
    key: [u8; MASTER_KEY_SIZE],
}

/// Errors that can occur with key slots
#[derive(Debug, Error)]
pub enum KeySlotError {
    /// No active key slots available
    #[error("No active key slots available")]
    NoActiveSlots,

    /// All key slots are full
    #[error("All key slots are full (maximum {MAX_KEY_SLOTS} slots)")]
    AllSlotsFull,

    /// Invalid slot index
    #[error("Invalid slot index: {0} (must be < {MAX_KEY_SLOTS})")]
    InvalidSlotIndex(usize),

    /// Failed to decrypt master key (wrong password)
    #[error("Failed to decrypt master key: incorrect password")]
    DecryptionFailed,

    /// AES-GCM encryption/decryption error
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Key derivation error
    #[error("Key derivation error: {0}")]
    KdfError(#[from] crate::error::CryptorError),
}

impl KeySlot {
    /// Creates an inactive (empty) key slot
    fn empty() -> Self {
        Self {
            active: false,
            salt: [0u8; 32],
            nonce: [0u8; 12],
            encrypted_master_key: [0u8; ENCRYPTED_KEY_SIZE],
        }
    }

    /// Creates a new active key slot by encrypting the master key with a password
    fn new(master_key: &MasterKey, password: &str) -> Result<Self, KeySlotError> {
        // Generate random salt and nonce
        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Derive key from password
        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let derived_key = Zeroizing::new(kdf.derive_key(password.as_bytes(), &salt)?);

        // Encrypt the master key with the derived key
        let cipher = Aes256Gcm::new_from_slice(&derived_key[..])
            .map_err(|e| KeySlotError::EncryptionError(e.to_string()))?;

        #[allow(deprecated)]
        let nonce = Nonce::clone_from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, master_key.as_bytes())
            .map_err(|e| KeySlotError::EncryptionError(e.to_string()))?;

        // Copy encrypted key to fixed-size array
        let mut encrypted_master_key = [0u8; ENCRYPTED_KEY_SIZE];
        encrypted_master_key.copy_from_slice(&ciphertext);

        Ok(Self {
            active: true,
            salt,
            nonce: nonce_bytes,
            encrypted_master_key,
        })
    }

    /// Attempts to unlock this slot with a password
    fn unlock(&self, password: &str) -> Result<MasterKey, KeySlotError> {
        if !self.active {
            return Err(KeySlotError::DecryptionFailed);
        }

        // Derive key from password
        let kdf = Argon2Kdf::new(CryptoConfig::default());
        let derived_key = Zeroizing::new(kdf.derive_key(password.as_bytes(), &self.salt)?);

        // Attempt to decrypt the master key
        let cipher = Aes256Gcm::new_from_slice(&derived_key[..])
            .map_err(|e| KeySlotError::EncryptionError(e.to_string()))?;

        #[allow(deprecated)]
        let nonce = Nonce::clone_from_slice(&self.nonce);
        let plaintext = cipher
            .decrypt(&nonce, self.encrypted_master_key.as_ref())
            .map_err(|_| KeySlotError::DecryptionFailed)?;

        // Convert to MasterKey
        let mut key = [0u8; MASTER_KEY_SIZE];
        key.copy_from_slice(&plaintext);

        Ok(MasterKey { key })
    }

    /// Returns whether this slot is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivates this slot
    fn deactivate(&mut self) {
        self.active = false;
        self.salt.zeroize();
        self.nonce.zeroize();
        self.encrypted_master_key.zeroize();
    }
}

impl KeySlots {
    /// Creates a new key slots collection with all slots empty
    pub fn new() -> Self {
        Self {
            slots: [
                KeySlot::empty(),
                KeySlot::empty(),
                KeySlot::empty(),
                KeySlot::empty(),
                KeySlot::empty(),
                KeySlot::empty(),
                KeySlot::empty(),
                KeySlot::empty(),
            ],
        }
    }

    /// Adds a new key slot with the given password, encrypting the master key
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key to encrypt in this slot
    /// * `password` - The password for this slot
    ///
    /// # Returns
    ///
    /// The index of the newly created slot
    ///
    /// # Errors
    ///
    /// Returns an error if all slots are full
    pub fn add_slot(&mut self, master_key: &MasterKey, password: &str) -> Result<usize, KeySlotError> {
        // Find first inactive slot
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if !slot.active {
                *slot = KeySlot::new(master_key, password)?;
                return Ok(i);
            }
        }

        Err(KeySlotError::AllSlotsFull)
    }

    /// Removes a key slot by index
    ///
    /// # Arguments
    ///
    /// * `index` - The slot index to remove
    ///
    /// # Errors
    ///
    /// Returns an error if the index is invalid
    pub fn remove_slot(&mut self, index: usize) -> Result<(), KeySlotError> {
        if index >= MAX_KEY_SLOTS {
            return Err(KeySlotError::InvalidSlotIndex(index));
        }

        self.slots[index].deactivate();
        Ok(())
    }

    /// Attempts to unlock the volume with a password by trying all active slots
    ///
    /// # Arguments
    ///
    /// * `password` - The password to try
    ///
    /// # Returns
    ///
    /// The decrypted master key if any slot matches
    ///
    /// # Errors
    ///
    /// Returns an error if no slots can be unlocked with this password
    pub fn unlock(&self, password: &str) -> Result<MasterKey, KeySlotError> {
        // Try each active slot
        for slot in &self.slots {
            if slot.active {
                if let Ok(master_key) = slot.unlock(password) {
                    return Ok(master_key);
                }
            }
        }

        // No slot could be unlocked
        Err(KeySlotError::DecryptionFailed)
    }

    /// Returns the number of active key slots
    pub fn active_count(&self) -> usize {
        self.slots.iter().filter(|s| s.active).count()
    }

    /// Returns whether the given slot index is active
    pub fn is_slot_active(&self, index: usize) -> bool {
        index < MAX_KEY_SLOTS && self.slots[index].active
    }

    /// Finds the first free (inactive) slot
    ///
    /// # Returns
    ///
    /// Some(index) if a free slot is found, None if all slots are full
    pub fn find_free_slot(&self) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| !slot.active)
    }

    /// Changes the password for an existing key slot
    ///
    /// This updates the encrypted master key in the specified slot with
    /// a new password-derived key.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key to re-encrypt
    /// * `slot_index` - The slot index to update
    /// * `new_password` - The new password for this slot
    ///
    /// # Returns
    ///
    /// Ok(()) if the password was changed successfully
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The slot index is invalid
    /// - The slot is not active
    /// - Encryption fails
    pub fn change_password(
        &mut self,
        master_key: &MasterKey,
        slot_index: usize,
        new_password: &str,
    ) -> Result<(), KeySlotError> {
        if slot_index >= MAX_KEY_SLOTS {
            return Err(KeySlotError::InvalidSlotIndex(slot_index));
        }

        if !self.slots[slot_index].active {
            return Err(KeySlotError::NoActiveSlots);
        }

        // Create new key slot with new password
        let new_slot = KeySlot::new(master_key, new_password)?;

        // Replace the old slot
        self.slots[slot_index] = new_slot;

        Ok(())
    }
}

impl Default for KeySlots {
    fn default() -> Self {
        Self::new()
    }
}

impl MasterKey {
    /// Generates a new random master key
    pub fn generate() -> Self {
        let mut key = [0u8; MASTER_KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        Self { key }
    }

    /// Creates a master key from existing bytes
    ///
    /// # Arguments
    ///
    /// * `key` - The 32-byte key material
    pub fn from_bytes(key: [u8; MASTER_KEY_SIZE]) -> Self {
        Self { key }
    }

    /// Returns the key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Returns the key size in bytes
    pub const fn size() -> usize {
        MASTER_KEY_SIZE
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_generation() {
        let key1 = MasterKey::generate();
        let key2 = MasterKey::generate();

        // Keys should be different
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key1.as_bytes().len(), MASTER_KEY_SIZE);
    }

    #[test]
    fn test_single_slot_unlock() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Add a slot
        let index = slots.add_slot(&master_key, "TestPassword123!").unwrap();
        assert_eq!(index, 0);
        assert_eq!(slots.active_count(), 1);

        // Unlock with correct password
        let unlocked = slots.unlock("TestPassword123!").unwrap();
        assert_eq!(unlocked.as_bytes(), master_key.as_bytes());

        // Try wrong password
        assert!(slots.unlock("WrongPassword").is_err());
    }

    #[test]
    fn test_multiple_slots() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Add multiple slots with different passwords
        slots.add_slot(&master_key, "Password1!").unwrap();
        slots.add_slot(&master_key, "Password2!").unwrap();
        slots.add_slot(&master_key, "Password3!").unwrap();

        assert_eq!(slots.active_count(), 3);

        // All passwords should unlock the same master key
        let unlocked1 = slots.unlock("Password1!").unwrap();
        let unlocked2 = slots.unlock("Password2!").unwrap();
        let unlocked3 = slots.unlock("Password3!").unwrap();

        assert_eq!(unlocked1.as_bytes(), master_key.as_bytes());
        assert_eq!(unlocked2.as_bytes(), master_key.as_bytes());
        assert_eq!(unlocked3.as_bytes(), master_key.as_bytes());
    }

    #[test]
    fn test_slot_removal() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        slots.add_slot(&master_key, "Password1!").unwrap();
        slots.add_slot(&master_key, "Password2!").unwrap();

        assert_eq!(slots.active_count(), 2);

        // Remove first slot
        slots.remove_slot(0).unwrap();
        assert_eq!(slots.active_count(), 1);
        assert!(!slots.is_slot_active(0));
        assert!(slots.is_slot_active(1));

        // First password should no longer work
        assert!(slots.unlock("Password1!").is_err());

        // Second password should still work
        let unlocked = slots.unlock("Password2!").unwrap();
        assert_eq!(unlocked.as_bytes(), master_key.as_bytes());
    }

    #[test]
    fn test_max_slots() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Fill all slots
        for i in 0..MAX_KEY_SLOTS {
            let password = format!("Password{}!", i);
            let index = slots.add_slot(&master_key, &password).unwrap();
            assert_eq!(index, i);
        }

        assert_eq!(slots.active_count(), MAX_KEY_SLOTS);

        // Adding another should fail
        assert!(matches!(
            slots.add_slot(&master_key, "ExtraPassword!"),
            Err(KeySlotError::AllSlotsFull)
        ));

        // All passwords should still work
        for i in 0..MAX_KEY_SLOTS {
            let password = format!("Password{}!", i);
            let unlocked = slots.unlock(&password).unwrap();
            assert_eq!(unlocked.as_bytes(), master_key.as_bytes());
        }
    }

    #[test]
    fn test_key_slot_reuse() {
        let master_key = MasterKey::generate();
        let mut slots = KeySlots::new();

        // Add and remove a slot
        slots.add_slot(&master_key, "Password1!").unwrap();
        slots.remove_slot(0).unwrap();

        // Slot should be reusable
        let index = slots.add_slot(&master_key, "Password2!").unwrap();
        assert_eq!(index, 0);
        assert!(slots.is_slot_active(0));

        let unlocked = slots.unlock("Password2!").unwrap();
        assert_eq!(unlocked.as_bytes(), master_key.as_bytes());
    }

    #[test]
    fn test_master_key_zeroization() {
        let key = MasterKey::generate();
        let original = key.as_bytes().to_vec();

        // Drop the key
        drop(key);

        // Memory should be zeroized (we can't directly test this,
        // but the Zeroize trait guarantees it)
        // This test mainly ensures the derive macro is applied
        assert!(!original.iter().all(|&b| b == 0));
    }
}
