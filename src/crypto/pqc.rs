// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Post-quantum cryptography module.
//!
//! Provides ML-KEM-1024 (formerly CRYSTALS-Kyber) implementation for
//! quantum-resistant key encapsulation.

use crate::error::{CryptorError, Result};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem1024};
use zeroize::{Zeroize, Zeroizing};

// Import rand 0.9 for ML-KEM compatibility
// ml-kem 0.3.0-pre.2 uses rand_core 0.9.3 which is compatible with rand 0.9
use rand09 as rand_compat;

/// ML-KEM-1024 public key size in bytes.
pub const PUBLIC_KEY_SIZE: usize = 1568;

/// ML-KEM-1024 secret key size in bytes.
pub const SECRET_KEY_SIZE: usize = 3168;

/// ML-KEM-1024 ciphertext size in bytes.
pub const CIPHERTEXT_SIZE: usize = 1568;

/// ML-KEM-1024 shared secret size in bytes.
pub const SHARED_SECRET_SIZE: usize = 32;

/// ML-KEM field prime q = 3329.
/// All polynomial coefficients must be in the range [0, q-1].
const MLKEM_Q: u16 = 3329;

/// Size of the encoded polynomial coefficients in the encapsulation key.
/// ML-KEM-1024 has k=4, with 256 coefficients per polynomial, each encoded as 12 bits.
/// Total: 4 * 256 * 12 / 8 = 1536 bytes
const ENCODED_COEFFICIENTS_SIZE: usize = 1536;

/// Validate an ML-KEM-1024 encapsulation key for ModulusOverflow.
///
/// Per FIPS 203 Section 7.2, implementations should check that all polynomial
/// coefficients in the encapsulation key are in the valid range [0, q-1] where
/// q = 3329. This prevents malicious keys with invalid coefficients.
///
/// # Arguments
///
/// * `encapsulation_key` - The public encapsulation key (1568 bytes)
///
/// # Returns
///
/// `Ok(())` if all coefficients are valid, or an error describing the first
/// invalid coefficient found.
///
/// # Errors
///
/// Returns an error if:
/// - The key size is not exactly 1568 bytes
/// - Any polynomial coefficient is >= 3329 (ModulusOverflow)
pub fn validate_encapsulation_key(encapsulation_key: &[u8]) -> Result<()> {
    if encapsulation_key.len() != PUBLIC_KEY_SIZE {
        return Err(CryptorError::Cryptography(format!(
            "Invalid encapsulation key size: expected {}, got {}",
            PUBLIC_KEY_SIZE,
            encapsulation_key.len()
        )));
    }

    // The encapsulation key structure is: ByteEncode12(t) || ρ
    // where t contains the encoded polynomial coefficients (1536 bytes)
    // and ρ is a 32-byte seed.
    //
    // ByteEncode12 encodes coefficients as 12-bit values packed contiguously.
    // For every 3 bytes, we extract 2 coefficients:
    //   coeff1 = bytes[0] | ((bytes[1] & 0x0f) << 8)
    //   coeff2 = (bytes[1] >> 4) | (bytes[2] << 4)

    let encoded_coeffs = &encapsulation_key[..ENCODED_COEFFICIENTS_SIZE];

    // Process 3 bytes at a time to extract 2 coefficients
    for (chunk_idx, chunk) in encoded_coeffs.chunks_exact(3).enumerate() {
        let b0 = chunk[0] as u16;
        let b1 = chunk[1] as u16;
        let b2 = chunk[2] as u16;

        // First coefficient: low 8 bits from b0, low 4 bits from b1
        let coeff1 = b0 | ((b1 & 0x0f) << 8);
        // Second coefficient: high 4 bits from b1, all 8 bits from b2
        let coeff2 = (b1 >> 4) | (b2 << 4);

        if coeff1 >= MLKEM_Q {
            return Err(CryptorError::Cryptography(format!(
                "ModulusOverflow: coefficient {} at position {} has value {} >= q ({})",
                chunk_idx * 2,
                chunk_idx * 3,
                coeff1,
                MLKEM_Q
            )));
        }

        if coeff2 >= MLKEM_Q {
            return Err(CryptorError::Cryptography(format!(
                "ModulusOverflow: coefficient {} at position {} has value {} >= q ({})",
                chunk_idx * 2 + 1,
                chunk_idx * 3,
                coeff2,
                MLKEM_Q
            )));
        }
    }

    Ok(())
}

/// Encapsulate a shared secret using an ML-KEM-1024 public key.
///
/// This function validates the encapsulation key for ModulusOverflow per
/// FIPS 203 Section 7.2 before performing encapsulation. This is the secure
/// default that should be used when receiving keys from external sources.
///
/// # Arguments
///
/// * `encapsulation_key` - The public encapsulation key (1568 bytes)
///
/// # Returns
///
/// A tuple of (ciphertext, shared_secret) where:
/// - `ciphertext` is the encapsulated key (1568 bytes)
/// - `shared_secret` is the derived shared secret (32 bytes) in zeroizing memory
///
/// # Errors
///
/// Returns an error if:
/// - The encapsulation key size is invalid
/// - The encapsulation key has ModulusOverflow (coefficients >= 3329)
///
/// # Example
///
/// ```
/// use tesseract_lib::crypto::pqc::{MlKemKeyPair, encapsulate};
///
/// let keypair = MlKemKeyPair::generate();
/// let (ciphertext, shared_secret) = encapsulate(keypair.encapsulation_key()).unwrap();
///
/// // Send ciphertext to the key holder
/// // Use shared_secret as encryption key
/// ```
pub fn encapsulate(
    encapsulation_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_SIZE]>)> {
    // First validate the key for ModulusOverflow (CWE-676 mitigation)
    validate_encapsulation_key(encapsulation_key)?;

    // Then perform encapsulation
    encapsulate_unchecked(encapsulation_key)
}

/// ML-KEM-1024 key pair.
///
/// Contains both the public encapsulation key and secret decapsulation key.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MlKemKeyPair {
    /// Public encapsulation key (1568 bytes)
    pub encapsulation_key: Vec<u8>,
    /// Secret decapsulation key (3168 bytes)
    decapsulation_key: Vec<u8>,
}

impl MlKemKeyPair {
    /// Generate a new ML-KEM-1024 key pair.
    ///
    /// # Returns
    ///
    /// A new key pair with randomly generated keys.
    ///
    /// # Example
    ///
    /// ```
    /// use tesseract_lib::crypto::pqc::MlKemKeyPair;
    ///
    /// let keypair = MlKemKeyPair::generate();
    /// ```
    pub fn generate() -> Self {
        // Use rng() from rand 0.9 (compatible with ml-kem 0.3.0-pre.2)
        let mut rng = rand_compat::rng();
        let (dk, ek) = MlKem1024::generate(&mut rng);

        Self {
            encapsulation_key: ek.as_bytes().to_vec(),
            decapsulation_key: dk.as_bytes().to_vec(),
        }
    }

    /// Get the public encapsulation key.
    ///
    /// This key can be safely shared and used to encapsulate shared secrets.
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.encapsulation_key
    }

    /// Get the private decapsulation key.
    ///
    /// This key must be kept secret and is used to decapsulate shared secrets.
    pub fn decapsulation_key(&self) -> &[u8] {
        &self.decapsulation_key
    }

    /// Decapsulate a shared secret from a ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encapsulated ciphertext (1568 bytes)
    ///
    /// # Returns
    ///
    /// The decapsulated shared secret (32 bytes) in zeroizing memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext is invalid or decapsulation fails.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; SHARED_SECRET_SIZE]>> {
        if ciphertext.len() != CIPHERTEXT_SIZE {
            return Err(CryptorError::Cryptography(format!(
                "Invalid ciphertext size: expected {}, got {}",
                CIPHERTEXT_SIZE,
                ciphertext.len()
            )));
        }

        // Parse the decapsulation key using the type parameter set directly
        let dk_array: &[u8; SECRET_KEY_SIZE] =
            self.decapsulation_key.as_slice().try_into().map_err(|_| {
                CryptorError::Cryptography("Invalid decapsulation key size".to_string())
            })?;

        // Use type alias to simplify
        type DK = <MlKem1024 as KemCore>::DecapsulationKey;
        let dk = DK::from_bytes(dk_array.into());

        // Parse the ciphertext
        let ct_array: &[u8; CIPHERTEXT_SIZE] = ciphertext
            .try_into()
            .map_err(|_| CryptorError::Cryptography("Invalid ciphertext size".to_string()))?;
        let ct = Ciphertext::<MlKem1024>::from(*ct_array);

        // Decapsulate the shared secret (never fails - returns Result<_, Infallible>)
        let ss = dk.decapsulate(&ct).expect("Decapsulation is infallible");

        // Copy to zeroizing array
        let mut result = Zeroizing::new([0u8; SHARED_SECRET_SIZE]);
        result.copy_from_slice(&ss);

        Ok(result)
    }

    /// Export the key pair to bytes.
    ///
    /// # Returns
    ///
    /// A tuple of (encapsulation_key, decapsulation_key) byte vectors.
    /// The decapsulation key is returned in zeroizing memory for security.
    pub fn to_bytes(&self) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
        (
            self.encapsulation_key.clone(),
            Zeroizing::new(self.decapsulation_key.clone()),
        )
    }

    /// Import a key pair from bytes.
    ///
    /// # Arguments
    ///
    /// * `encapsulation_key` - The public encapsulation key (1568 bytes)
    /// * `decapsulation_key` - The secret decapsulation key (3168 bytes)
    ///
    /// # Returns
    ///
    /// A key pair constructed from the provided keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the key sizes are invalid.
    pub fn from_bytes(encapsulation_key: &[u8], decapsulation_key: &[u8]) -> Result<Self> {
        if encapsulation_key.len() != PUBLIC_KEY_SIZE {
            return Err(CryptorError::Cryptography(format!(
                "Invalid encapsulation key size: expected {}, got {}",
                PUBLIC_KEY_SIZE,
                encapsulation_key.len()
            )));
        }

        if decapsulation_key.len() != SECRET_KEY_SIZE {
            return Err(CryptorError::Cryptography(format!(
                "Invalid decapsulation key size: expected {}, got {}",
                SECRET_KEY_SIZE,
                decapsulation_key.len()
            )));
        }

        Ok(Self {
            encapsulation_key: encapsulation_key.to_vec(),
            decapsulation_key: decapsulation_key.to_vec(),
        })
    }
}

/// Encapsulate without ModulusOverflow validation (internal use only).
///
/// # Safety
///
/// This function does NOT validate the encapsulation key for ModulusOverflow.
/// Only use this when the key is known to be valid (e.g., locally generated).
/// For external keys, use [`encapsulate`] which performs validation.
///
/// # Arguments
///
/// * `encapsulation_key` - The public encapsulation key (1568 bytes)
///
/// # Returns
///
/// A tuple of (ciphertext, shared_secret) on success.
pub(crate) fn encapsulate_unchecked(
    encapsulation_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_SIZE]>)> {
    if encapsulation_key.len() != PUBLIC_KEY_SIZE {
        return Err(CryptorError::Cryptography(format!(
            "Invalid encapsulation key size: expected {}, got {}",
            PUBLIC_KEY_SIZE,
            encapsulation_key.len()
        )));
    }

    // Parse the encapsulation key
    let ek_array: &[u8; PUBLIC_KEY_SIZE] = encapsulation_key
        .try_into()
        .map_err(|_| CryptorError::Cryptography("Invalid encapsulation key size".to_string()))?;

    // Use type alias to simplify
    type EK = <MlKem1024 as KemCore>::EncapsulationKey;
    let ek = EK::from_bytes(ek_array.into());

    // Use rng() from rand 0.9 (compatible with ml-kem 0.3.0-pre.2)
    let mut rng = rand_compat::rng();

    // Encapsulate to get ciphertext and shared secret (never fails - returns Result<_, Infallible>)
    let (ct, ss) = ek
        .encapsulate(&mut rng)
        .expect("Encapsulation is infallible");

    // Copy to zeroizing array
    let mut secret_array = Zeroizing::new([0u8; SHARED_SECRET_SIZE]);
    secret_array.copy_from_slice(&ss);

    Ok((ct.to_vec(), secret_array))
}

/// Decapsulate a shared secret using a decapsulation key and ciphertext.
///
/// # Arguments
///
/// * `decapsulation_key` - The private decapsulation key (3168 bytes)
/// * `ciphertext` - The encapsulation ciphertext (1568 bytes)
///
/// # Returns
///
/// The 32-byte shared secret
///
/// # Errors
///
/// Returns an error if key or ciphertext sizes are invalid
pub fn decapsulate(
    decapsulation_key: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_SECRET_SIZE]>> {
    if decapsulation_key.len() != SECRET_KEY_SIZE {
        return Err(CryptorError::Cryptography(format!(
            "Invalid decapsulation key size: expected {}, got {}",
            SECRET_KEY_SIZE,
            decapsulation_key.len()
        )));
    }

    if ciphertext.len() != CIPHERTEXT_SIZE {
        return Err(CryptorError::Cryptography(format!(
            "Invalid ciphertext size: expected {}, got {}",
            CIPHERTEXT_SIZE,
            ciphertext.len()
        )));
    }

    // Parse the decapsulation key
    let dk_array: &[u8; SECRET_KEY_SIZE] = decapsulation_key
        .try_into()
        .map_err(|_| CryptorError::Cryptography("Invalid decapsulation key size".to_string()))?;

    // Parse the ciphertext
    let ct_array: &[u8; CIPHERTEXT_SIZE] = ciphertext
        .try_into()
        .map_err(|_| CryptorError::Cryptography("Invalid ciphertext size".to_string()))?;

    // Use type alias to simplify
    type DK = <MlKem1024 as KemCore>::DecapsulationKey;
    let dk = DK::from_bytes(dk_array.into());
    let ct = Ciphertext::<MlKem1024>::from(*ct_array);

    // Decapsulate to get shared secret (never fails - returns Result<_, Infallible>)
    let ss = dk.decapsulate(&ct).expect("Decapsulation is infallible");

    // Copy to zeroizing array
    let mut secret_array = Zeroizing::new([0u8; SHARED_SECRET_SIZE]);
    secret_array.copy_from_slice(&ss);

    Ok(secret_array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = MlKemKeyPair::generate();
        assert_eq!(keypair.encapsulation_key().len(), PUBLIC_KEY_SIZE);
        assert_eq!(keypair.decapsulation_key.len(), SECRET_KEY_SIZE);
    }

    #[test]
    fn test_encapsulation_decapsulation_roundtrip() {
        let keypair = MlKemKeyPair::generate();

        // Encapsulate
        let (ciphertext, shared_secret1) = encapsulate(keypair.encapsulation_key()).unwrap();
        assert_eq!(ciphertext.len(), CIPHERTEXT_SIZE);
        assert_eq!(shared_secret1.len(), SHARED_SECRET_SIZE);

        // Decapsulate
        let shared_secret2 = keypair.decapsulate(&ciphertext).unwrap();

        // Secrets should match
        assert_eq!(*shared_secret1, *shared_secret2);
    }

    #[test]
    fn test_different_encapsulations_different_ciphertexts() {
        let keypair = MlKemKeyPair::generate();

        let (ct1, _) = encapsulate(keypair.encapsulation_key()).unwrap();
        let (ct2, _) = encapsulate(keypair.encapsulation_key()).unwrap();

        // Different encapsulations should produce different ciphertexts
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_different_keypairs_different_keys() {
        let keypair1 = MlKemKeyPair::generate();
        let keypair2 = MlKemKeyPair::generate();

        assert_ne!(keypair1.encapsulation_key(), keypair2.encapsulation_key());
        assert_ne!(keypair1.decapsulation_key, keypair2.decapsulation_key);
    }

    #[test]
    fn test_keypair_serialization() {
        let keypair1 = MlKemKeyPair::generate();
        let (ek, dk) = keypair1.to_bytes();

        let keypair2 = MlKemKeyPair::from_bytes(&ek, &dk).unwrap();

        assert_eq!(keypair1.encapsulation_key(), keypair2.encapsulation_key());
        assert_eq!(keypair1.decapsulation_key, keypair2.decapsulation_key);
    }

    #[test]
    fn test_invalid_encapsulation_key_size() {
        let result = encapsulate(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ciphertext_size() {
        let keypair = MlKemKeyPair::generate();
        let result = keypair.decapsulate(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_from_invalid_sizes() {
        let result = MlKemKeyPair::from_bytes(&[0u8; 100], &[0u8; 200]);
        assert!(result.is_err());
    }

    #[test]
    fn test_shared_secret_uniqueness() {
        let keypair = MlKemKeyPair::generate();

        let (ct1, ss1) = encapsulate(keypair.encapsulation_key()).unwrap();
        let (ct2, ss2) = encapsulate(keypair.encapsulation_key()).unwrap();

        // Different encapsulations should produce different shared secrets
        assert_ne!(*ss1, *ss2);

        // But decapsulation should recover the correct secrets
        let ss1_decap = keypair.decapsulate(&ct1).unwrap();
        let ss2_decap = keypair.decapsulate(&ct2).unwrap();

        assert_eq!(*ss1, *ss1_decap);
        assert_eq!(*ss2, *ss2_decap);
    }

    #[test]
    fn test_validate_encapsulation_key_valid() {
        // A valid key generated by the library should pass validation
        let keypair = MlKemKeyPair::generate();
        assert!(validate_encapsulation_key(keypair.encapsulation_key()).is_ok());
    }

    #[test]
    fn test_validate_encapsulation_key_wrong_size() {
        // Wrong size should fail
        assert!(validate_encapsulation_key(&[0u8; 100]).is_err());
        assert!(validate_encapsulation_key(&[0u8; 1567]).is_err());
        assert!(validate_encapsulation_key(&[0u8; 1569]).is_err());
    }

    #[test]
    fn test_validate_encapsulation_key_modulus_overflow() {
        // Create a key with an invalid coefficient (>= 3329)
        let keypair = MlKemKeyPair::generate();
        let mut bad_key = keypair.encapsulation_key.clone();

        // Encode a coefficient >= 3329 at the start of the key
        // For the first coefficient: coeff1 = bytes[0] | ((bytes[1] & 0x0f) << 8)
        // To encode 3329 (0xD01): bytes[0] = 0x01, bytes[1] low nibble = 0x0D
        // But we want >= 3329, so use 3330 (0xD02): bytes[0] = 0x02, bytes[1] low nibble = 0x0D
        bad_key[0] = 0x02;
        bad_key[1] = (bad_key[1] & 0xF0) | 0x0D; // Keep high nibble, set low nibble to 0xD

        let result = validate_encapsulation_key(&bad_key);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("ModulusOverflow"),
            "Error should mention ModulusOverflow: {}",
            err_msg
        );
    }

    #[test]
    fn test_validate_encapsulation_key_max_valid_coefficient() {
        // Test with coefficients at the boundary (3328 is valid, 3329 is not)
        let keypair = MlKemKeyPair::generate();
        let mut key_3328 = keypair.encapsulation_key.clone();

        // Encode 3328 (0xD00) as the first coefficient
        // coeff1 = bytes[0] | ((bytes[1] & 0x0f) << 8) = 0x00 | (0x0D << 8) = 0xD00 = 3328
        key_3328[0] = 0x00;
        key_3328[1] = (key_3328[1] & 0xF0) | 0x0D;

        // 3328 should be valid
        assert!(validate_encapsulation_key(&key_3328).is_ok());

        // Now encode 3329 (0xD01) - should fail
        key_3328[0] = 0x01;
        assert!(validate_encapsulation_key(&key_3328).is_err());
    }

    #[test]
    fn test_encapsulate_validated_rejects_bad_key() {
        // Create a key with ModulusOverflow
        let keypair = MlKemKeyPair::generate();
        let mut bad_key = keypair.encapsulation_key.clone();

        // Encode an invalid coefficient
        bad_key[0] = 0xFF;
        bad_key[1] = 0xFF; // This encodes 0xFFF = 4095 >> 3329

        let result = encapsulate(&bad_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_encapsulate_accepts_good_key() {
        let keypair = MlKemKeyPair::generate();
        let result = encapsulate(keypair.encapsulation_key());
        assert!(result.is_ok());

        // Verify the result can be decapsulated
        let (ct, ss1) = result.unwrap();
        let ss2 = keypair.decapsulate(&ct).unwrap();
        assert_eq!(*ss1, *ss2);
    }
}
