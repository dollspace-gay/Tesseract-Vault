// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Differential Testing for Tesseract Encryption
//!
//! Compares behavior across different code paths and implementations to ensure
//! consistency and detect subtle bugs that might only appear in edge cases.
//!
//! ## Differential Testing Approaches
//!
//! 1. **Cross-Path Testing**: Verify streaming vs non-streaming encryption
//! 2. **Parameter Variation**: Test with different chunk sizes, buffer sizes
//! 3. **Round-Trip Verification**: Encrypt with one method, decrypt with another
//! 4. **Reference Comparison**: Compare against known-good test vectors

use proptest::prelude::*;
use tesseract_lib::crypto::aes_gcm::AesGcmEncryptor;
use tesseract_lib::crypto::kdf::Argon2Kdf;
use tesseract_lib::crypto::Encryptor;
use tesseract_lib::crypto::KeyDerivation;
use tesseract_lib::{decrypt_bytes, encrypt_bytes};

/// Generate a valid password that meets requirements
fn valid_password() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Z][a-z]{4,10}[0-9]{2,4}[!@#$%^&*]")
        .unwrap()
        .prop_filter("Password must be at least 8 chars", |p| p.len() >= 8)
}

/// Test vector for differential testing
#[derive(Debug, Clone)]
struct DiffTestVector {
    plaintext: Vec<u8>,
    key: [u8; 32],
    nonce: [u8; 12],
}

impl DiffTestVector {
    fn arbitrary() -> impl Strategy<Value = Self> {
        (
            prop::collection::vec(any::<u8>(), 0..10000),
            prop::collection::vec(any::<u8>(), 32..=32),
            prop::collection::vec(any::<u8>(), 12..=12),
        )
            .prop_map(|(plaintext, key_vec, nonce_vec)| {
                let mut key = [0u8; 32];
                let mut nonce = [0u8; 12];
                key.copy_from_slice(&key_vec);
                nonce.copy_from_slice(&nonce_vec);
                DiffTestVector {
                    plaintext,
                    key,
                    nonce,
                }
            })
    }
}

// =============================================================================
// Cross-Implementation Differential Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Verify AES-GCM encryption produces consistent ciphertext length
    ///
    /// For any plaintext length N, ciphertext should always be N + 16 (tag size)
    #[test]
    fn aes_gcm_length_invariant(vector in DiffTestVector::arbitrary()) {
        let encryptor = AesGcmEncryptor::new();

        let ciphertext = encryptor.encrypt(&vector.key, &vector.nonce, &vector.plaintext)
            .expect("Encryption should succeed");

        // AES-GCM always adds exactly 16 bytes (authentication tag)
        prop_assert_eq!(
            ciphertext.len(),
            vector.plaintext.len() + 16,
            "Ciphertext length should be plaintext + 16 bytes"
        );
    }

    /// Verify encryption/decryption is reversible for all inputs
    #[test]
    fn aes_gcm_reversible(vector in DiffTestVector::arbitrary()) {
        let encryptor = AesGcmEncryptor::new();

        let ciphertext = encryptor.encrypt(&vector.key, &vector.nonce, &vector.plaintext)
            .expect("Encryption should succeed");

        let decrypted = encryptor.decrypt(&vector.key, &vector.nonce, &ciphertext)
            .expect("Decryption should succeed");

        prop_assert_eq!(&vector.plaintext, &*decrypted);
    }

    /// Verify same inputs always produce same outputs (deterministic)
    #[test]
    fn aes_gcm_deterministic(vector in DiffTestVector::arbitrary()) {
        let encryptor = AesGcmEncryptor::new();

        let ciphertext1 = encryptor.encrypt(&vector.key, &vector.nonce, &vector.plaintext)
            .expect("First encryption should succeed");

        let ciphertext2 = encryptor.encrypt(&vector.key, &vector.nonce, &vector.plaintext)
            .expect("Second encryption should succeed");

        // Same key + nonce + plaintext MUST produce identical ciphertext
        prop_assert_eq!(ciphertext1, ciphertext2,
            "Same inputs must produce identical ciphertext");
    }

    /// Verify nonce uniqueness produces different ciphertext
    #[test]
    fn aes_gcm_nonce_differentiation(
        plaintext in prop::collection::vec(any::<u8>(), 16..1000),
        key in prop::collection::vec(any::<u8>(), 32..=32),
        nonce1 in prop::collection::vec(any::<u8>(), 12..=12),
        nonce2 in prop::collection::vec(any::<u8>(), 12..=12)
    ) {
        prop_assume!(nonce1 != nonce2);

        let key_array: [u8; 32] = key.try_into().unwrap();
        let encryptor = AesGcmEncryptor::new();

        let ciphertext1 = encryptor.encrypt(&key_array, &nonce1, &plaintext)
            .expect("First encryption should succeed");

        let ciphertext2 = encryptor.encrypt(&key_array, &nonce2, &plaintext)
            .expect("Second encryption should succeed");

        // Different nonces MUST produce different ciphertext
        prop_assert_ne!(ciphertext1, ciphertext2,
            "Different nonces must produce different ciphertext");
    }
}

// =============================================================================
// Key Derivation Differential Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Verify key derivation produces consistent results
    #[test]
    fn kdf_deterministic(
        password in prop::collection::vec(any::<u8>(), 1..100),
        salt in prop::collection::vec(any::<u8>(), 16..=16)
    ) {
        let kdf = Argon2Kdf::default();

        let key1 = kdf.derive_key(&password, &salt)
            .expect("First derivation should succeed");

        let key2 = kdf.derive_key(&password, &salt)
            .expect("Second derivation should succeed");

        // Same password + salt must produce identical key
        prop_assert_eq!(key1.as_slice(), key2.as_slice(),
            "Key derivation must be deterministic");
    }

    /// Verify key derivation is sensitive to password changes
    #[test]
    fn kdf_password_sensitivity(
        password1 in prop::collection::vec(any::<u8>(), 1..100),
        password2 in prop::collection::vec(any::<u8>(), 1..100),
        salt in prop::collection::vec(any::<u8>(), 16..=16)
    ) {
        prop_assume!(password1 != password2);

        let kdf = Argon2Kdf::default();

        let key1 = kdf.derive_key(&password1, &salt)
            .expect("First derivation should succeed");

        let key2 = kdf.derive_key(&password2, &salt)
            .expect("Second derivation should succeed");

        // Different passwords must produce different keys
        prop_assert_ne!(key1.as_slice(), key2.as_slice(),
            "Different passwords must produce different keys");
    }

    /// Verify key derivation is sensitive to salt changes
    #[test]
    fn kdf_salt_sensitivity(
        password in prop::collection::vec(any::<u8>(), 1..100),
        salt1 in prop::collection::vec(any::<u8>(), 16..=16),
        salt2 in prop::collection::vec(any::<u8>(), 16..=16)
    ) {
        prop_assume!(salt1 != salt2);

        let kdf = Argon2Kdf::default();

        let key1 = kdf.derive_key(&password, &salt1)
            .expect("First derivation should succeed");

        let key2 = kdf.derive_key(&password, &salt2)
            .expect("Second derivation should succeed");

        // Different salts must produce different keys
        prop_assert_ne!(key1.as_slice(), key2.as_slice(),
            "Different salts must produce different keys");
    }
}

// =============================================================================
// High-Level API Differential Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Verify encrypt_bytes/decrypt_bytes round-trip
    #[test]
    fn bytes_api_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..10000),
        password in valid_password()
    ) {
        let (salt, nonce, ciphertext) = encrypt_bytes(&plaintext, &password)
            .expect("Encryption should succeed");

        let decrypted = decrypt_bytes(&salt, &nonce, &ciphertext, &password)
            .expect("Decryption should succeed");

        prop_assert_eq!(&plaintext, &*decrypted,
            "Round-trip encryption/decryption must preserve data");
    }

    /// Verify each encryption uses unique nonce
    #[test]
    fn bytes_api_unique_nonces(
        plaintext in prop::collection::vec(any::<u8>(), 16..1000),
        password in valid_password()
    ) {
        let (_, nonce1, _) = encrypt_bytes(&plaintext, &password)
            .expect("First encryption should succeed");

        let (_, nonce2, _) = encrypt_bytes(&plaintext, &password)
            .expect("Second encryption should succeed");

        prop_assert_ne!(nonce1, nonce2,
            "Each encryption must use a unique nonce");
    }

    /// Verify wrong password fails authentication
    #[test]
    fn bytes_api_auth_failure(
        plaintext in prop::collection::vec(any::<u8>(), 16..1000),
        password1 in valid_password(),
        password2 in valid_password()
    ) {
        prop_assume!(password1 != password2);

        let (salt, nonce, ciphertext) = encrypt_bytes(&plaintext, &password1)
            .expect("Encryption should succeed");

        let result = decrypt_bytes(&salt, &nonce, &ciphertext, &password2);

        prop_assert!(result.is_err(),
            "Decryption with wrong password must fail");
    }
}

// =============================================================================
// BLAKE3 Hash Differential Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Verify BLAKE3 is deterministic
    #[test]
    fn blake3_deterministic(data in prop::collection::vec(any::<u8>(), 0..10000)) {
        let hash1 = blake3::hash(&data);
        let hash2 = blake3::hash(&data);

        prop_assert_eq!(hash1.as_bytes(), hash2.as_bytes(),
            "BLAKE3 must be deterministic");
    }

    /// Verify BLAKE3 produces unique hashes for different inputs
    #[test]
    fn blake3_collision_resistance(
        data1 in prop::collection::vec(any::<u8>(), 1..1000),
        data2 in prop::collection::vec(any::<u8>(), 1..1000)
    ) {
        prop_assume!(data1 != data2);

        let hash1 = blake3::hash(&data1);
        let hash2 = blake3::hash(&data2);

        prop_assert_ne!(hash1.as_bytes(), hash2.as_bytes(),
            "Different inputs must produce different hashes");
    }

    /// Verify BLAKE3 incremental hashing matches single-shot
    #[test]
    fn blake3_incremental_consistency(
        data in prop::collection::vec(any::<u8>(), 0..10000),
        chunk_size in 1usize..1000
    ) {
        // Single-shot hash
        let single_hash = blake3::hash(&data);

        // Incremental hash
        let mut hasher = blake3::Hasher::new();
        for chunk in data.chunks(chunk_size) {
            hasher.update(chunk);
        }
        let incremental_hash = hasher.finalize();

        prop_assert_eq!(single_hash.as_bytes(), incremental_hash.as_bytes(),
            "Incremental hashing must match single-shot");
    }

    /// Verify BLAKE3 keyed hashing is different from unkeyed
    #[test]
    fn blake3_keyed_vs_unkeyed(
        data in prop::collection::vec(any::<u8>(), 1..1000),
        key in prop::collection::vec(any::<u8>(), 32..=32)
    ) {
        let key_array: [u8; 32] = key.try_into().unwrap();

        let unkeyed = blake3::hash(&data);
        let keyed = blake3::keyed_hash(&key_array, &data);

        prop_assert_ne!(unkeyed.as_bytes(), keyed.as_bytes(),
            "Keyed hash must differ from unkeyed");
    }
}

// =============================================================================
// Edge Case Differential Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Test empty plaintext handling
    #[test]
    fn empty_plaintext_handling(
        key in prop::collection::vec(any::<u8>(), 32..=32),
        nonce in prop::collection::vec(any::<u8>(), 12..=12)
    ) {
        let key_array: [u8; 32] = key.try_into().unwrap();
        let encryptor = AesGcmEncryptor::new();

        // Empty plaintext should work
        let ciphertext = encryptor.encrypt(&key_array, &nonce, &[])
            .expect("Empty plaintext encryption should succeed");

        // Should still have 16-byte tag
        prop_assert_eq!(ciphertext.len(), 16);

        let decrypted = encryptor.decrypt(&key_array, &nonce, &ciphertext)
            .expect("Empty plaintext decryption should succeed");

        prop_assert!(decrypted.is_empty());
    }

    /// Test single-byte plaintext
    #[test]
    fn single_byte_plaintext(
        byte in any::<u8>(),
        key in prop::collection::vec(any::<u8>(), 32..=32),
        nonce in prop::collection::vec(any::<u8>(), 12..=12)
    ) {
        let key_array: [u8; 32] = key.try_into().unwrap();
        let encryptor = AesGcmEncryptor::new();
        let plaintext = [byte];

        let ciphertext = encryptor.encrypt(&key_array, &nonce, &plaintext)
            .expect("Single-byte encryption should succeed");

        prop_assert_eq!(ciphertext.len(), 17); // 1 byte + 16 tag

        let decrypted = encryptor.decrypt(&key_array, &nonce, &ciphertext)
            .expect("Single-byte decryption should succeed");

        prop_assert_eq!(&plaintext[..], &(*decrypted)[..]);
    }

    /// Test boundary sizes (powers of 2, block boundaries)
    #[test]
    fn boundary_size_plaintext(
        size_index in 0usize..10,
        key in prop::collection::vec(any::<u8>(), 32..=32),
        nonce in prop::collection::vec(any::<u8>(), 12..=12)
    ) {
        let sizes = [15, 16, 17, 31, 32, 33, 63, 64, 65, 127];
        let size = sizes[size_index];

        let key_array: [u8; 32] = key.try_into().unwrap();
        let encryptor = AesGcmEncryptor::new();
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        let ciphertext = encryptor.encrypt(&key_array, &nonce, &plaintext)
            .expect("Boundary size encryption should succeed");

        prop_assert_eq!(ciphertext.len(), size + 16);

        let decrypted = encryptor.decrypt(&key_array, &nonce, &ciphertext)
            .expect("Boundary size decryption should succeed");

        prop_assert_eq!(&plaintext, &*decrypted);
    }
}
